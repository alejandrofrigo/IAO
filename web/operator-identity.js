(() => {
  "use strict";
  if (window.__IAO_OPERATOR_IDENTITY_LOADED__) return;
  window.__IAO_OPERATOR_IDENTITY_LOADED__ = true;
  const DB_NAME = "iao-operator-root", STORE = "identity";
  const encoder = new TextEncoder();
  const ROOT_DOMAIN = encoder.encode("IAO-OPERATOR-ROOT-V1\0");
  function apiUrl(path) {
    if (typeof window.iaoApiUrl !== "function") throw new Error("API_CONFIG_NOT_AVAILABLE");
    return window.iaoApiUrl(path);
  }
  function openDB() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, 1);
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains(STORE)) request.result.createObjectStore(STORE);
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }
  async function readIdentity() {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readonly"), request = tx.objectStore(STORE).get("root");
      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(request.error);
      tx.oncomplete = () => db.close();
      tx.onerror = () => { db.close(); reject(tx.error); };
    });
  }
  async function writeIdentity(value) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).put(value, "root");
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = () => { db.close(); reject(tx.error); };
      tx.onabort = () => { db.close(); reject(tx.error); };
    });
  }
  async function deleteIdentity() {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).delete("root");
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = () => { db.close(); reject(tx.error); };
    });
  }
  function b64url(bytes) {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function pem(label, bytes) {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return "-----BEGIN " + label + "-----\n" +
      (btoa(binary).match(/.{1,64}/g) || []).join("\n") +
      "\n-----END " + label + "-----";
  }
  function derInteger(bytes) {
    let first = 0;
    while (first < bytes.length - 1 && bytes[first] === 0) first++;
    let value = bytes.slice(first);
    if (value[0] & 0x80) {
      const padded = new Uint8Array(value.length + 1);
      padded.set(value, 1); value = padded;
    }
    const result = new Uint8Array(value.length + 2);
    result[0] = 2; result[1] = value.length; result.set(value, 2);
    return result;
  }
  function rawEcdsaToDer(raw) {
    if (raw.length !== 64) throw new Error("INVALID_ECDSA_SIGNATURE_LENGTH");
    const r = derInteger(raw.slice(0, 32)), s = derInteger(raw.slice(32));
    const sequence = new Uint8Array(r.length + s.length + 2);
    sequence[0] = 0x30; sequence[1] = r.length + s.length;
    sequence.set(r, 2); sequence.set(s, 2 + r.length);
    return sequence;
  }
  async function request(path, method, body) {
    const headers = {};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (typeof window.iaoGetSessionToken === "function") {
      const token = window.iaoGetSessionToken();
      if (token) headers.Authorization = "Bearer " + token;
    }
    const response = await fetch(apiUrl(path), {
      method: method || "GET", mode: "cors", credentials: "omit",
      cache: "no-store", headers,
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "HTTP_" + response.status);
    return data;
  }
  async function generateRootKey() {
    const generated = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]
    );
    const spki = new Uint8Array(await crypto.subtle.exportKey("spki", generated.publicKey));
    const privateBytes = new Uint8Array(await crypto.subtle.exportKey("pkcs8", generated.privateKey));
    let privateKey;
    try {
      privateKey = await crypto.subtle.importKey(
        "pkcs8", privateBytes, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]
      );
    } finally { privateBytes.fill(0); }
    return { privateKey, publicKeyPem: pem("PUBLIC KEY", spki) };
  }
  async function bootstrap(code) {
    if (!crypto.subtle || !window.indexedDB) throw new Error("BROWSER_CRYPTO_OR_STORAGE_UNAVAILABLE");
    let stored = await readIdentity();
    if (stored && stored.keyVersion) throw new Error("ROOT_IDENTITY_ALREADY_REGISTERED");
    if (!stored) {
      const key = await generateRootKey();
      stored = {
        privateKey: key.privateKey,
        publicKeyPem: key.publicKeyPem,
        createdAt: Date.now(),
        bootstrapPending: true
      };
      // Keep the key if the network outcome is ambiguous: the server may have
      // consumed the one-time code before a response was lost.
      await writeIdentity(stored);
    }
    const result = await request("/v1/operator/bootstrap", "POST", {
      code, root_public_key_pem: stored.publicKeyPem
    });
    await writeIdentity({ ...stored, keyVersion: result.key_version, bootstrapPending: false });
    return result;
  }
  async function associateSession() {
    const identity = await readIdentity();
    if (!identity || !identity.privateKey) throw new Error("ROOT_IDENTITY_NOT_ENROLLED");
    const challenge = await request("/v1/operator/session/challenge", "POST", {});
    const encoded = challenge.signing_payload.replace(/-/g, "+").replace(/_/g, "/");
    const payload = Uint8Array.from(
      atob(encoded + "=".repeat((4 - encoded.length % 4) % 4)), c => c.charCodeAt(0)
    );
    const message = new Uint8Array(ROOT_DOMAIN.length + payload.length);
    message.set(ROOT_DOMAIN); message.set(payload, ROOT_DOMAIN.length);
    const raw = new Uint8Array(await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" }, identity.privateKey, message
    ));
    return request("/v1/operator/session/bind", "POST", {
      challenge: challenge.challenge, signature: b64url(rawEcdsaToDer(raw))
    });
  }
  async function status() { return request("/v1/operator/session/status", "GET"); }
  function panel() {
    if (document.getElementById("iao-operator-identity-panel")) return;
    const section = document.createElement("section");
    section.id = "iao-operator-identity-panel";
    section.style.cssText = "margin:18px auto;padding:16px;max-width:680px;border:1px solid #8886;border-radius:14px;font:inherit;";
    const title = document.createElement("h3"); title.textContent = "Identidad raíz del operador";
    const description = document.createElement("p");
    description.textContent = "La clave privada se genera en este navegador y se guarda como CryptoKey no exportable. El código de bootstrap se usa una sola vez y no se conserva.";
    const code = document.createElement("input");
    code.type = "password"; code.autocomplete = "off"; code.placeholder = "Código de bootstrap fuera de banda";
    code.style.cssText = "width:100%;box-sizing:border-box;padding:12px;margin:8px 0;";
    const bootstrapButton = document.createElement("button");
    bootstrapButton.type = "button"; bootstrapButton.textContent = "Registrar identidad raíz";
    const associateButton = document.createElement("button");
    associateButton.type = "button"; associateButton.textContent = "Asociar sesión autenticada";
    const statusButton = document.createElement("button");
    statusButton.type = "button"; statusButton.textContent = "Consultar asociación";
    const output = document.createElement("pre");
    output.style.cssText = "white-space:pre-wrap;overflow-wrap:anywhere;";
    function show(message, failed) { output.textContent = message; output.style.color = failed ? "#c44" : "inherit"; }
    async function run(button, action, success) {
      button.disabled = true;
      try { show(success(await action()), false); }
      catch (error) { show("ERROR: " + error.message, true); }
      finally { button.disabled = false; }
    }
    bootstrapButton.addEventListener("click", () => run(bootstrapButton, async () => {
      const secret = code.value; code.value = "";
      if (!secret) throw new Error("OPERATOR_BOOTSTRAP_REQUIRED");
      return bootstrap(secret);
    }, result => "IDENTIDAD RAÍZ REGISTRADA\nAlgoritmo: " + result.algorithm + "\nVersión: " + result.key_version));
    associateButton.addEventListener("click", () => run(
      associateButton, associateSession,
      result => "ASOCIACIÓN VERIFICADA\nAutoridad: " + result.authority
    ));
    statusButton.addEventListener("click", () => run(statusButton, status,
      result => "Asociada: " + (result.associated ? "sí" : "no") + "\nAutoridad: " + result.authority
    ));
    section.append(title, description, code, bootstrapButton, associateButton, statusButton, output);
    document.body.appendChild(section);
    readIdentity().then(identity => show(
      identity ? "Clave raíz local disponible en este navegador." : "No hay identidad raíz registrada en este navegador.", false
    )).catch(error => show("Almacenamiento no disponible: " + error.message, true));
  }
  window.IAOOperatorIdentity = Object.freeze({ associateSession, status });
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", panel, { once: true });
  else panel();
})();