(() => {
  "use strict";

  if (window.__IAO_DEVICE_AUTHORITY_LOADED__) return;
  window.__IAO_DEVICE_AUTHORITY_LOADED__ = true;

  const DB_NAME = "iao-device-authority";
  const STORE = "identity";
  const encoder = new TextEncoder();

  const apiUrl = (path) => {
    if (typeof window.iaoApiUrl !== "function") {
      throw new Error("API_CONFIG_NOT_AVAILABLE");
    }
    return window.iaoApiUrl(path);
  };

  function openDB() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, 1);
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains(STORE)) {
          request.result.createObjectStore(STORE);
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  async function dbGet() {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readonly");
      const req = tx.objectStore(STORE).get("primary");
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error);
      tx.oncomplete = () => db.close();
      tx.onerror = () => {
        db.close();
        reject(tx.error);
      };
    });
  }

  async function dbGetPending() {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readonly");
      const req = tx.objectStore(STORE).get("recovery-pending");
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error);
      tx.oncomplete = () => db.close();
      tx.onerror = () => { db.close(); reject(tx.error); };
    });
  }

  async function dbPutPending(value) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).put(value, "recovery-pending");
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = () => { db.close(); reject(tx.error); };
      tx.onabort = () => { db.close(); reject(tx.error); };
    });
  }

  async function dbDeletePending() {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).delete("recovery-pending");
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = () => { db.close(); reject(tx.error); };
    });
  }

  async function dbPut(value) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).put(value, "primary");
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
      tx.onerror = () => {
        db.close();
        reject(tx.error);
      };
      tx.onabort = () => {
        db.close();
        reject(tx.error);
      };
    });
  }

  async function dbDelete() {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).delete("primary");
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
      tx.onerror = () => {
        db.close();
        reject(tx.error);
      };
    });
  }

  function b64url(bytes) {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");
  }

  function pem(label, bytes) {
    const binary = Array.from(bytes, b => String.fromCharCode(b)).join("");
    const base64 = btoa(binary).match(/.{1,64}/g).join("\n");
    return `-----BEGIN ${label}-----\n${base64}\n-----END ${label}-----`;
  }

  function derInteger(bytes) {
    let first = 0;
    while (first < bytes.length - 1 && bytes[first] === 0) first++;
    let value = bytes.slice(first);
    if (value[0] & 0x80) {
      const padded = new Uint8Array(value.length + 1);
      padded.set(value, 1);
      value = padded;
    }
    const result = new Uint8Array(value.length + 2);
    result[0] = 0x02;
    result[1] = value.length;
    result.set(value, 2);
    return result;
  }

  function rawEcdsaToDer(raw) {
    if (raw.length !== 64) throw new Error("INVALID_ECDSA_SIGNATURE_LENGTH");
    const r = derInteger(raw.slice(0, 32));
    const s = derInteger(raw.slice(32, 64));
    const sequence = new Uint8Array(r.length + s.length + 2);
    sequence[0] = 0x30;
    sequence[1] = r.length + s.length;
    sequence.set(r, 2);
    sequence.set(s, 2 + r.length);
    return sequence;
  }

  async function post(path, body) {
    const headers = { "Content-Type": "application/json" };
    if (typeof window.iaoGetSessionToken === "function") {
      const token = window.iaoGetSessionToken();
      if (token) headers.Authorization = "Bearer " + token;
    }
    const response = await fetch(apiUrl(path), {
      method: "POST",
      mode: "cors",
      credentials: "omit",
      cache: "no-store",
      headers,
      body: JSON.stringify(body)
    });

    let data = {};
    try {
      data = await response.json();
    } catch (_) {
      throw new Error("INVALID_SERVER_RESPONSE");
    }

    if (!response.ok) {
      throw new Error(data.error || data.code || `HTTP_${response.status}`);
    }
    return data;
  }

  async function createIdentity() {
    const generated = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );

    const spki = new Uint8Array(
      await crypto.subtle.exportKey("spki", generated.publicKey)
    );
    const privateBytes = new Uint8Array(
      await crypto.subtle.exportKey("pkcs8", generated.privateKey)
    );

    let privateKey;
    try {
      privateKey = await crypto.subtle.importKey(
        "pkcs8",
        privateBytes,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign"]
      );
    } finally {
      privateBytes.fill(0);
    }

    const fingerprint = new Uint8Array(
      await crypto.subtle.digest("SHA-256", spki)
    );
    const deviceId = Array.from(
      fingerprint, b => b.toString(16).padStart(2, "0")
    ).join("");

    return {
      privateKey,
      deviceId,
      publicKeyPem: pem("PUBLIC KEY", spki)
    };
  }

  async function enroll(code) {
    if (!crypto.subtle || !indexedDB) {
      throw new Error("BROWSER_CRYPTO_OR_STORAGE_UNAVAILABLE");
    }

    const identity = await createIdentity();
    const result = await post("/v1/device/enroll", {
      code,
      public_key_pem: identity.publicKeyPem
    });

    await dbPut({
      deviceId: identity.deviceId,
      privateKey: identity.privateKey,
      publicKeyPem: identity.publicKeyPem,
      algorithm: result.algorithm,
      enrolledAt: Date.now()
    });

    return { algorithm: result.algorithm };
  }

  async function publicKeyPem() {
    const identity = await dbGet();
    if (!identity || typeof identity.publicKeyPem !== "string") throw new Error("DEVICE_NOT_ENROLLED");
    return identity.publicKeyPem;
  }

  async function prepareRecoveryIdentity() {
    if (!crypto.subtle || !indexedDB) throw new Error("BROWSER_CRYPTO_OR_STORAGE_UNAVAILABLE");
    const identity = await createIdentity();
    await dbPutPending({
      deviceId: identity.deviceId,
      privateKey: identity.privateKey,
      publicKeyPem: identity.publicKeyPem,
      recoveryPending: true,
      createdAt: Date.now()
    });
    return { publicKeyPem: identity.publicKeyPem };
  }

  async function prepareBootstrapIdentity() {
    const pending = await dbGetPending();
    if (pending && pending.recoveryPending === true && pending.privateKey &&
        typeof pending.publicKeyPem === "string") {
      return { publicKeyPem: pending.publicKeyPem };
    }
    return prepareRecoveryIdentity();
  }

  async function signBootstrapPayload(payloadBase64) {
    const identity = await dbGetPending();
    if (!identity || identity.recoveryPending !== true || !identity.privateKey) {
      throw new Error("BOOTSTRAP_DEVICE_KEY_NOT_PREPARED");
    }
    if (typeof payloadBase64 !== "string" || !/^[A-Za-z0-9_-]+$/.test(payloadBase64)) {
      throw new Error("INVALID_OPERATOR_BOOTSTRAP_PAYLOAD");
    }
    const encoded = payloadBase64.replace(/-/g, "+").replace(/_/g, "/");
    const payload = Uint8Array.from(
      atob(encoded + "=".repeat((4 - encoded.length % 4) % 4)),
      c => c.charCodeAt(0)
    );
    const domain = new TextEncoder().encode("IAO-OPERATOR-BOOTSTRAP-DEVICE-V1\x00");
    const message = new Uint8Array(domain.length + payload.length);
    message.set(domain); message.set(payload, domain.length);
    const raw = new Uint8Array(await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" }, identity.privateKey, message
    ));
    return b64url(rawEcdsaToDer(raw));
  }

  async function recoveryPublicKeyPem() {
    const identity = await dbGetPending();
    if (!identity || identity.recoveryPending !== true || !identity.privateKey) {
      throw new Error("RECOVERY_DEVICE_KEY_NOT_PREPARED");
    }
    return identity.publicKeyPem;
  }

  async function hasRecoveryKey(publicKeyPem) {
    if (typeof publicKeyPem !== "string" || !publicKeyPem) return false;
    const pending = await dbGetPending();
    if (pending && pending.privateKey && pending.publicKeyPem === publicKeyPem) return true;
    const active = await dbGet();
    return !!(active && active.privateKey && active.publicKeyPem === publicKeyPem);
  }

  async function signRecoveryPayload(payloadBase64) {
    const identity = await dbGetPending();
    if (!identity || identity.recoveryPending !== true || !identity.privateKey) {
      throw new Error("RECOVERY_DEVICE_KEY_NOT_PREPARED");
    }
    if (typeof payloadBase64 !== "string" || !/^[A-Za-z0-9_-]+$/.test(payloadBase64)) {
      throw new Error("INVALID_OPERATOR_RECOVERY_PAYLOAD");
    }
    const encoded = payloadBase64.replace(/-/g, "+").replace(/_/g, "/");
    const payload = Uint8Array.from(
      atob(encoded + "=".repeat((4 - encoded.length % 4) % 4)),
      c => c.charCodeAt(0)
    );
    const domain = new TextEncoder().encode("IAO-OPERATOR-RECOVERY-DEVICE-V1\x00");
    const message = new Uint8Array(domain.length + payload.length);
    message.set(domain); message.set(payload, domain.length);
    const raw = new Uint8Array(await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" }, identity.privateKey, message
    ));
    return b64url(rawEcdsaToDer(raw));
  }

  async function activateRecoveryIdentity(expectedPublicKeyPem) {
    if (typeof expectedPublicKeyPem !== "string" || !expectedPublicKeyPem) {
      throw new Error("RECOVERY_DEVICE_KEY_NOT_PREPARED");
    }
    const identity = await dbGetPending();
    if (identity && identity.recoveryPending === true && identity.privateKey &&
        identity.publicKeyPem === expectedPublicKeyPem) {
      await dbPut({ ...identity, recoveryPending: false, enrolledAt: Date.now() });
      await dbDeletePending();
      return { activated: true };
    }
    const active = await dbGet();
    if (active && active.recoveryPending !== true &&
        active.privateKey && active.publicKeyPem === expectedPublicKeyPem) {
      return { activated: true, reconciled: true };
    }
    throw new Error("RECOVERY_DEVICE_KEY_NOT_PREPARED");
  }

  async function signOperatorLoginPayload(payloadBase64) {
    const identity = await dbGet();
    if (!identity || !identity.privateKey || !identity.deviceId) {
      throw new Error("DEVICE_NOT_ENROLLED");
    }
    if (typeof payloadBase64 !== "string" || !/^[A-Za-z0-9_-]+$/.test(payloadBase64)) {
      throw new Error("INVALID_OPERATOR_LOGIN_PAYLOAD");
    }
    const encoded = payloadBase64.replace(/-/g, "+").replace(/_/g, "/");
    const payload = Uint8Array.from(
      atob(encoded + "=".repeat((4 - encoded.length % 4) % 4)),
      c => c.charCodeAt(0)
    );
    const domain = new TextEncoder().encode("IAO-OPERATOR-DEVICE-LOGIN-V1\x00");
    const message = new Uint8Array(domain.length + payload.length);
    message.set(domain);
    message.set(payload, domain.length);
    const raw = new Uint8Array(await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" }, identity.privateKey, message
    ));
    return b64url(rawEcdsaToDer(raw));
  }

  async function signedTaskHeaders(payload) {
    const identity = await dbGet();
    if (!identity || !identity.privateKey || !identity.deviceId) {
      throw new Error("DEVICE_NOT_ENROLLED");
    }
    const bodyText = JSON.stringify(payload);
    const challenge = await post("/v1/device/challenge", {
      device_id: identity.deviceId
    });
    const timestamp = Math.floor(Date.now() / 1000);
    const digest = new Uint8Array(
      await crypto.subtle.digest("SHA-256", encoder.encode(bodyText))
    );
    const hexDigest = Array.from(
      digest, b => b.toString(16).padStart(2, "0")
    ).join("");
    const signedText = [
      "POST", "/v1/tasks", String(timestamp), challenge.nonce, hexDigest
    ].join("\n");
    const rawSignature = new Uint8Array(
      await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        identity.privateKey,
        encoder.encode(signedText)
      )
    );
    return {
      "X-IAO-Device-Proof": JSON.stringify({
        device_id: identity.deviceId,
        nonce: challenge.nonce,
        timestamp,
        request_digest: hexDigest,
        signature: b64url(rawEcdsaToDer(rawSignature))
      })
    };
  }

  async function submitQueuedTask(payload, idempotencyKey) {
    const identity = await dbGet();
    if (!identity) throw new Error("DEVICE_NOT_ENROLLED");
    if (
      idempotencyKey !== undefined &&
      (typeof idempotencyKey !== "string" ||
       !/^[A-Za-z0-9._:-]{1,128}$/.test(idempotencyKey))
    ) {
      throw new Error("INVALID_IDEMPOTENCY_KEY");
    }
    const proofHeaders = await signedTaskHeaders(payload);
    const headers = { "Content-Type": "application/json", ...proofHeaders };
    if (idempotencyKey !== undefined) headers["Idempotency-Key"] = idempotencyKey;
    if (typeof window.iaoGetSessionToken === "function") {
      const token = window.iaoGetSessionToken();
      if (token) headers.Authorization = "Bearer " + token;
    }
    const response = await fetch(apiUrl("/v1/tasks"), {
      method: "POST", mode: "cors", credentials: "omit", cache: "no-store",
      headers, body: JSON.stringify(payload)
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "HTTP_" + response.status);
    return data;
  }

  async function signedCancelHeaders(taskId) {
    const identity = await dbGet();
    if (!identity || !identity.privateKey || !identity.deviceId) {
      throw new Error("DEVICE_NOT_ENROLLED");
    }
    if (typeof taskId !== "string" ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(taskId)) {
      throw new Error("INVALID_TASK_ID");
    }
    const path = "/v1/tasks/" + taskId + "/cancel";
    const challenge = await post("/v1/device/challenge", {
      device_id: identity.deviceId
    });
    const timestamp = Math.floor(Date.now() / 1000);
    const bodyText = "";
    const digest = new Uint8Array(
      await crypto.subtle.digest("SHA-256", encoder.encode(bodyText))
    );
    const hexDigest = Array.from(
      digest, b => b.toString(16).padStart(2, "0")
    ).join("");
    const signedText = [
      "POST", path, String(timestamp), challenge.nonce, hexDigest
    ].join("\n");
    const rawSignature = new Uint8Array(await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      identity.privateKey,
      encoder.encode(signedText)
    ));
    return {
      "X-IAO-Device-Proof": JSON.stringify({
        device_id: identity.deviceId,
        nonce: challenge.nonce,
        timestamp,
        request_digest: hexDigest,
        signature: b64url(rawEcdsaToDer(rawSignature))
      })
    };
  }

  async function cancelQueuedTask(taskId) {
    const path = "/v1/tasks/" + taskId + "/cancel";
    const headers = { ...await signedCancelHeaders(taskId) };
    if (typeof window.iaoGetSessionToken === "function") {
      const token = window.iaoGetSessionToken();
      if (token) headers.Authorization = "Bearer " + token;
    }
    const response = await fetch(apiUrl(path), {
      method: "POST", mode: "cors", credentials: "omit", cache: "no-store",
      headers, body: ""
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "HTTP_" + response.status);
    return data;
  }

  async function signedStatus() {
    const identity = await dbGet();
    if (!identity || !identity.privateKey || !identity.deviceId) {
      throw new Error("DEVICE_NOT_ENROLLED");
    }

    const challenge = await post("/v1/device/challenge", {
      device_id: identity.deviceId
    });

    const timestamp = Math.floor(Date.now() / 1000);
    const action = "status";
    const canonical = JSON.stringify({ action });
    const digest = new Uint8Array(
      await crypto.subtle.digest("SHA-256", encoder.encode(canonical))
    );

    const hexDigest = Array.from(
      digest, b => b.toString(16).padStart(2, "0")
    ).join("");

    const signedText = [
      "POST",
      "/v1/device/command",
      String(timestamp),
      challenge.nonce,
      hexDigest
    ].join("\n");

    const rawSignature = new Uint8Array(
      await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        identity.privateKey,
        encoder.encode(signedText)
      )
    );

    const signatureDer = rawEcdsaToDer(rawSignature);

    return post("/v1/device/command", {
      device_id: identity.deviceId,
      nonce: challenge.nonce,
      timestamp,
      action,
      signature: b64url(signatureDer)
    });
  }

  function showResult(message, isError = false) {
    const output = document.getElementById("iao-device-result");
    if (!output) return;
    output.textContent = message;
    output.style.color = isError ? "#c44" : "inherit";
  }

  function addPanel() {
    if (document.getElementById("iao-device-panel")) return;

    const panel = document.createElement("section");
    panel.id = "iao-device-panel";
    panel.style.cssText =
      "margin:18px auto;padding:16px;max-width:680px;" +
      "border:1px solid #8886;border-radius:14px;" +
      "font:inherit;";

    const heading = document.createElement("h3");
    heading.textContent = "Centro de mando · Dispositivo autorizado";

    const explanation = document.createElement("p");
    explanation.textContent =
      "Registra este navegador con un código de un solo uso. " +
      "La autorización disponible actualmente es únicamente de consulta.";

    const input = document.createElement("input");
    input.id = "iao-device-enrollment-code";
    input.type = "password";
    input.autocomplete = "off";
    input.placeholder = "Código de enrolamiento";
    input.style.cssText = "width:100%;box-sizing:border-box;padding:12px;margin:8px 0;";

    const enrollButton = document.createElement("button");
    enrollButton.type = "button";
    enrollButton.textContent = "Registrar este dispositivo";

    const statusButton = document.createElement("button");
    statusButton.type = "button";
    statusButton.textContent = "Verificar autorización";

    const revokeButton = document.createElement("button");
    revokeButton.type = "button";
    revokeButton.textContent = "Eliminar clave local";

    for (const button of [enrollButton, statusButton, revokeButton]) {
      button.style.cssText = "padding:10px 14px;margin:5px;cursor:pointer;";
    }

    const output = document.createElement("pre");
    output.id = "iao-device-result";
    output.style.cssText = "white-space:pre-wrap;overflow-wrap:anywhere;";

    enrollButton.addEventListener("click", async () => {
      enrollButton.disabled = true;
      try {
        const code = input.value.trim();
        if (!code) throw new Error("ENROLLMENT_CODE_REQUIRED");
        if (await dbGet()) throw new Error("DEVICE_ALREADY_ENROLLED");

        const result = await enroll(code);
        input.value = "";
        showResult(
          "DISPOSITIVO REGISTRADO\n" +
          "Algoritmo: " + result.algorithm
        );
      } catch (error) {
        showResult("ERROR: " + error.message, true);
      } finally {
        enrollButton.disabled = false;
      }
    });

    statusButton.addEventListener("click", async () => {
      statusButton.disabled = true;
      try {
        const result = await signedStatus();
        showResult(
          "AUTORIZACIÓN VERIFICADA\n" +
          "Acción: " + result.action +
          "\nAutoridad: " + result.authority
        );
      } catch (error) {
        showResult("ERROR: " + error.message, true);
      } finally {
        statusButton.disabled = false;
      }
    });

    revokeButton.addEventListener("click", async () => {
      if (!window.confirm(
        "Esto elimina la clave local de este navegador. " +
        "No revoca el dispositivo en el servidor. ¿Continuar?"
      )) return;

      try {
        await dbDelete();
        showResult(
          "CLAVE LOCAL ELIMINADA\n" +
          "Para revocación completa también debe revocarse el dispositivo en el servidor."
        );
      } catch (error) {
        showResult("ERROR: " + error.message, true);
      }
    });

    panel.append(
      heading, explanation, input,
      enrollButton, statusButton, revokeButton, output
    );
    document.body.appendChild(panel);

    dbGet().then(identity => {
      if (identity) {
        showResult("Este navegador tiene una clave de dispositivo registrada.");
      } else {
        showResult("Este navegador todavía no está registrado.");
      }
    }).catch(error => {
      showResult("Almacenamiento no disponible: " + error.message, true);
    });
  }

  window.IAODeviceAuthority = Object.freeze({
    publicKeyPem,
    prepareBootstrapIdentity,
    signBootstrapPayload,
    prepareRecoveryIdentity,
    recoveryPublicKeyPem,
    hasRecoveryKey,
    signRecoveryPayload,
    activateRecoveryIdentity,
    signOperatorLoginPayload,
    signedStatus,
    signedTaskHeaders,
    submitQueuedTask,
    signedCancelHeaders,
    cancelQueuedTask
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", addPanel, { once: true });
  } else {
    addPanel();
  }
})();
