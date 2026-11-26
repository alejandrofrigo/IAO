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
  async function request(path, method, body, omitAuth = false) {
    const headers = {};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (!omitAuth && typeof window.iaoGetSessionToken === "function") {
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
  function generateOfflineRecoveryCode() {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    let binary = "";
    for (const value of bytes) binary += String.fromCharCode(value);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  async function bootstrap(code, recoveryCode) {
    if (!crypto.subtle || !window.indexedDB) throw new Error("BROWSER_CRYPTO_OR_STORAGE_UNAVAILABLE");
    if (!window.IAODeviceAuthority ||
        typeof window.IAODeviceAuthority.prepareBootstrapIdentity !== "function" ||
        typeof window.IAODeviceAuthority.signBootstrapPayload !== "function" ||
        typeof window.IAODeviceAuthority.activateRecoveryIdentity !== "function") {
      throw new Error("DEVICE_BOOTSTRAP_NOT_AVAILABLE");
    }
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
      // Keep both pending private keys if the network outcome is ambiguous.
      await writeIdentity(stored);
    }
    const device = await window.IAODeviceAuthority.prepareBootstrapIdentity();
    const devicePublicKeyPem = device.publicKeyPem;
    const encodedPem = devicePublicKeyPem
      .replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s/g, "");
    const deviceDer = Uint8Array.from(atob(encodedPem), ch => ch.charCodeAt(0));
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", deviceDer));
    const deviceId = Array.from(digest, value => value.toString(16).padStart(2, "0")).join("");
    const bindingPayload = encoder.encode(JSON.stringify({
      device_id: deviceId,
      key_version: 1,
      protocol: "IAO-DEVICE-BINDING-V1",
      public_key_sha256: deviceId,
      role: "PRIMARY"
    }));
    const rootMessage = new Uint8Array(ROOT_DOMAIN.length + bindingPayload.length);
    rootMessage.set(ROOT_DOMAIN);
    rootMessage.set(bindingPayload, ROOT_DOMAIN.length);
    const rootRaw = new Uint8Array(await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" }, stored.privateKey, rootMessage
    ));
    const payloadEncoded = b64url(bindingPayload);
    const deviceSignature = await window.IAODeviceAuthority.signBootstrapPayload(payloadEncoded);
    const result = await request("/v1/operator/bootstrap", "POST", {
      code,
      recovery_code: recoveryCode,
      root_public_key_pem: stored.publicKeyPem,
      device_public_key_pem: devicePublicKeyPem,
      root_signature: b64url(rawEcdsaToDer(rootRaw)),
      device_signature: deviceSignature
    });
    if (result.status !== "ROOT_AND_DEVICE_REGISTERED" ||
        result.authority !== "OPERATOR_BOOTSTRAPPED_READ_ONLY" ||
        result.device_registered !== true || result.key_version !== 1) {
      throw new Error("INVALID_OPERATOR_BOOTSTRAP_RESPONSE");
    }
    await window.IAODeviceAuthority.activateRecoveryIdentity(devicePublicKeyPem);
    await writeIdentity({
      privateKey: stored.privateKey,
      publicKeyPem: stored.publicKeyPem,
      keyVersion: result.key_version,
      createdAt: Date.now(),
      bootstrapPending: false
    });
    return { ...result, recoveryCode };
  }
  async function recoverIdentity(recoveryCode, newRecoveryCode) {
    if (!crypto.subtle || !window.indexedDB) throw new Error("BROWSER_CRYPTO_OR_STORAGE_UNAVAILABLE");
    if (typeof recoveryCode !== "string" || recoveryCode.length < 32 || recoveryCode.length > 512) {
      throw new Error("INVALID_OPERATOR_RECOVERY_CODE");
    }
    if (typeof newRecoveryCode !== "string" || newRecoveryCode.length < 32 || newRecoveryCode.length > 512 || newRecoveryCode === recoveryCode) {
      throw new Error("INVALID_NEW_OPERATOR_RECOVERY_CODE");
    }
    if (!window.IAODeviceAuthority ||
        typeof window.IAODeviceAuthority.prepareRecoveryIdentity !== "function" ||
        typeof window.IAODeviceAuthority.signRecoveryPayload !== "function") {
      throw new Error("DEVICE_RECOVERY_NOT_AVAILABLE");
    }
    let stored = await readIdentity() || {};
    if (!stored.recoveryPendingPrivateKey) {
      const generated = await generateRootKey();
      stored = {
        ...stored,
        recoveryPendingPrivateKey: generated.privateKey,
        recoveryPendingPublicKeyPem: generated.publicKeyPem,
        recoveryPendingAt: Date.now()
      };
      await writeIdentity(stored);
    }
    let devicePublicKeyPem = stored.recoveryPendingDevicePublicKeyPem;
    if (devicePublicKeyPem &&
        !(await window.IAODeviceAuthority.hasRecoveryKey(devicePublicKeyPem))) {
      const updated = { ...stored };
      delete updated.recoveryPendingDevicePublicKeyPem;
      stored = updated;
      devicePublicKeyPem = null;
      await writeIdentity(stored);
    }
    if (!devicePublicKeyPem) {
      devicePublicKeyPem = await window.IAODeviceAuthority.recoveryPublicKeyPem().catch(async () => {
        const prepared = await window.IAODeviceAuthority.prepareRecoveryIdentity();
        return prepared.publicKeyPem;
      });
      stored = { ...stored, recoveryPendingDevicePublicKeyPem: devicePublicKeyPem };
      await writeIdentity(stored);
    }
    const reconciliation = await request("/v1/operator/recovery/status", "POST", {
      new_root_public_key_pem: stored.recoveryPendingPublicKeyPem,
      new_device_public_key_pem: devicePublicKeyPem
    });
    if (reconciliation.committed === true) {
      await window.IAODeviceAuthority.activateRecoveryIdentity(devicePublicKeyPem);
      await writeIdentity({
        privateKey: stored.recoveryPendingPrivateKey,
        publicKeyPem: stored.recoveryPendingPublicKeyPem,
        identityId: stored.identityId || null,
        keyVersion: reconciliation.key_version,
        createdAt: Date.now(),
        bootstrapPending: false
      });
      return {
        authority: "OPERATOR_RECOVERED_READ_ONLY",
        key_version: reconciliation.key_version,
        device_replaced: true,
        recovery_code_rotated: true,
        recoveryCode: newRecoveryCode,
        reconciled: true
      };
    }
    const challenge = await request("/v1/operator/recovery/challenge", "POST", {
      recovery_code: recoveryCode,
      new_root_public_key_pem: stored.recoveryPendingPublicKeyPem,
      new_device_public_key_pem: devicePublicKeyPem,
      new_recovery_code: newRecoveryCode
    });
    if (challenge.protocol !== "IAO-OPERATOR-RECOVERY-V1" ||
        typeof challenge.challenge !== "string" ||
        typeof challenge.signing_payload !== "string") {
      throw new Error("INVALID_OPERATOR_RECOVERY_CHALLENGE");
    }
    const encoded = challenge.signing_payload.replace(/-/g, "+").replace(/_/g, "/");
    const payload = Uint8Array.from(
      atob(encoded + "=".repeat((4 - encoded.length % 4) % 4)),
      c => c.charCodeAt(0)
    );
    const rootDomain = encoder.encode("IAO-OPERATOR-RECOVERY-V1\x00");
    const rootMessage = new Uint8Array(rootDomain.length + payload.length);
    rootMessage.set(rootDomain); rootMessage.set(payload, rootDomain.length);
    const rootRaw = new Uint8Array(await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" }, stored.recoveryPendingPrivateKey, rootMessage
    ));
    const deviceSignature = await window.IAODeviceAuthority.signRecoveryPayload(
      challenge.signing_payload
    );
    const result = await request("/v1/operator/recovery/complete", "POST", {
      challenge: challenge.challenge,
      root_signature: b64url(rawEcdsaToDer(rootRaw)),
      device_signature: deviceSignature
    });
    await window.IAODeviceAuthority.activateRecoveryIdentity();
    await writeIdentity({
      privateKey: stored.recoveryPendingPrivateKey,
      publicKeyPem: stored.recoveryPendingPublicKeyPem,
      identityId: stored.identityId || null,
      keyVersion: result.key_version,
      createdAt: Date.now(),
      bootstrapPending: false
    });
    return { ...result, recoveryCode: newRecoveryCode };
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
  async function revokeIdentity() {
    const identity = await readIdentity();
    const sessionToken = typeof window.iaoGetSessionToken === "function"
      ? window.iaoGetSessionToken() : "";
    let sessionIdentityId = null;
    try {
      const payloadPart = sessionToken.split(".")[0].replace(/-/g, "+").replace(/_/g, "/");
      const claims = JSON.parse(atob(payloadPart + "=".repeat((4 - payloadPart.length % 4) % 4)));
      const match = typeof claims.sub === "string"
        ? /^operator:([0-9a-f]{32})$/.exec(claims.sub) : null;
      sessionIdentityId = match ? match[1] : null;
    } catch (_) {}
    const identityId = identity && identity.identityId || sessionIdentityId;
    if (!identity || !identity.privateKey || !identity.keyVersion || !identityId) {
      throw new Error("ROOT_IDENTITY_OR_OPERATOR_SESSION_NOT_ENROLLED");
    }
    if (!window.confirm("Revocar permanentemente la identidad raíz y desactivar el dispositivo primario? Esta acción requiere el código de recuperación offline para recuperar el acceso.")) {
      return { cancelled: true };
    }
    const payload = encoder.encode("revoke-root-v1\n" + identityId);
    const message = new Uint8Array(ROOT_DOMAIN.length + payload.length);
    message.set(ROOT_DOMAIN); message.set(payload, ROOT_DOMAIN.length);
    const raw = new Uint8Array(await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" }, identity.privateKey, message
    ));
    const result = await request("/v1/operator/identity/revoke", "POST", {
      key_version: identity.keyVersion,
      signature: b64url(rawEcdsaToDer(raw))
    });
    await deleteIdentity();
    if (typeof window.iaoClearOperatorSession === "function") {
      window.iaoClearOperatorSession();
    }
    return result;
  }
  async function deleteIdentity() {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).delete("root");
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = () => { db.close(); reject(tx.error); };
      tx.onabort = () => { db.close(); reject(tx.error); };
    });
  }
  async function login() {
    if (!crypto.subtle || !window.indexedDB) throw new Error("BROWSER_CRYPTO_OR_STORAGE_UNAVAILABLE");
    const identity = await readIdentity();
    if (!identity || !identity.privateKey || !identity.keyVersion) {
      throw new Error("ROOT_IDENTITY_NOT_ENROLLED");
    }
    if (!window.IAODeviceAuthority ||
        typeof window.IAODeviceAuthority.signOperatorLoginPayload !== "function") {
      throw new Error("DEVICE_AUTHORITY_NOT_AVAILABLE");
    }
    const challenge = await request("/v1/operator/login/challenge", "POST", {}, true);
    if (challenge.protocol !== "IAO-OPERATOR-LOGIN-V1" ||
        typeof challenge.challenge !== "string" ||
        typeof challenge.signing_payload !== "string") {
      throw new Error("INVALID_OPERATOR_LOGIN_CHALLENGE");
    }
    const encoded = challenge.signing_payload.replace(/-/g, "+").replace(/_/g, "/");
    const payload = Uint8Array.from(
      atob(encoded + "=".repeat((4 - encoded.length % 4) % 4)),
      c => c.charCodeAt(0)
    );
    const rootMessage = new Uint8Array(ROOT_DOMAIN.length + payload.length);
    rootMessage.set(ROOT_DOMAIN);
    rootMessage.set(payload, ROOT_DOMAIN.length);
    const rootRaw = new Uint8Array(await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" }, identity.privateKey, rootMessage
    ));
    const deviceSignature = await window.IAODeviceAuthority.signOperatorLoginPayload(
      challenge.signing_payload
    );
    const result = await request("/v1/operator/login/complete", "POST", {
      challenge: challenge.challenge,
      root_signature: b64url(rawEcdsaToDer(rootRaw)),
      device_signature: deviceSignature
    }, true);
    if (typeof result.access_token !== "string" ||
        result.authority !== "OPERATOR_AUTHENTICATED_READ_ONLY" ||
        !Array.isArray(result.scopes) || result.scopes.length !== 0 ||
        result.expires_in !== 900) {
      throw new Error("INVALID_OPERATOR_LOGIN_RESPONSE");
    }
    if (typeof window.iaoActivateOperatorSession !== "function") {
      throw new Error("OPERATOR_SESSION_ACTIVATION_UNAVAILABLE");
    }
    await window.iaoActivateOperatorSession(result.access_token);
    return result;
  }
  async function bindPrimaryDevice(publicKeyPem) {
    const identity = await readIdentity();
    if (!identity || !identity.privateKey || !identity.keyVersion) throw new Error("ROOT_IDENTITY_NOT_ENROLLED");
    if (typeof publicKeyPem !== "string" || publicKeyPem.length > 4096) throw new Error("DEVICE_PUBLIC_KEY_REQUIRED");
    const encoded = publicKeyPem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s/g, "");
    const der = Uint8Array.from(atob(encoded), c => c.charCodeAt(0));
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", der));
    const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
    const deviceId = hex(digest);
    const payload = encoder.encode(JSON.stringify({
      device_id: deviceId,
      key_version: identity.keyVersion,
      protocol: "IAO-DEVICE-BINDING-V1",
      public_key_sha256: deviceId,
      role: "PRIMARY"
    }));
    const message = new Uint8Array(ROOT_DOMAIN.length + payload.length);
    message.set(ROOT_DOMAIN); message.set(payload, ROOT_DOMAIN.length);
    const raw = new Uint8Array(await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" }, identity.privateKey, message
    ));
    return request("/v1/operator/device/bind", "POST", {
      public_key_pem: publicKeyPem, signature: b64url(rawEcdsaToDer(raw))
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
    description.textContent = "La clave privada se genera en este navegador y se guarda como CryptoKey no exportable. El código de bootstrap se usa una sola vez y no se conserva. La sesión pública de visitante no puede asociarse: se requiere una sesión autenticada de operador.";
    const code = document.createElement("input");
    code.type = "password"; code.autocomplete = "off"; code.placeholder = "Código de bootstrap fuera de banda";
    code.style.cssText = "width:100%;box-sizing:border-box;padding:12px;margin:8px 0;";
    const recoveryCode = document.createElement("input");
    recoveryCode.type = "password"; recoveryCode.autocomplete = "off";
    recoveryCode.placeholder = "Código de recuperación offline actual";
    recoveryCode.style.cssText = "width:100%;box-sizing:border-box;padding:12px;margin:8px 0;";
    const newRecoveryCode = document.createElement("input");
    newRecoveryCode.type = "password"; newRecoveryCode.autocomplete = "off";
    newRecoveryCode.placeholder = "Nuevo código de recuperación offline (mínimo 32 caracteres)";
    newRecoveryCode.style.cssText = "width:100%;box-sizing:border-box;padding:12px;margin:8px 0;";
    const bootstrapRecoveryCode = document.createElement("input");
    bootstrapRecoveryCode.type = "password"; bootstrapRecoveryCode.autocomplete = "off";
    bootstrapRecoveryCode.placeholder = "Crear código de recuperación offline (mínimo 32 caracteres)";
    bootstrapRecoveryCode.style.cssText = "width:100%;box-sizing:border-box;padding:12px;margin:8px 0;";
    const generateBootstrapRecoveryButton = document.createElement("button");
    generateBootstrapRecoveryButton.type = "button";
    generateBootstrapRecoveryButton.textContent = "Generar código offline";
    const generateNewRecoveryButton = document.createElement("button");
    generateNewRecoveryButton.type = "button";
    generateNewRecoveryButton.textContent = "Generar nuevo código offline";
    const bootstrapButton = document.createElement("button");
    bootstrapButton.type = "button"; bootstrapButton.textContent = "Registrar identidad raíz";
    const recoveryButton = document.createElement("button");
    recoveryButton.type = "button"; recoveryButton.textContent = "Recuperar identidad y sustituir dispositivo";
    const loginButton = document.createElement("button");
    loginButton.type = "button"; loginButton.textContent = "Iniciar sesión de operador";
    const associateButton = document.createElement("button");
    associateButton.type = "button"; associateButton.textContent = "Asociar sesión autenticada";
    const statusButton = document.createElement("button");
    statusButton.type = "button"; statusButton.textContent = "Consultar asociación";
    const revokeButton = document.createElement("button");
    revokeButton.type = "button"; revokeButton.textContent = "Revocar identidad y dispositivo";
    const bindDeviceButton = document.createElement("button");
    bindDeviceButton.type = "button"; bindDeviceButton.textContent = "Vincular dispositivo primario";
    const output = document.createElement("pre");
    output.style.cssText = "white-space:pre-wrap;overflow-wrap:anywhere;";
    let sessionAuthority = "UNAVAILABLE";
    function show(message, failed) { output.textContent = message; output.style.color = failed ? "#c44" : "inherit"; }
    function applySessionGates() {
      const hasToken = typeof window.iaoGetSessionToken === "function" &&
        Boolean(window.iaoGetSessionToken());
      associateButton.disabled = !hasToken || sessionAuthority !== "UNBOUND_READ_ONLY";
      bindDeviceButton.disabled = !hasToken || sessionAuthority !== "IDENTITY_BOUND_READ_ONLY";
    }
    async function refreshSessionGates() {
      sessionAuthority = "UNAVAILABLE";
      applySessionGates();
      if (typeof window.iaoGetSessionToken !== "function" || !window.iaoGetSessionToken()) return;
      try {
        const current = await status();
        sessionAuthority = typeof current.authority === "string"
          ? current.authority : "UNAVAILABLE";
      } catch (_) {
        sessionAuthority = "UNAVAILABLE";
      }
      applySessionGates();
    }
    async function run(button, action, success) {
      button.disabled = true;
      try { show(success(await action()), false); }
      catch (error) { show("ERROR: " + error.message, true); }
      finally { await refreshSessionGates(); }
    }
    generateBootstrapRecoveryButton.addEventListener("click", () => {
      bootstrapRecoveryCode.value = generateOfflineRecoveryCode();
    });
    generateNewRecoveryButton.addEventListener("click", () => {
      newRecoveryCode.value = generateOfflineRecoveryCode();
    });
    recoveryButton.addEventListener("click", () => run(
      recoveryButton, async () => {
        const secret = recoveryCode.value;
        const nextSecret = newRecoveryCode.value;
        if (!secret) throw new Error("OPERATOR_RECOVERY_CODE_REQUIRED");
        if (!nextSecret) throw new Error("NEW_OPERATOR_RECOVERY_CODE_REQUIRED");
        const result = await recoverIdentity(secret, nextSecret);
        recoveryCode.value = "";
        newRecoveryCode.value = "";
        return result;
      },
      result => "IDENTIDAD RECUPERADA\\nVersión de clave: " + result.key_version + "\\nDispositivo sustituido: " + result.device_replaced + "\\nNuevo código offline (guárdalo ahora):\\n" + result.recoveryCode
    ));
    bootstrapButton.addEventListener("click", () => run(bootstrapButton, async () => {
      const secret = code.value;
      const recoverySecret = bootstrapRecoveryCode.value;
      if (!secret) throw new Error("OPERATOR_BOOTSTRAP_REQUIRED");
      if (!recoverySecret) throw new Error("OPERATOR_RECOVERY_CODE_REQUIRED");
      if (secret === recoverySecret) throw new Error("RECOVERY_CODE_MUST_DIFFER_FROM_BOOTSTRAP");
      const result = await bootstrap(secret, recoverySecret);
      code.value = "";
      bootstrapRecoveryCode.value = "";
      return result;
    }, result => "IDENTIDAD RAÍZ REGISTRADA\nAlgoritmo: " + result.algorithm + "\nVersión: " + result.key_version + "\nCódigo de recuperación offline (guárdalo ahora):\n" + result.recoveryCode));
    loginButton.addEventListener("click", () => run(
      loginButton, login,
      result => "SESIÓN DE OPERADOR AUTENTICADA\nAutoridad: " + result.authority + "\nPermisos: ninguno (solo lectura)"
    ));
    associateButton.addEventListener("click", () => run(
      associateButton, associateSession,
      result => "ASOCIACIÓN VERIFICADA\nAutoridad: " + result.authority
    ));
    statusButton.addEventListener("click", () => run(statusButton, status,
      result => "Asociada: " + (result.associated ? "sí" : "no") + "\nAutoridad: " + result.authority
    ));
    revokeButton.addEventListener("click", () => run(
      revokeButton, revokeIdentity,
      result => result.cancelled ? "Revocación cancelada." : "IDENTIDAD REVOCADA\nDispositivo desactivado: " + result.device_revoked
    ));
    bindDeviceButton.addEventListener("click", () => run(bindDeviceButton, async () => {
      if (!window.IAODeviceAuthority || typeof window.IAODeviceAuthority.publicKeyPem !== "function") {
        throw new Error("DEVICE_AUTHORITY_NOT_AVAILABLE");
      }
      return bindPrimaryDevice(await window.IAODeviceAuthority.publicKeyPem());
    }, result => "DISPOSITIVO VINCULADO\nAutoridad: " + result.authority + "\nVersión: " + result.key_version));
    section.append(title, description, code, bootstrapRecoveryCode, generateBootstrapRecoveryButton, bootstrapButton, recoveryCode, newRecoveryCode, generateNewRecoveryButton, recoveryButton, loginButton, associateButton, statusButton, bindDeviceButton, revokeButton, output);
    document.body.appendChild(section);
    window.addEventListener("iao-session-changed", refreshSessionGates);
    refreshSessionGates();
    readIdentity().then(identity => show(
      identity ? (identity.bootstrapPending ? "Clave raíz local conservada; confirma el bootstrap o consulta su estado." : "Clave raíz local disponible en este navegador.") : "No hay identidad raíz registrada en este navegador.", false
    )).catch(error => show("Almacenamiento no disponible: " + error.message, true));
  }
  window.IAOOperatorIdentity = Object.freeze({ login, associateSession, bindPrimaryDevice, recoverIdentity, revokeIdentity, status });
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", panel, { once: true });
  else panel();
})();