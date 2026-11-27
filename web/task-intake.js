(() => {
  const queryEl = document.querySelector("#iao-task-query");
  const submitButton = document.querySelector("#iao-task-submit");
  const refreshButton = document.querySelector("#iao-task-refresh");
  const cancelButton = document.querySelector("#iao-task-cancel");
  const authStatusEl = document.querySelector("#iao-task-auth-status");
  const statusEl = document.querySelector("#iao-task-status");
  const resultEl = document.querySelector("#iao-task-result");
  if (!queryEl || !submitButton || !refreshButton || !cancelButton || !authStatusEl || !statusEl || !resultEl) return;

  let latestTaskId = null;
  let pendingIdempotency = null;
  let busy = false;
  let lastSessionToken = sessionToken();

  function sessionToken() {
    return typeof window.iaoGetSessionToken === "function"
      ? window.iaoGetSessionToken()
      : null;
  }

  function setStatus(value) {
    statusEl.textContent = value;
  }

  function setAuthStatus(value) {
    authStatusEl.textContent = value;
  }

  function newIdempotencyKey() {
    if (crypto.randomUUID) return crypto.randomUUID();
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, value => value.toString(16).padStart(2, "0")).join("");
  }

  async function refreshGate() {
    const token = sessionToken();
    const configured = window.IAO_API_CONFIG_STATUS === "configured" &&
      typeof window.iaoApiUrl === "function";
    if (!configured || !token) {
      queryEl.disabled = true;
      submitButton.disabled = true;
      refreshButton.disabled = true;
      cancelButton.disabled = true;
      setAuthStatus("Inicia sesión como operador y vincula el dispositivo primario.");
      return false;
    }
    if (!window.IAOOperatorIdentity ||
        typeof window.IAOOperatorIdentity.capabilityGrantStatus !== "function") {
      queryEl.disabled = true;
      submitButton.disabled = true;
      refreshButton.disabled = true;
      cancelButton.disabled = true;
      setAuthStatus("La autoridad de capacidades no está disponible.");
      return false;
    }
    try {
      const status = await window.IAOOperatorIdentity.capabilityGrantStatus();
      const active = Array.isArray(status.active_capabilities) &&
        status.active_capabilities.includes("knowledge.search");
      queryEl.disabled = !active || busy;
      submitButton.disabled = !active || busy;
      refreshButton.disabled = !latestTaskId || busy;
      cancelButton.disabled = !latestTaskId || !token || busy;
      setAuthStatus(active
        ? "Autorización activa: knowledge.search (solo lectura, corpus IAO)."
        : "Sin autorización activa. Concede knowledge.search desde el panel de identidad.");
      return active;
    } catch (error) {
      queryEl.disabled = true;
      submitButton.disabled = true;
      refreshButton.disabled = true;
      cancelButton.disabled = !latestTaskId || !token || busy;
      setAuthStatus("No se pudo verificar la autorización: " + String(error.message || error));
      return false;
    }
  }

  async function submitTask() {
    const query = queryEl.value.trim();
    if (!query || query.length > 500 || busy) return;
    if (!window.IAODeviceAuthority ||
        typeof window.IAODeviceAuthority.submitQueuedTask !== "function") {
      setStatus("El cliente seguro del dispositivo no está disponible.");
      return;
    }
    busy = true;
    submitButton.disabled = true;
    refreshButton.disabled = true;
    resultEl.textContent = "";
    setStatus("Verificando autorización y enviando la búsqueda...");
    try {
      const active = await refreshGate();
      if (!active) throw new Error("CAPABILITY_NOT_GRANTED");
      const payload = {
        goal: "Consulta de solo lectura en el corpus de IAO",
        capability: "knowledge.search",
        input: { query },
        execution_mode: "queued"
      };
      if (!pendingIdempotency || pendingIdempotency.query !== query) {
        pendingIdempotency = {query, key: newIdempotencyKey()};
      }
      const result = await window.IAODeviceAuthority.submitQueuedTask(
        payload, pendingIdempotency.key
      );
      if (
        !result || typeof result.task_id !== "string" ||
        !/^[0-9a-f-]{36}$/.test(result.task_id) ||
        result.state !== "QUEUED"
      ) {
        throw new Error("INVALID_QUEUED_TASK_RESPONSE");
      }
      latestTaskId = result.task_id;
      pendingIdempotency = null;
      queryEl.value = "";
      resultEl.textContent = JSON.stringify({
        task_id: result.task_id,
        state: result.state,
        capability: "knowledge.search"
      }, null, 2);
      setStatus("Búsqueda aceptada por la cola de IAO. Si el TaskWorker está activo, volverá a verificar la autorización antes de ejecutarla.");
    } catch (error) {
      setStatus("No se pudo enviar la tarea: " + String(error.message || error));
    } finally {
      busy = false;
      await refreshGate();
    }
  }

  async function refreshTaskStatus() {
    if (!latestTaskId || busy) return;
    const token = sessionToken();
    if (!token || typeof window.iaoApiUrl !== "function") {
      setStatus("Sesión no disponible para consultar el estado.");
      return;
    }
    busy = true;
    refreshButton.disabled = true;
    setStatus("Consultando estado de la tarea...");
    try {
      const response = await fetch(
        window.iaoApiUrl("/v1/tasks/" + encodeURIComponent(latestTaskId)),
        {
          method: "GET",
          headers: { Authorization: "Bearer " + token },
          credentials: "omit",
          cache: "no-store"
        }
      );
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || "HTTP_" + response.status);
      resultEl.textContent = JSON.stringify({
        task_id: data.task_id,
        state: data.state,
        capability: "knowledge.search",
        result: data.result || null
      }, null, 2);
      setStatus("Estado consultado: " + data.state + ".");
    } catch (error) {
      setStatus("No se pudo consultar la tarea: " + String(error.message || error));
    } finally {
      busy = false;
      await refreshGate();
    }
  }

  async function cancelTask() {
    if (!latestTaskId || busy) return;
    if (!window.IAODeviceAuthority ||
        typeof window.IAODeviceAuthority.cancelQueuedTask !== "function") {
      setStatus("El cliente seguro del dispositivo no está disponible.");
      return;
    }
    busy = true;
    cancelButton.disabled = true;
    setStatus("Firmando la cancelación con el dispositivo primario...");
    try {
      const result = await window.IAODeviceAuthority.cancelQueuedTask(latestTaskId);
      resultEl.textContent = JSON.stringify({
        task_id: latestTaskId,
        state: result.state,
        cancellation: result.cancellation
      }, null, 2);
      setStatus("Cancelación: " + result.cancellation + ". Estado: " + result.state + ".");
    } catch (error) {
      setStatus("No se pudo cancelar la tarea: " + String(error.message || error));
    } finally {
      busy = false;
      await refreshGate();
    }
  }

  submitButton.addEventListener("click", submitTask);
  refreshButton.addEventListener("click", refreshTaskStatus);
  cancelButton.addEventListener("click", cancelTask);
  window.addEventListener("iao-session-changed", () => {
    const token = sessionToken();
    if (token !== lastSessionToken) {
      latestTaskId = null;
      resultEl.textContent = "";
      lastSessionToken = token;
    }
    void refreshGate();
  });
  window.addEventListener("iao-capabilities-changed", () => { void refreshGate(); });
  void refreshGate();
})();
