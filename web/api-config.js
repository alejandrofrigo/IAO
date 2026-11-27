/* Fail-closed IAO API endpoint configuration.
 * Inject IAO_API_BASE_OVERRIDE at deployment time or provide
 * <meta name="iao-api-base" content="https://api.example.invalid">.
 * Never bake temporary Quick Tunnel URLs or credentials into this file.
 */
(function configureIAOApi(global) {
  "use strict";

  function configuredValue() {
    if (typeof global.IAO_API_BASE_OVERRIDE === "string" &&
        global.IAO_API_BASE_OVERRIDE.trim()) {
      return global.IAO_API_BASE_OVERRIDE.trim();
    }
    if (global.document && typeof global.document.querySelector === "function") {
      const meta = global.document.querySelector('meta[name="iao-api-base"]');
      if (meta && typeof meta.content === "string" && meta.content.trim()) {
        return meta.content.trim();
      }
    }
    return "";
  }

  function normalizeBase(value) {
    if (typeof value !== "string" || !value || value.length > 512) {
      throw new Error("INVALID_API_BASE");
    }
    let parsed;
    try {
      parsed = new URL(value);
    } catch (_error) {
      throw new Error("INVALID_API_BASE");
    }
    const loopback = parsed.hostname === "localhost" ||
      parsed.hostname === "127.0.0.1" || parsed.hostname === "[::1]";
    if ((parsed.protocol !== "https:" &&
         !(parsed.protocol === "http:" && loopback)) ||
        !parsed.hostname || parsed.username || parsed.password ||
        (parsed.port && parsed.port !== "443" &&
         !(parsed.protocol === "http:" && loopback)) ||
        (parsed.pathname !== "/" && parsed.pathname !== "") ||
        parsed.search || parsed.hash) {
      throw new Error("INVALID_API_BASE");
    }
    return parsed.origin;
  }

  let base = "";
  let configError = "API_BASE_NOT_CONFIGURED";
  const candidate = configuredValue();
  if (candidate) {
    try {
      base = normalizeBase(candidate);
      configError = "";
    } catch (_error) {
      configError = "INVALID_API_BASE";
    }
  }

  global.IAO_API_BASE = base;
  global.IAO_API_CONFIG_STATUS = base ? "configured" : "blocked";
  global.IAO_API_CONFIG_ERROR = base ? "" : configError;
  global.iaoApiUrl = function iaoApiUrl(path) {
    if (!base) throw new Error(configError || "API_BASE_NOT_CONFIGURED");
    const rawPath = typeof path === "string" ? path.split("?", 1)[0] : "";
    if (typeof path !== "string" ||
        !(path.startsWith("/v1/") || path.startsWith("/health/")) ||
        rawPath.startsWith("//") || rawPath.includes("//") || rawPath.includes("\\")) {
      throw new Error("INVALID_API_PATH");
    }
    const target = new URL(path.slice(1), base + "/");
    if (target.origin !== base || target.username || target.password ||
        !(target.pathname.startsWith("/v1/") ||
          target.pathname.startsWith("/health/"))) {
      throw new Error("INVALID_API_PATH");
    }
    return target.toString();
  };
})(window);
