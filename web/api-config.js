/* Provider-neutral API configuration.
 * GitHub Pages injects an HTTPS origin at build time when IAO_API_BASE_URL is set.
 * An empty value intentionally disables API calls; never point the public client
 * at an ephemeral tunnel or silently fall back to an unrelated origin.
 */
window.IAO_API_BASE = "";
window.iaoApiUrl = function (path) {
  const base = String(window.IAO_API_BASE || "").trim();
  if (!base) throw new Error("IAO_API_ENDPOINT_NOT_CONFIGURED");
  const origin = new URL(base);
  if (origin.protocol !== "https:" || !origin.hostname ||
      origin.username || origin.password || origin.pathname !== "/" ||
      origin.search || origin.hash) {
    throw new Error("IAO_API_ENDPOINT_INVALID");
  }
  const relative = String(path || "").replace(/^\/+/, "");
  return new URL(relative, origin.origin + "/").toString();
};
