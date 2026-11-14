/* IAO public API endpoint; HTTP/2 tunnel health and CORS verified. */
window.IAO_API_BASE = "https://gzip-mercury-intensive-terminology.trycloudflare.com";
window.iaoApiUrl = function (path) {
  return new URL(String(path).replace(/^\/+/, ""), window.IAO_API_BASE + "/").toString();
};
