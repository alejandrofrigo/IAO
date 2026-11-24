/* IAO public API endpoint; temporary Cloudflare Quick Tunnel. */
window.IAO_API_BASE = "https://approximate-participant-military-parental.trycloudflare.com";
window.iaoApiUrl = function (path) {
 return new URL(String(path).replace(/^\/+/, ""), window.IAO_API_BASE + "/").toString();
};
