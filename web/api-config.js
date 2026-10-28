/* Configuración de API de IAO; generado con respaldo. */
(function () {
  "use strict";
  var base = 'https://iao-backend.onrender.com'.replace(/\\/+$/, "");
  window.IAO_API_BASE = base;
  window.iaoApiUrl = function (path) {
    return base + "/" + String(path).replace(/^\\/+/, "");
  };
  var originalFetch = window.fetch.bind(window);
  window.fetch = function (input, init) {
    try {
      if (typeof input === "string" &&
          /^\\/v1\\//.test(input)) {
        input = window.iaoApiUrl(input);
      } else if (input instanceof URL &&
                 input.pathname.startsWith("/v1/")) {
        input = window.iaoApiUrl(input.pathname + input.search);
      } else if (input instanceof Request) {
        var u = new URL(input.url);
        if (u.pathname.startsWith("/v1/")) {
          input = new Request(
            window.iaoApiUrl(u.pathname + u.search),
            new Request(input, {mode: "cors"})
          );
        }
      }
    } catch (e) {
      return Promise.reject(e);
    }
    return originalFetch(input, init);
  };
})();
