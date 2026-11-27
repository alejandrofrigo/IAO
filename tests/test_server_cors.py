"""Default CORS policy must not disclose or trust a hard-coded operator origin."""
import os
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from omega.server import make_handler


class _Service:
    def handle(self, method, path, headers, body):
        return 200, {"status": "live"}


def test_stdlib_server_has_no_default_cross_origin_allowlist():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(_Service()))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{httpd.server_address[1]}/health/live",
            headers={"Origin": "https://untrusted.example"},
        )
        with patch.dict(os.environ, {}, clear=True):
            with urllib.request.urlopen(request, timeout=3) as response:
                assert response.status == 200
                assert response.headers.get("Access-Control-Allow-Origin") is None
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=3)
