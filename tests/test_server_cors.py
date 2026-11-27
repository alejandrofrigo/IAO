"""Default CORS policy must not disclose or trust a hard-coded operator origin."""
import os
import threading
from contextlib import redirect_stderr
from io import StringIO
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
            f"http://127.0.0.1:{httpd.server_address[1]}/health/live?token=private-query-marker",
            headers={"Origin": "https://untrusted.example"},
        )
        captured = StringIO()
        with patch.dict(os.environ, {}, clear=True), redirect_stderr(captured):
            with urllib.request.urlopen(request, timeout=3) as response:
                assert response.status == 200
                assert response.headers.get("Access-Control-Allow-Origin") is None
        log = captured.getvalue()
        assert "private-query-marker" not in log
        assert "/health/live" not in log
        assert '"route_group": "health"' in log
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=3)
