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

def test_stdlib_cors_preflight_matches_api_mutation_methods_and_rejects_patch():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(_Service()))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    url = f"http://127.0.0.1:{httpd.server_address[1]}/v1/memory"
    try:
        with patch.dict(os.environ, {"IAO_CORS_ORIGINS": "https://app.example"}, clear=True):
            request = urllib.request.Request(
                url,
                method="OPTIONS",
                headers={
                    "Origin": "https://app.example",
                    "Access-Control-Request-Method": "DELETE",
                    "Access-Control-Request-Headers": "authorization, content-type",
                },
            )
            thread.start()
            with urllib.request.urlopen(request, timeout=3) as response:
                assert response.status == 204
                assert response.headers["Access-Control-Allow-Methods"] == (
                    "GET, POST, PUT, DELETE, OPTIONS"
                )

            denied = urllib.request.Request(
                url,
                method="OPTIONS",
                headers={
                    "Origin": "https://app.example",
                    "Access-Control-Request-Method": "PATCH",
                },
            )
            try:
                urllib.request.urlopen(denied, timeout=3)
                raise AssertionError("PATCH preflight must be denied")
            except urllib.error.HTTPError as response:
                assert response.code == 403
                assert response.headers.get("Access-Control-Allow-Origin") is None
    finally:
        if thread.is_alive():
            httpd.shutdown()
        httpd.server_close()
        if thread.is_alive():
            thread.join(timeout=3)
