"""Default CORS policy must not disclose or trust a hard-coded operator origin."""
import os
import threading
import urllib.error
from contextlib import redirect_stderr
from io import StringIO
import urllib.request
import socket
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
                payload = __import__("json").loads(response.read())
                assert response.code == 403
                assert payload["error"] == "CORS_PREFLIGHT_DENIED"
                assert len(payload["correlation_id"]) == 32
                assert response.headers.get("Access-Control-Allow-Origin") is None
                assert response.headers["X-Correlation-ID"] == payload["correlation_id"]
                assert response.headers["Cache-Control"] == "no-store"
                assert response.headers["X-Content-Type-Options"] == "nosniff"
    finally:
        if thread.is_alive():
            httpd.shutdown()
        httpd.server_close()
        if thread.is_alive():
            thread.join(timeout=3)


def test_stdlib_api_rejects_invalid_and_oversized_content_length():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(_Service()))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    cases = (
        ("Content-Length: -1", 400, "INVALID_CONTENT_LENGTH"),
        ("Content-Length: +1", 400, "INVALID_CONTENT_LENGTH"),
        ("Content-Length: not-a-number", 400, "INVALID_CONTENT_LENGTH"),
        ("Content-Length: 65537", 413, "PAYLOAD_TOO_LARGE"),
        ("Transfer-Encoding: chunked", 400, "INVALID_TRANSFER_ENCODING"),
    )
    try:
        for header, expected_status, expected_error in cases:
            with socket.create_connection(httpd.server_address, timeout=3) as sock:
                request = (
                    "POST /v1/memory HTTP/1.1\r\n"
                    "Host: localhost\r\n"
                    f"{header}\r\n"
                    "Connection: close\r\n\r\n"
                )
                sock.sendall(request.encode("ascii"))
                response = bytearray()
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response.extend(chunk)
            head, _, body = bytes(response).partition(b"\r\n\r\n")
            status_line = head.split(b"\r\n", 1)[0]
            assert int(status_line.split()[1]) == expected_status
            payload = __import__("json").loads(body)
            assert payload["error"] == expected_error
            assert len(payload["correlation_id"]) == 32
            headers = head.decode("latin-1").lower()
            assert f"x-correlation-id: {payload['correlation_id']}" in headers
            assert "cache-control: no-store" in headers
            assert "x-content-type-options: nosniff" in headers
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=3)
