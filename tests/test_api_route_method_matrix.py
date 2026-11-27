"""Known /v1 routes expose the same method contract in both HTTP adapters."""
import json
import os
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from apps.api import main
from omega.server import build_service, make_handler
from starlette.middleware.cors import CORSMiddleware
from tests.test_production_api import configured_client


ROUTE_METHODS = [
    ("/health/live", ("GET",)),
    ("/health/ready", ("GET",)),
    ("/v1/public/session", ("POST",)),
    ("/v1/operator/bootstrap/status", ("POST",)),
    ("/v1/operator/bootstrap", ("POST",)),
    ("/v1/operator/recovery/status", ("POST",)),
    ("/v1/operator/recovery/challenge", ("POST",)),
    ("/v1/operator/recovery/complete", ("POST",)),
    ("/v1/operator/login/challenge", ("POST",)),
    ("/v1/operator/login/complete", ("POST",)),
    ("/v1/operator/identity/revoke", ("POST",)),
    ("/v1/operator/device/bind", ("POST",)),
    ("/v1/operator/session/challenge", ("POST",)),
    ("/v1/operator/session/bind", ("POST",)),
    ("/v1/operator/session/status", ("GET",)),
    ("/v1/federation/status", ("GET",)),
    ("/v1/federation/internet", ("POST",)),
    ("/v1/me", ("GET",)),
    ("/v1/conversations", ("POST",)),
    ("/v1/conversations/00000000-0000-0000-0000-000000000001/messages", ("GET",)),
    ("/v1/chat", ("POST",)),
    ("/v1/tasks", ("POST",)),
    ("/v1/tasks/00000000-0000-0000-0000-000000000002", ("GET",)),
    ("/v1/audit/events", ("GET",)),
    ("/v1/device/enroll", ("POST",)),
    ("/v1/device/challenge", ("POST",)),
    ("/v1/device/command", ("POST",)),
    ("/v1/memory", ("GET", "POST", "DELETE")),
    ("/v1/memory/export", ("GET",)),
    ("/v1/memory/00000000-0000-0000-0000-000000000003", ("PUT", "DELETE")),
]


def _wrong_method(allowed):
    if allowed == ("GET",):
        return "POST"
    if allowed == ("POST",):
        return "GET"
    return "PATCH"


def _assert_405(status, payload, headers, allowed):
    assert status == 405
    assert payload["error"] == "METHOD_NOT_ALLOWED"
    assert payload["allowed_methods"] == list(allowed)
    assert headers["Allow"] == ", ".join(allowed)
    assert headers["X-Correlation-ID"] == payload["correlation_id"]
    assert len(payload["correlation_id"]) == 32
    assert headers["Cache-Control"] == "no-store"
    assert headers["X-Content-Type-Options"] == "nosniff"





def test_fastapi_cors_method_allowlist_matches_stdlib():
    middleware = next(
        item for item in main.app.user_middleware
        if item.cls is CORSMiddleware
    )
    assert set(middleware.kwargs["allow_methods"]) == {
        "GET", "POST", "PUT", "DELETE", "OPTIONS",
    }


def test_fastapi_v1_known_route_method_matrix(monkeypatch, tmp_path):
    client = configured_client(monkeypatch, tmp_path)
    try:
        for path, allowed in ROUTE_METHODS:
            response = client.request(_wrong_method(allowed), path)
            _assert_405(
                response.status_code,
                response.json(),
                response.headers,
                allowed,
            )
    finally:
        if main._service is not None:
            main._service.store.close()
            main._service = None
            main._federation_node = None


def test_stdlib_v1_known_route_method_matrix(tmp_path):
    audit_key = "route-matrix-audit-key-" + "y" * 40
    token_key = "route-matrix-token-key-" + "x" * 40
    corpus = os.path.abspath("docs/corpus")
    with patch.dict(os.environ, {"AUDIT_HMAC_KEY": audit_key}, clear=False):
        service = build_service(
            tmp_path / "state",
            token_key,
            corpus,
            identity_rollback_anchor_enabled=False,
        )
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(service))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        for path, allowed in ROUTE_METHODS:
            method = _wrong_method(allowed)
            request = urllib.request.Request(
                base + path,
                data=b"" if method == "POST" else None,
                method=method,
            )
            try:
                urllib.request.urlopen(request, timeout=3)
                raise AssertionError(f"method {method} unexpectedly accepted for {path}")
            except urllib.error.HTTPError as response:
                payload = json.loads(response.read())
                _assert_405(response.code, payload, response.headers, allowed)
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=3)
        service.store.close()

PROTECTED_ROUTES = [
    ("GET", "/v1/operator/session/status", b""),
    ("POST", "/v1/operator/session/challenge", b"{}"),
    ("POST", "/v1/operator/session/bind", b"{}"),
    ("POST", "/v1/operator/identity/revoke", b"{}"),
    ("POST", "/v1/operator/device/bind", b"{}"),
    ("POST", "/v1/device/enroll", b"{}"),
    ("POST", "/v1/device/challenge", b"{}"),
    ("POST", "/v1/device/command", b"{}"),
    ("POST", "/v1/federation/internet", b"{}"),
    ("GET", "/v1/me", b""),
    ("POST", "/v1/conversations", b"{}"),
    ("GET", "/v1/conversations/00000000-0000-0000-0000-000000000001/messages", b""),
    ("POST", "/v1/chat", b"{}"),
    ("POST", "/v1/tasks", b"{}"),
    ("GET", "/v1/tasks/00000000-0000-0000-0000-000000000002", b""),
    ("GET", "/v1/audit/events", b""),
    ("GET", "/v1/memory", b""),
    ("GET", "/v1/memory/export", b""),
    ("PUT", "/v1/memory/00000000-0000-0000-0000-000000000003", b'{"value":"x"}'),
    ("DELETE", "/v1/memory/00000000-0000-0000-0000-000000000003", b""),
]


def test_every_privileged_v1_route_requires_a_bearer(tmp_path, monkeypatch):
    audit_key = "route-auth-audit-key-" + "y" * 40
    token_key = "route-auth-token-key-" + "x" * 40
    monkeypatch.setenv("AUDIT_HMAC_KEY", audit_key)
    service = build_service(
        tmp_path / "state",
        token_key,
        os.path.abspath("docs/corpus"),
        identity_rollback_anchor_enabled=False,
    )
    try:
        for method, path, body in PROTECTED_ROUTES:
            status, payload = service.handle(method, path, {}, body)
            assert status == 401, (method, path, status, payload)
            assert payload["error"] == "AUTHENTICATION_REQUIRED", (method, path, payload)
            assert len(payload["correlation_id"]) == 32
    finally:
        service.store.close()
