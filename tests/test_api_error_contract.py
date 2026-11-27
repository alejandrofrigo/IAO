"""Stable and privacy-safe error envelopes across FastAPI entrypoints."""
import asyncio

from starlette.requests import Request

from apps.api import main
from tests.test_production_api import configured_client


def test_device_route_hides_unexpected_exception_with_correlation_headers(monkeypatch, tmp_path):
    client = configured_client(monkeypatch, tmp_path)

    def fail_service():
        raise ValueError("private-device-runtime-marker")

    monkeypatch.setattr(main, "_get_service", fail_service)
    response = client.post("/v1/device/challenge", json={})
    payload = response.json()
    assert response.status_code == 503
    assert payload["error"] == "IAO_SERVICE_UNAVAILABLE"
    assert isinstance(payload["correlation_id"], str)
    assert len(payload["correlation_id"]) == 32
    assert response.headers["x-correlation-id"] == payload["correlation_id"]
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "private-device-runtime-marker" not in response.text


def test_negative_content_length_uses_common_error_contract():
    request = Request({
        "type": "http",
        "method": "POST",
        "path": "/v1/device/challenge",
        "headers": [(b"content-length", b"-1")],
        "query_string": b"",
        "server": ("test", 80),
        "client": ("test", 123),
        "scheme": "http",
        "http_version": "1.1",
        "root_path": "",
    })
    _body, error = asyncio.run(main._read_bounded_service_body(request))
    assert error.status_code == 400
    assert error.body
    assert error.headers["cache-control"] == "no-store"
    assert error.headers["x-content-type-options"] == "nosniff"
    assert len(error.headers["x-correlation-id"]) == 32


def test_unknown_fastapi_route_uses_common_not_found_contract(monkeypatch, tmp_path):
    client = configured_client(monkeypatch, tmp_path)
    response = client.get("/unmapped-route-private-marker")
    payload = response.json()
    assert response.status_code == 404
    assert payload["error"] == "NOT_FOUND"
    assert len(payload["correlation_id"]) == 32
    assert response.headers["x-correlation-id"] == payload["correlation_id"]
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "private-marker" not in response.text


def test_framework_exception_handler_never_echoes_internal_detail():
    request = Request({
        "type": "http", "method": "GET", "path": "/unmapped",
        "headers": [], "query_string": b"", "server": ("test", 80),
        "client": ("test", 123), "scheme": "http", "http_version": "1.1",
        "root_path": "",
    })
    response = asyncio.run(main._unhandled_exception_handler(
        request, RuntimeError("private-framework-exception-marker"),
    ))
    assert response.status_code == 500
    assert b"private-framework-exception-marker" not in response.body
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert len(response.headers["x-correlation-id"]) == 32

def test_service_response_always_supplies_valid_correlation_header():
    response = main._service_response(400, {"error": "INVALID_REQUEST"})
    payload = response.body.decode("utf-8")
    import json
    decoded = json.loads(payload)
    correlation_id = decoded["correlation_id"]
    assert len(correlation_id) == 32
    assert all(char in "0123456789abcdef" for char in correlation_id)
    assert response.headers["x-correlation-id"] == correlation_id
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_signed_non_decimal_content_length_is_rejected():
    request = Request({
        "type": "http",
        "method": "POST",
        "path": "/v1/device/challenge",
        "headers": [(b"content-length", b"+1")],
        "query_string": b"",
        "server": ("test", 80),
        "client": ("test", 123),
        "scheme": "http",
        "http_version": "1.1",
        "root_path": "",
    })
    _body, error = asyncio.run(main._read_bounded_service_body(request))
    assert error.status_code == 400
    assert error.body
    assert error.headers["x-correlation-id"]
    assert error.headers["cache-control"] == "no-store"
    assert error.headers["x-content-type-options"] == "nosniff"
