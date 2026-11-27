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
