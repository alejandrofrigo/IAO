import json
from types import SimpleNamespace

import apps.api.main as api_main
from starlette.requests import Request


def _response_payload(response):
    return json.loads(response.body)


def _ready_request():
    return Request({
        "type": "http",
        "method": "GET",
        "path": "/health/ready",
        "headers": [],
        "query_string": b"",
        "server": ("test", 80),
        "client": ("test", 123),
        "scheme": "http",
        "http_version": "1.1",
        "root_path": "",
    })


def test_readiness_reports_local_scope_without_claiming_production(monkeypatch):
    service = SimpleNamespace(
        model=object(),
        handle=lambda *_args: (200, {"status": "ready", "checks": {"database": True, "audit_chain": True}}),
    )
    calls = []
    monkeypatch.setattr(api_main, "_get_service", lambda: calls.append(True) or service)
    monkeypatch.setattr(
        api_main, "_federation_worker_status",
        {"autojoin": True, "discovery": False, "external_network": True},
    )

    response = api_main.ready(_ready_request())
    payload = _response_payload(response)

    assert response.status_code == 200
    assert payload["status"] == "degraded"
    assert payload["readiness_scope"] == "local_infrastructure_only"
    assert payload["production_ready"] is False
    assert payload["checks"]["database"] is True
    assert payload["checks"]["federation_workers"] == {
        "autojoin": "start_reported_unverified",
        "discovery": "not_started_or_unavailable",
        "external_network": "start_reported_unverified",
    }
    assert payload["checks"]["model_adapter"] == "configured_unverified"
    assert payload["production_gates"]["independent_federation"] == "not_verified"
    assert len(calls) == 1


def test_readiness_fails_closed_when_local_dependencies_are_not_ready(monkeypatch):
    service = SimpleNamespace(
        model=None,
        handle=lambda *_args: (503, {"status": "not_ready", "checks": {"database": False}}),
    )
    monkeypatch.setattr(api_main, "_get_service", lambda: service)
    response = api_main.ready()
    payload = _response_payload(response)
    assert response.status_code == 503
    assert payload["status"] == "not_ready"
    assert payload["checks"]["database"] is False
    assert "production_ready" not in payload


def test_readiness_hides_internal_runtime_exception(monkeypatch):
    def fail():
        raise RuntimeError("private-runtime-detail")

    monkeypatch.setattr(api_main, "_get_service", fail)
    response = api_main.ready()
    payload = _response_payload(response)
    assert response.status_code == 503
    assert payload == {
        "status": "not_ready",
        "reason": "PERSISTENT_RUNTIME_UNAVAILABLE",
    }
    assert "private-runtime-detail" not in response.body.decode()
