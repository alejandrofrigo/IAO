import json
from types import SimpleNamespace

import apps.api.main as api_main
from starlette.requests import Request
from omega import supervision


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
    assert payload["checks"]["task_worker"] == "disabled_by_default"
    assert payload["production_gates"]["independent_federation"] == "not_verified"
    assert len(calls) == 1


def test_readiness_fails_closed_when_local_dependencies_are_not_ready(monkeypatch):
    service = SimpleNamespace(
        model=None,
        handle=lambda *_args: (503, {"status": "not_ready", "checks": {"database": False}}),
    )
    monkeypatch.setattr(api_main, "_get_service", lambda: service)
    response = api_main.ready(_ready_request())
    payload = _response_payload(response)
    assert response.status_code == 503
    assert payload["status"] == "not_ready"
    assert payload["checks"]["database"] is False
    assert "production_ready" not in payload


def test_readiness_hides_internal_runtime_exception(monkeypatch):
    def fail():
        raise RuntimeError("private-runtime-detail")

    monkeypatch.setattr(api_main, "_get_service", fail)
    response = api_main.ready(_ready_request())
    payload = _response_payload(response)
    assert response.status_code == 503
    assert payload["status"] == "not_ready"
    assert payload["reason"] == "PERSISTENT_RUNTIME_UNAVAILABLE"
    assert isinstance(payload["correlation_id"], str)
    assert len(payload["correlation_id"]) == 32
    assert "private-runtime-detail" not in response.body.decode()


def test_task_worker_readiness_requires_heartbeat_and_live_pid(monkeypatch, tmp_path):
    monkeypatch.setenv("IAO_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(
        supervision,
        "read_heartbeat",
        lambda *_args, **_kwargs: {"status": "HEALTHY", "pid": 4242},
        raising=False,
    )
    monkeypatch.setattr(api_main.os, "kill", lambda pid, sig: None)
    assert api_main._task_worker_health() == "healthy"

    monkeypatch.setattr(
        supervision,
        "read_heartbeat",
        lambda *_args, **_kwargs: {"status": "STALE", "pid": 4242},
        raising=False,
    )
    assert api_main._task_worker_health() == "stale_heartbeat"

    def missing(pid, sig):
        raise ProcessLookupError
    monkeypatch.setattr(supervision, "read_heartbeat", lambda *_a, **_k: {"status": "HEALTHY", "pid": 4242}, raising=False)
    monkeypatch.setattr(api_main.os, "kill", missing)
    assert api_main._task_worker_health() == "process_not_alive"


def test_task_worker_readiness_rejects_pid_without_heartbeat(monkeypatch, tmp_path):
    monkeypatch.setenv("IAO_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(
        supervision,
        "read_heartbeat",
        lambda *_args, **_kwargs: {"status": "UNVERIFIED", "pid": 4242},
        raising=False,
    )
    monkeypatch.setattr(
        api_main.os, "kill",
        lambda *_args: (_ for _ in ()).throw(AssertionError("PID must not be probed without heartbeat")),
    )
    assert api_main._task_worker_health() == "heartbeat_unverified"
