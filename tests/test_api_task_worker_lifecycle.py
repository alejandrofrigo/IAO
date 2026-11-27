from __future__ import annotations

import asyncio
import threading

import pytest

import apps.api.main as api_main


class _Store:
    def __init__(self):
        self.events = []

    def audit(self, *args, **kwargs):
        self.events.append((args, kwargs))


class _Service:
    def __init__(self):
        self.store = _Store()
        self.registry = object()
        self.operator_identity_authority = object()


def test_task_worker_is_disabled_by_default(monkeypatch):
    api_main._stop_task_worker()
    monkeypatch.delenv("IAO_TASK_WORKER_ENABLED", raising=False)

    assert api_main._task_worker_requested() is False
    assert api_main._start_task_worker(_Service()) is False
    assert api_main._task_worker_thread is None


def test_opt_in_worker_uses_existing_store_and_stops_cleanly(monkeypatch):
    api_main._stop_task_worker()
    monkeypatch.setenv("IAO_TASK_WORKER_ENABLED", "true")
    monkeypatch.setenv("IAO_TASK_WORKER_LEASE_SECONDS", "75")
    monkeypatch.setenv("IAO_TASK_WORKER_POLL_SECONDS", "0.2")
    entered = threading.Event()
    stopped = threading.Event()
    constructed = {}

    class FakeTaskWorker:
        def __init__(self, store, registry, **kwargs):
            constructed["store"] = store
            constructed["registry"] = registry
            constructed["kwargs"] = kwargs

        def run_forever(self):
            entered.set()
            stopped.wait(2)

        def stop(self):
            stopped.set()

    monkeypatch.setattr("omega.task_worker.TaskWorker", FakeTaskWorker)
    service = _Service()

    assert api_main._start_task_worker(service) is True
    assert entered.wait(1)
    first_thread = api_main._task_worker_thread
    assert api_main._start_task_worker(service) is True
    assert api_main._task_worker_thread is first_thread
    assert constructed["store"] is service.store
    assert constructed["registry"] is service.registry
    assert constructed["kwargs"]["operator_identity_authority"] is service.operator_identity_authority
    assert constructed["kwargs"]["lease_seconds"] == 75
    assert constructed["kwargs"]["poll_seconds"] == 0.2
    assert service.store.events[0][0] == ("system", "TASK_WORKER_START", "api_lifespan")

    api_main._stop_task_worker()
    assert stopped.is_set()
    assert not first_thread.is_alive()
    assert api_main._task_worker is None
    assert api_main._task_worker_thread is None


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("IAO_TASK_WORKER_LEASE_SECONDS", "1"),
        ("IAO_TASK_WORKER_LEASE_SECONDS", "999"),
        ("IAO_TASK_WORKER_POLL_SECONDS", "0"),
        ("IAO_TASK_WORKER_POLL_SECONDS", "100"),
        ("IAO_TASK_WORKER_LEASE_SECONDS", "not-an-integer"),
        ("IAO_TASK_WORKER_POLL_SECONDS", "not-a-number"),
    ],
)
def test_worker_rejects_unsafe_runtime_settings(monkeypatch, name, value):
    api_main._stop_task_worker()
    monkeypatch.setenv("IAO_TASK_WORKER_ENABLED", "true")
    monkeypatch.setenv(name, value)

    with pytest.raises(RuntimeError, match="TASK_WORKER_SETTINGS_(OUT_OF_RANGE|INVALID)"):
        api_main._start_task_worker(_Service())

    assert api_main._task_worker_thread is None



def test_requested_worker_reports_missing_persistent_keys(monkeypatch):
    api_main._stop_task_worker()
    monkeypatch.setenv("IAO_TASK_WORKER_ENABLED", "true")
    monkeypatch.delenv("OMEGA_DEV_TOKEN_KEY", raising=False)
    monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)

    async def run_lifespan():
        async with api_main._runtime_lifespan(api_main.app):
            assert api_main._task_worker_readiness() == {
                "status": "blocked",
                "reason": "PERSISTENT_KEYS_UNAVAILABLE",
            }

    asyncio.run(run_lifespan())


def test_requested_worker_reports_invalid_settings_in_readiness(monkeypatch):
    api_main._stop_task_worker()
    monkeypatch.setenv("IAO_TASK_WORKER_ENABLED", "true")
    monkeypatch.setenv("OMEGA_DEV_TOKEN_KEY", "t" * 40)
    monkeypatch.setenv("AUDIT_HMAC_KEY", "a" * 40)
    monkeypatch.setenv("IAO_TASK_WORKER_LEASE_SECONDS", "999")
    monkeypatch.setattr(api_main, "_get_service", lambda: _Service())

    async def run_lifespan():
        async with api_main._runtime_lifespan(api_main.app):
            assert api_main._task_worker_readiness() == {
                "status": "start_failed",
                "reason": "TASK_WORKER_SETTINGS_OUT_OF_RANGE",
            }

    asyncio.run(run_lifespan())
