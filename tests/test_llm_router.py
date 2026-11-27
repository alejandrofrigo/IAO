"""Deterministic tests for provider selection, failover and secret-safe health state."""
from __future__ import annotations

import json

import pytest

from omega import llm_router as router


def provider(ident: str, priority: int = 100) -> dict[str, object]:
    return {
        "id": ident,
        "url": f"https://{ident}.example.test/v1",
        "model": f"{ident}-model",
        "key_env": f"{ident.upper()}_API_KEY",
        "priority": priority,
    }


def test_failover_records_only_error_class_and_recovers_success(monkeypatch):
    first, second = provider("first", 1), provider("second", 2)
    monkeypatch.setattr(router, "providers", lambda: [first, second])
    state = {}
    monkeypatch.setattr(router, "health", lambda: state)
    saved = []

    def persist(path, data):
        state.clear()
        state.update(data)
        saved.append(data.copy())

    monkeypatch.setattr(router, "_write_json", persist)
    calls = []

    def request(candidate, messages, timeout):
        calls.append(candidate["id"])
        if candidate["id"] == "first":
            raise TimeoutError("synthetic private transport detail")
        return "respuesta válida", "second-upstream-model"

    monkeypatch.setattr(router, "_request", request)
    monkeypatch.setattr(router.time, "time", lambda: 1_700_000_000)
    monkeypatch.setattr(router.random, "randint", lambda low, high: 0)

    result = router.chat_with_metadata([{"role": "user", "content": "hola"}])

    assert calls == ["first", "second"]
    assert result == {
        "reply": "respuesta válida",
        "model_identity": {
            "provider_id": "second",
            "configured_model": "second-model",
            "upstream_model": "second-upstream-model",
            "identity_status": "upstream_model_reported",
        },
    }
    assert saved[-1]["first"]["last_error"] == "TimeoutError"
    assert saved[-1]["second"]["failures"] == 0
    assert "synthetic private transport detail" not in json.dumps(saved)


def test_cooling_provider_is_skipped_when_another_is_ready(monkeypatch):
    cooling, ready = provider("cooling", 1), provider("ready", 2)
    monkeypatch.setattr(router, "providers", lambda: [cooling, ready])
    monkeypatch.setattr(
        router, "health",
        lambda: {"cooling": {"failures": 3, "retry_after": 500}, "ready": {"retry_after": 0}},
    )
    calls = []

    def request(candidate, messages, timeout):
        calls.append(candidate["id"])
        return "ok", None

    monkeypatch.setattr(router, "_request", request)
    monkeypatch.setattr(router.time, "time", lambda: 100)
    monkeypatch.setattr(router, "_write_json", lambda path, data: None)

    result = router.chat_with_metadata([{"role": "user", "content": "hola"}])

    assert calls == ["ready"]
    assert result["model_identity"]["identity_status"] == "configured_model_only"


def test_all_provider_errors_are_sanitized_and_health_contains_no_secret(monkeypatch):
    secret = "SYNTHETIC-DO-NOT-LOG-credential-value"
    candidates = [provider("alpha", 1), provider("beta", 2)]
    monkeypatch.setattr(router, "providers", lambda: candidates)
    monkeypatch.setattr(router, "health", lambda: {})
    saved = []
    monkeypatch.setattr(router, "_write_json", lambda path, data: saved.append(data.copy()))

    def request(candidate, messages, timeout):
        raise RuntimeError(secret)

    monkeypatch.setattr(router, "_request", request)
    monkeypatch.setattr(router.time, "time", lambda: 1_700_000_000)
    monkeypatch.setattr(router.random, "randint", lambda low, high: 0)

    with pytest.raises(RuntimeError) as caught:
        router.chat_with_metadata([{"role": "user", "content": "hola"}])

    assert str(caught.value) == "IAO_ALL_PROVIDERS_FAILED: alpha:RuntimeError, beta:RuntimeError"
    serialized = json.dumps(saved) + str(caught.value)
    assert secret not in serialized
    assert all(state["last_error"] == "RuntimeError" for state in saved[-1].values())


def test_provider_status_exposes_no_key_material(monkeypatch):
    secret = "SYNTHETIC-STATUS-SECRET"
    monkeypatch.setenv("ALPHA_API_KEY", secret)
    monkeypatch.setattr(router, "providers", lambda: [provider("alpha")])
    monkeypatch.setattr(router, "health", lambda: {"alpha": {"failures": 1, "last_success": None}})

    result = router.status()

    assert result["configured"] == 1
    assert result["providers"][0]["id"] == "alpha"
    assert secret not in json.dumps(result)
