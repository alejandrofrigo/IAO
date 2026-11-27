import asyncio
import logging

import apps.api.main as api_main


def test_configured_startup_failure_is_logged_without_exception_message(monkeypatch, caplog):
    monkeypatch.setenv("OMEGA_DEV_TOKEN_KEY", "a" * 32)
    monkeypatch.setenv("AUDIT_HMAC_KEY", "b" * 32)

    def fail_startup():
        raise RuntimeError("sensitive-runtime-detail")

    monkeypatch.setattr(api_main, "_get_service", fail_startup)

    async def exercise_lifespan():
        async with api_main._runtime_lifespan(api_main.app):
            return "liveness-remains-available"

    with caplog.at_level(logging.ERROR, logger="iao.runtime"):
        result = asyncio.run(exercise_lifespan())

    assert result == "liveness-remains-available"
    assert "RUNTIME_START_FAILED error_type=RuntimeError" in caplog.text
    assert "sensitive-runtime-detail" not in caplog.text


def test_liveness_only_startup_does_not_require_persistent_keys(monkeypatch):
    monkeypatch.delenv("OMEGA_DEV_TOKEN_KEY", raising=False)
    monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
    called = []
    monkeypatch.setattr(api_main, "_get_service", lambda: called.append(True))

    async def exercise_lifespan():
        async with api_main._runtime_lifespan(api_main.app):
            return True

    assert asyncio.run(exercise_lifespan()) is True
    assert called == []
