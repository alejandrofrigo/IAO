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


def test_partial_runtime_credentials_are_reported_as_startup_failure(monkeypatch, caplog):
    monkeypatch.setenv("OMEGA_DEV_TOKEN_KEY", "short")
    monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)

    def fail_startup():
        raise RuntimeError("credential-detail-must-not-leak")

    monkeypatch.setattr(api_main, "_get_service", fail_startup)

    async def exercise_lifespan():
        async with api_main._runtime_lifespan(api_main.app):
            return True

    with caplog.at_level(logging.ERROR, logger="iao.runtime"):
        assert asyncio.run(exercise_lifespan()) is True

    assert "RUNTIME_START_FAILED error_type=RuntimeError" in caplog.text
    assert "credential-detail-must-not-leak" not in caplog.text


def test_shutdown_stops_all_owned_discovery_workers(monkeypatch):
    from omega import external_network, federation_autojoin, federation_discovery

    calls = []
    monkeypatch.setattr(
        federation_autojoin, "stop_federation_autojoin",
        lambda timeout: calls.append(("autojoin", timeout)) or True,
    )
    monkeypatch.setattr(
        federation_discovery, "stop_federation_discovery",
        lambda timeout: calls.append(("discovery", timeout)) or True,
    )
    monkeypatch.setattr(
        external_network, "stop_external_network",
        lambda timeout: calls.append(("external_network", timeout)) or True,
    )

    api_main._stop_background_workers()

    assert calls == [
        ("autojoin", 5.0),
        ("discovery", 5.0),
        ("external_network", 5.0),
    ]
