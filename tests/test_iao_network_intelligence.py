from omega.network_intelligence import (
    configured_bootstrap_count,
    discover_federation,
    run_cycle,
)
from omega.architecture import SUBSYSTEMS


def test_network_intelligence_is_registered():
    spec = SUBSYSTEMS["network_intelligence"]["components"]
    assert "omega.network_intelligence" in spec
    assert "run_cycle" in spec["omega.network_intelligence"]


def test_bootstrap_count_uses_configured_seeds(monkeypatch):
    monkeypatch.setenv(
        "IAO_P2P_BOOTSTRAP_URLS",
        "https://one.example, ,https://two.example",
    )
    assert configured_bootstrap_count() == 2


def test_no_bootstrap_is_not_reported_as_authenticated(monkeypatch):
    monkeypatch.delenv("IAO_P2P_BOOTSTRAP_URLS", raising=False)
    result = discover_federation()
    assert result["status"] == "NO_BOOTSTRAP_CONFIGURED"
    assert result["authenticated_candidates"] is None


def test_run_cycle_has_concurrency_and_interval_controls():
    import inspect
    source = inspect.getsource(run_cycle)
    assert "LOCK_EX | fcntl.LOCK_NB" in source
    assert "MIN_INTERVAL" in source
