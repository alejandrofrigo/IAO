import json
from pathlib import Path

from tools.iao_runtime_recovery import RuntimeRecovery


def test_restart_budget_is_bounded(tmp_path):
    now = [1000.0]
    monitor = RuntimeRecovery(tmp_path, clock=lambda: now[0])

    for _ in range(3):
        assert monitor.record_restart_attempt("PADGE")["allowed"]

    result = monitor.record_restart_attempt("PADGE")
    assert result["allowed"] is False
    assert result["status"] == "RESTART_BUDGET_EXHAUSTED"


def test_restart_budget_recovers_after_window(tmp_path):
    now = [1000.0]
    monitor = RuntimeRecovery(tmp_path, clock=lambda: now[0])

    for _ in range(3):
        monitor.record_restart_attempt("PADGE")

    now[0] += 301
    assert monitor.record_restart_attempt("PADGE")["allowed"]


def test_state_is_persistent(tmp_path):
    first = RuntimeRecovery(tmp_path, clock=lambda: 1000.0)
    first.record_restart_attempt("GUARDIAN")

    second = RuntimeRecovery(tmp_path, clock=lambda: 1001.0)
    result = second.record_restart_attempt("GUARDIAN")
    assert result["allowed"]
    state = json.loads((tmp_path / "state.json").read_text())
    assert len(state["GUARDIAN"]["restart_attempts"]) == 2


def test_invalid_component_name_rejected(tmp_path):
    monitor = RuntimeRecovery(tmp_path)
    try:
        monitor.record_restart_attempt("../PADGE")
    except ValueError:
        pass
    else:
        raise AssertionError("Se aceptó una identidad inválida")


def test_observation_does_not_claim_restart(tmp_path):
    monitor = RuntimeRecovery(tmp_path)
    result = monitor.observe("PADGE", 2147483647, "iao-impossible-process")
    assert result["restart_performed"] is False
