import json
import subprocess

from omega import libp2p_discovery
from tools import iao_autonomous_coordinator
from tools import iao_federation_autonomy


def test_libp2p_discovery_records_public_peers_without_enrolling(monkeypatch):
    monkeypatch.setattr(
        libp2p_discovery,
        "discover_sync",
        lambda timeout: {
            "status": "DISCOVERY_COMPLETED",
            "connected_bootstrappers": 2,
            "routing_peers_discovered": 17,
            "persisted_new_peers": 5,
            "enrollment_performed": False,
        },
    )

    result = iao_federation_autonomy.run_libp2p_discovery()

    assert result == {
        "status": "DISCOVERY_COMPLETED",
        "connected_bootstrappers": 2,
        "routing_peers_discovered": 17,
        "persisted_new_peers": 5,
        "enrollment_performed": False,
        "capabilities_granted": [],
        "remote_code_executed": False,
    }


def test_libp2p_discovery_failure_is_reported_without_crashing(monkeypatch):
    def fail(timeout):
        raise OSError("private endpoint detail")

    monkeypatch.setattr(libp2p_discovery, "discover_sync", fail)
    result = iao_federation_autonomy.run_libp2p_discovery()

    assert result["status"] == "DISCOVERY_ERROR"
    assert result["error_class"] == "OSError"
    assert "private endpoint detail" not in json.dumps(result)


def test_expansion_cycle_is_independent_and_logs_only_counts(monkeypatch):
    report = {
        "libp2p_discovery": {
            "status": "DISCOVERY_COMPLETED",
            "connected_bootstrappers": 2,
            "routing_peers_discovered": 17,
            "persisted_new_peers": 5,
        },
        "active_authorized_feeds": 1,
        "new_candidates": 3,
    }
    monkeypatch.setattr(
        iao_autonomous_coordinator.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, stdout=json.dumps(report), stderr=""
        ),
    )
    events = []
    monkeypatch.setattr(
        iao_autonomous_coordinator,
        "log",
        lambda name, **data: events.append((name, data)),
    )

    assert iao_autonomous_coordinator.run_expansion_once() is True
    assert events[0][0] == "EXPANSION_CYCLE_COMPLETED"
    assert events[0][1]["peers_discovered"] == 17
    assert events[0][1]["new_peers_persisted"] == 5
    assert events[0][1]["peer_enrollment_performed"] is False


def test_expansion_cycle_timeout_is_nonfatal(monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 120)

    monkeypatch.setattr(iao_autonomous_coordinator.subprocess, "run", timeout)
    events = []
    monkeypatch.setattr(
        iao_autonomous_coordinator,
        "log",
        lambda name, **data: events.append((name, data)),
    )

    assert iao_autonomous_coordinator.run_expansion_once() is False
    assert events == [
        (
            "EXPANSION_CYCLE_FAILED",
            {"reason": "TIMEOUT", "timeout_seconds": 120},
        )
    ]
