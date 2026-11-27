import json
from pathlib import Path

from tools import iao_libp2p_discovery as worker


def test_cycle_persists_only_safe_discovery_status(tmp_path, monkeypatch):
    monkeypatch.setattr(worker, "state_dir", lambda: tmp_path)
    monkeypatch.setattr(
        worker.libp2p_discovery,
        "discover_sync",
        lambda **kwargs: {
            "status": "DISCOVERY_COMPLETED",
            "connected_bootstrappers": 2,
            "routing_peers_discovered": 7,
            "persisted_new_peers": 4,
            "enrollment_performed": False,
            "capabilities_granted": [],
            "remote_code_executed": False,
        },
    )
    report = worker.cycle(timeout=5)
    stored = json.loads((tmp_path / "discovery-report.json").read_text())
    assert report == stored
    assert report["status"] == "DISCOVERY_COMPLETED"
    assert report["routing_peers_discovered"] == 7
    assert report["enrollment_performed"] is False
    assert report["capabilities_granted"] == []
    assert report["remote_code_executed"] is False
    assert report["listener_exposed"] is False


def test_cycle_reports_optional_dependency_failure_without_claiming_success(tmp_path, monkeypatch):
    monkeypatch.setattr(worker, "state_dir", lambda: tmp_path)
    def fail(**kwargs):
        raise ImportError("optional libp2p dependency unavailable")
    monkeypatch.setattr(worker.libp2p_discovery, "discover_sync", fail)
    report = worker.cycle()
    assert report["status"] == "DISCOVERY_ERROR"
    assert report["error_class"] == "ImportError"
    assert report["enrollment_performed"] is False


def test_interval_is_bounded(monkeypatch):
    monkeypatch.setenv("IAO_LIBP2P_DISCOVERY_INTERVAL", "1")
    assert worker.read_interval() == worker.MIN_INTERVAL
    monkeypatch.setenv("IAO_LIBP2P_DISCOVERY_INTERVAL", "999999")
    assert worker.read_interval() == worker.MAX_INTERVAL
    monkeypatch.setenv("IAO_LIBP2P_DISCOVERY_INTERVAL", "bad")
    assert worker.read_interval() == worker.DEFAULT_INTERVAL


def test_report_refuses_symlink(tmp_path):
    target = tmp_path / "outside"
    target.write_text("{}")
    link = tmp_path / "discovery-report.json"
    link.symlink_to(target)
    import pytest
    with pytest.raises(RuntimeError, match="SYMLINK"):
        worker._atomic_report(link, {"status": "x"})
    assert target.read_text() == "{}"
