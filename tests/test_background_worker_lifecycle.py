from __future__ import annotations

from pathlib import Path

from omega import external_network, federation_autojoin, federation_discovery


def test_federation_autojoin_worker_stops_and_can_restart(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(federation_autojoin, "run_cycle", lambda *_: {"status": "ok"})
    assert federation_autojoin.start_federation_autojoin(object(), tmp_path) is True
    assert federation_autojoin.start_federation_autojoin(object(), tmp_path) is False
    assert federation_autojoin.stop_federation_autojoin(timeout=2) is True
    assert federation_autojoin.stop_federation_autojoin(timeout=0) is True
    assert federation_autojoin.start_federation_autojoin(object(), tmp_path) is True
    assert federation_autojoin.stop_federation_autojoin(timeout=2) is True


def test_federation_discovery_worker_stops_and_can_restart(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(federation_discovery, "discover_once", lambda *_: {"errors": 0})
    assert federation_discovery.start_federation_discovery(tmp_path) is True
    assert federation_discovery.start_federation_discovery(tmp_path) is True
    assert federation_discovery.stop_federation_discovery(timeout=2) is True
    assert federation_discovery.stop_federation_discovery(timeout=0) is True
    assert federation_discovery.start_federation_discovery(tmp_path) is True
    assert federation_discovery.stop_federation_discovery(timeout=2) is True


def test_external_network_worker_stops_and_can_restart(monkeypatch, tmp_path: Path):
    class FakeNetwork:
        def __init__(self):
            self.state_dir = tmp_path
            self.registry_path = tmp_path / "registry.json"

        def run_cycle(self):
            return {"discovered": 0}

        def _audit(self, *_args, **_kwargs):
            return None

    monkeypatch.setattr(external_network, "build_network", lambda *_args: FakeNetwork())
    monkeypatch.setenv("IAO_EXTERNAL_NETWORK_INTERVAL", "300")
    assert external_network.start_external_network(tmp_path) is True
    assert external_network.start_external_network(tmp_path) is False
    assert external_network.stop_external_network(timeout=2) is True
    assert external_network.stop_external_network(timeout=0) is True
    assert external_network.start_external_network(tmp_path) is True
    assert external_network.stop_external_network(timeout=2) is True
