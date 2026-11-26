import json

from omega.ipfs_assimilator import IPFSAssimilator
from omega.federation_assimilation_engine import AssimilationEngine
from omega.federation_discovery_engine import DiscoveryEngine


def test_ipfs_candidates_are_never_active(tmp_path, monkeypatch):
    import omega.ipfs_assimilator as module
    monkeypatch.setattr(module, "STATE", tmp_path / "ipfs.json")
    obj = IPFSAssimilator()
    total = obj.discover_nodes()
    assert total > 0
    assert all(v["operational"] is False for v in obj.memory.values())
    assert all(v["status"] == "discovered" for v in obj.memory.values())


def test_ipfs_does_not_announce_render_placeholder(monkeypatch):
    monkeypatch.delenv("IAO_PUBLIC_FEDERATION_URL", raising=False)
    obj = IPFSAssimilator()
    assert obj.announce_self() is None


def test_http_success_alone_never_assimilates():
    obj = AssimilationEngine()
    assert obj.test_node(obj.seed_nodes[0]) is False
    assert obj.assimilate() == []
    assert obj.get_capacity() == 0


def test_discovery_seeds_are_not_active(tmp_path, monkeypatch):
    import omega.federation_discovery_engine as module
    monkeypatch.setattr(module, "STATE", tmp_path / "nodes.json")
    obj = DiscoveryEngine()
    assert obj.get_active_nodes() == {}
    assert all(
        item["status"] == "discovered"
        for item in obj.memory.values()
    )


def test_legacy_active_without_evidence_is_downgraded(tmp_path, monkeypatch):
    import omega.federation_discovery_engine as module
    state = tmp_path / "nodes.json"
    state.write_text(json.dumps({
        "Legacy": {
            "url": "https://example.org",
            "status": "active",
            "operational": True,
        }
    }))
    monkeypatch.setattr(module, "STATE", state)
    obj = DiscoveryEngine()
    assert obj.memory["Legacy"]["status"] == "discovered"
    assert obj.get_active_nodes() == {}


def test_verified_active_requires_all_evidence(tmp_path, monkeypatch):
    import omega.federation_discovery_engine as module
    monkeypatch.setattr(module, "STATE", tmp_path / "nodes.json")
    obj = DiscoveryEngine()
    obj.memory["Verified"] = {
        "url": "https://node.example.org",
        "status": "active",
        "operational": True,
        "checks": {
            "identity_verified": True,
            "protocol_verified": True,
            "real_exchange_confirmed": True,
        },
    }
    assert "Verified" in obj.get_active_nodes()
