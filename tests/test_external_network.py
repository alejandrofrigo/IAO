import json

from omega.external_network import ExternalNetwork, _candidate


class Source:
    name = "test_source"

    def __init__(self, records):
        self.records = records

    def discover(self):
        return self.records


def record(node_id="node-00000001", origin="https://node.example.org"):
    return {
        "node_id": node_id,
        "origin": origin,
        "capabilities": ["knowledge.search", "heartbeat", "../admin", 3],
    }


def test_candidate_is_untrusted_and_has_no_authority():
    item = _candidate(record(), "unit")
    assert item is not None
    assert item["status"] == "DISCOVERED_UNVERIFIED"
    assert item["identity_verified"] is False
    assert item["enrolled"] is False
    assert item["granted_capabilities"] == []
    assert item["remote_code_execution"] is False
    assert item["private_data_access"] is False
    assert item["advertised_capabilities"] == ["heartbeat", "knowledge.search"]


def test_candidate_rejects_non_https_and_non_public_ip():
    assert _candidate(record(origin="http://node.example.org"), "unit") is None
    assert _candidate(record(origin="https://user:pass@node.example.org"), "unit") is None
    assert _candidate(record(origin="https://127.0.0.1"), "unit") is None


def test_cycle_grows_inventory_and_refreshes_existing_candidates(tmp_path):
    network = ExternalNetwork(tmp_path, [Source([record(), record("node-00000002")])])
    assert network.run_cycle()["added"] == 2
    result = network.run_cycle()
    assert result["added"] == 0
    assert result["refreshed"] == 2
    registry = json.loads((tmp_path / "registry.json").read_text())
    assert len(registry["candidates"]) == 2
    assert {item["observations"] for item in registry["candidates"].values()} == {2}


def test_source_failure_does_not_stop_other_sources(tmp_path):
    class Broken:
        name = "broken"
        def discover(self):
            raise RuntimeError("network unavailable")
    network = ExternalNetwork(tmp_path, [Broken(), Source([record()])])
    result = network.run_cycle()
    assert result["source_errors"] == 1
    assert result["added"] == 1


def test_registry_rejects_symlink(tmp_path):
    target = tmp_path / "outside.json"
    target.write_text('{"schema":1,"candidates":{}}')
    (tmp_path / "registry.json").symlink_to(target)
    import pytest
    with pytest.raises(RuntimeError, match="SYMLINK_REFUSED"):
        ExternalNetwork(tmp_path, []).run_cycle()


def test_invalid_registry_fails_closed(tmp_path):
    (tmp_path / "registry.json").write_text("not-json")
    import pytest
    with pytest.raises(Exception):
        ExternalNetwork(tmp_path, []).run_cycle()


def test_candidate_deduplicates_by_identity_and_origin():
    one = _candidate(record(), "feed-a")
    two = _candidate(record(), "feed-b")
    assert one["candidate_id"] == two["candidate_id"]


def test_p2p_inventory_stays_separate_from_http_candidates(tmp_path):
    source = Source([{"peer_id": "12D3KooWJ5xExamplePeerIdentifier",
                      "multiaddr": ["/ip4/203.0.113.10/tcp/4001"]}])
    source.name = "local_p2p_inventory"
    network = ExternalNetwork(tmp_path, [source])
    result = network.run_cycle()
    registry = json.loads((tmp_path / "registry.json").read_text())
    assert result["added"] == 1
    assert registry["candidates"] == {}
    peer = next(iter(registry["p2p_peers"].values()))
    assert peer["status"] == "DISCOVERED_UNVERIFIED"
    assert peer["granted_capabilities"] == []


def test_libp2p_adapter_uses_existing_outbound_discovery(monkeypatch):
    from omega import libp2p_discovery
    from omega.external_network import Libp2pDHTDiscovery

    monkeypatch.setattr(libp2p_discovery, "discover_sync", lambda *args, **kwargs: {
        "status": "DISCOVERY_COMPLETED",
        "peers": [{"peer_id": "12D3KooWJ5xExamplePeerIdentifier",
                   "multiaddrs": ["/ip4/203.0.113.10/tcp/4001"]}],
    })
    found = Libp2pDHTDiscovery().discover()
    assert found[0]["peer_id"] == "12D3KooWJ5xExamplePeerIdentifier"
    assert found[0]["multiaddr"][0].startswith("/")


def test_tor_onion_directory_adapter_discovers_candidates(monkeypatch):
    from omega import federation_transport
    from omega.external_network import TorOnionDirectories

    calls = []
    monkeypatch.setattr(federation_transport, "fetch_onion_json", lambda url, **kw: (
        calls.append((url, kw)) or {"peers": [record()]}
    ))
    source = TorOnionDirectories(["http://" + "d"*56 + ".onion/peers.json"])
    assert source.discover() == [record()]
    assert calls[0][1] == {"timeout": 15, "max_bytes": 500_000}


def test_candidate_refresh_preserves_local_verification_state(tmp_path):
    item = record()
    network = ExternalNetwork(tmp_path, [Source([item])])
    network.run_cycle()
    registry_path = tmp_path / "registry.json"
    registry = json.loads(registry_path.read_text())
    candidate = next(iter(registry["candidates"].values()))
    candidate.update({
        "status": "IDENTITY_VERIFIED",
        "identity_verified": True,
        "enrolled": True,
        "granted_capabilities": ["knowledge.search"],
    })
    registry_path.write_text(json.dumps(registry))
    network.run_cycle()
    refreshed = next(iter(json.loads(registry_path.read_text())["candidates"].values()))
    assert refreshed["status"] == "IDENTITY_VERIFIED"
    assert refreshed["identity_verified"] is True
    assert refreshed["enrolled"] is True
    assert refreshed["granted_capabilities"] == ["knowledge.search"]


def test_unverified_candidates_become_stale_and_are_pruned(tmp_path, monkeypatch):
    from datetime import datetime, timedelta, timezone

    network = ExternalNetwork(tmp_path, [Source([])])
    network.state_dir.mkdir(parents=True)
    old = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
    ancient = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat()
    stale = _candidate(record(), "unit")
    stale.update({"first_seen": old, "last_seen": old})
    expired = _candidate(record("node-00000002"), "unit")
    expired.update({"first_seen": ancient, "last_seen": ancient})
    registry = {
        "schema": 1,
        "candidates": {stale["candidate_id"]: stale, expired["candidate_id"]: expired},
        "p2p_peers": {},
    }
    (tmp_path / "registry.json").write_text(json.dumps(registry))
    result = network.run_cycle()
    saved = json.loads((tmp_path / "registry.json").read_text())["candidates"]
    assert result["stale"] == 1
    assert result["pruned"] == 1
    assert len(saved) == 1
    assert next(iter(saved.values()))["status"] == "STALE_UNVERIFIED"


def test_verified_candidates_are_not_pruned_by_inventory_retention(tmp_path):
    from datetime import datetime, timedelta, timezone

    network = ExternalNetwork(tmp_path, [Source([])])
    network.state_dir.mkdir(parents=True)
    ancient = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
    item = _candidate(record(), "unit")
    item.update({
        "first_seen": ancient, "last_seen": ancient,
        "status": "IDENTITY_VERIFIED", "identity_verified": True,
        "enrolled": True,
    })
    (tmp_path / "registry.json").write_text(json.dumps({
        "schema": 1, "candidates": {item["candidate_id"]: item}, "p2p_peers": {},
    }))
    network.run_cycle()
    saved = json.loads((tmp_path / "registry.json").read_text())["candidates"]
    assert item["candidate_id"] in saved
    assert saved[item["candidate_id"]]["identity_verified"] is True


def test_rediscovery_reactivates_stale_unverified_candidate(tmp_path):
    item = _candidate(record(), "unit")
    item.update({
        "first_seen": "2020-01-01T00:00:00+00:00",
        "last_seen": "2020-01-01T00:00:00+00:00",
        "status": "STALE_UNVERIFIED",
    })
    network = ExternalNetwork(tmp_path, [Source([record()])])
    network.state_dir.mkdir(parents=True)
    (tmp_path / "registry.json").write_text(json.dumps({
        "schema": 1, "candidates": {item["candidate_id"]: item}, "p2p_peers": {},
    }))
    network.run_cycle()
    refreshed = json.loads((tmp_path / "registry.json").read_text())["candidates"][item["candidate_id"]]
    assert refreshed["status"] == "DISCOVERED_UNVERIFIED"
    assert refreshed["last_seen"] != item["last_seen"]
