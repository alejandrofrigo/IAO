from tools import iao_federation_autonomous as federation


def test_ipfs_api_must_be_local_control_endpoint():
    assert federation._validate_local_ipfs_api("http://127.0.0.1:5001")
    assert federation._validate_local_ipfs_api("http://localhost:5001/")
    assert not federation._validate_local_ipfs_api("https://127.0.0.1:5001")
    assert not federation._validate_local_ipfs_api("http://8.8.8.8:5001")
    assert not federation._validate_local_ipfs_api("http://127.0.0.1:5001?token=secret")
    assert not federation._validate_local_ipfs_api("http://user:pass@127.0.0.1:5001")


def test_ipfs_peer_keeps_real_multiaddr_without_fabricated_https():
    item = federation._parse_ipfs_peer({
        "Peer": "12D3KooWJ5xExamplePeerIdentifier",
        "Addr": "/ip4/203.0.113.10/tcp/4001/p2p/12D3KooWJ5xExamplePeerIdentifier",
    })
    assert item is not None
    assert item["peer_id"] == "12D3KooWJ5xExamplePeerIdentifier"
    assert item["multiaddr"].startswith("/ip4/")
    assert "url" not in item
    assert item["status"] == "DISCOVERED_UNVERIFIED"
    assert item["granted_capabilities"] == []


def test_ipfs_peer_rejects_malformed_records():
    assert federation._parse_ipfs_peer({"Peer": "short", "Addr": "/ip4/1.2.3.4/tcp/4001"}) is None
    assert federation._parse_ipfs_peer({
        "Peer": "12D3KooWJ5xExamplePeerIdentifier",
        "Addr": "https://example.org",
    }) is None


def test_http_pipeline_does_not_promote_p2p_peer_to_fake_endpoint(tmp_path, monkeypatch):
    monkeypatch.setattr(federation, "NODES", tmp_path / "http-nodes.json")
    count = federation.merge_candidates_into_nodes([{
        "peer_id": "12D3KooWJ5xExamplePeerIdentifier",
        "multiaddr": "/ip4/203.0.113.10/tcp/4001",
        "source": "ipfs_swarm_peer",
        "status": "DISCOVERED_UNVERIFIED",
    }])
    assert count == 0
    assert federation.load(federation.NODES, {"nodes": []})["nodes"] == []


def test_p2p_candidates_are_persisted_separately_and_unverified(tmp_path, monkeypatch):
    monkeypatch.setattr(federation, "STATE", tmp_path)
    peer = {
        "peer_id": "12D3KooWJ5xExamplePeerIdentifier",
        "multiaddr": "/ip4/203.0.113.10/tcp/4001",
        "source": "ipfs_swarm_peer",
        "status": "DISCOVERED_UNVERIFIED",
        "granted_capabilities": [],
    }
    assert federation.merge_p2p_candidates([peer]) == 1
    stored = federation.load(tmp_path / "iao-p2p-candidates.json", {})
    record = stored["peers"][peer["peer_id"]]
    assert record["multiaddr"] == peer["multiaddr"]
    assert record["status"] == "DISCOVERED_UNVERIFIED"
    assert record["granted_capabilities"] == []
def test_libp2p_peer_inventory_is_persisted_separately(tmp_path):
    from omega.libp2p_discovery import persist_discovered_peers
    peers = [{
        "peer_id": "12D3KooWJ5xExamplePeerIdentifier",
        "multiaddrs": ["/ip4/203.0.113.10/tcp/4001"],
        "source": "libp2p_kad_dht",
    }]
    assert persist_discovered_peers(peers, state_dir=tmp_path) == 1
    registry = __import__("json").loads((tmp_path / "peers.json").read_text())
    record = registry["peers"]["12D3KooWJ5xExamplePeerIdentifier"]
    assert record["status"] == "DISCOVERED_UNVERIFIED"
    assert record["granted_capabilities"] == []
    assert record["source"] == "libp2p_kad_dht"

def test_libp2p_inventory_rejects_symlinked_registry(tmp_path):
    import pytest
    from omega.libp2p_discovery import persist_discovered_peers
    target = tmp_path / 'outside.json'
    target.write_text('{"schema":1,"peers":{}}', encoding="utf-8")
    (tmp_path / "peers.json").symlink_to(target)
    with pytest.raises(RuntimeError, match="P2P_REGISTRY_SYMLINK_REFUSED"):
        persist_discovered_peers([], state_dir=tmp_path)

def test_libp2p_inventory_fails_closed_on_corrupt_registry(tmp_path):
    import pytest
    from omega.libp2p_discovery import persist_discovered_peers
    (tmp_path / "peers.json").write_text("not-json", encoding="utf-8")
    with pytest.raises(RuntimeError, match="P2P_REGISTRY_INVALID_FAIL_CLOSED"):
        persist_discovered_peers([], state_dir=tmp_path)
