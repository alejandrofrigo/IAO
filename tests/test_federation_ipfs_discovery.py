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
