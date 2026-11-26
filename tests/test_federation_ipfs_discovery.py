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


def test_existing_libp2p_identity_permissions_are_restricted(tmp_path):
    import os
    import stat
    from omega.libp2p_discovery import _secure_identity_file
    key_path = tmp_path / "peer-identity.key"
    key_path.write_bytes(b"test-private-key-material")
    os.chmod(key_path, 0o644)
    _secure_identity_file(key_path)
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600


def test_libp2p_identity_refuses_symlink(tmp_path):
    import pytest
    from omega.libp2p_discovery import _secure_identity_file
    target = tmp_path / "target.key"
    target.write_bytes(b"private")
    link = tmp_path / "peer-identity.key"
    link.symlink_to(target)
    with pytest.raises(RuntimeError, match="P2P_IDENTITY_PATH_REFUSED"):
        _secure_identity_file(link)


def test_external_peer_is_not_enrolled_without_trusted_transport():
    from tools import iao_federation_autonomous as federation
    result = federation.enroll_if_consented(
        None,
        "iao-federation",
        {"endpoint": "https://peer.example.org/fed/v1/message"},
        {"ok": True, "peer_id": "0123456789abcdef"},
        {"capabilities": ["knowledge.search"]},
        {"require_mutual_tls": True, "allowed_capabilities": ["knowledge.search"]},
    )
    assert result["status"] == "BLOCKED_TRUSTED_TRANSPORT_NOT_INTEGRATED"
    assert result["enrollment_performed"] is False
    assert result["capabilities_granted"] == []


def test_external_federation_handshake_is_blocked_until_transport_adapter():
    from tools.iao_federation_autonomous import _remote_handshake_allowed
    assert _remote_handshake_allowed("http://127.0.0.1:8080/fed/v1/message")
    assert _remote_handshake_allowed("https://localhost/fed/v1/message")
    assert not _remote_handshake_allowed("https://peer.example.org/fed/v1/message")
    assert not _remote_handshake_allowed("https://10.1.2.3/fed/v1/message")
