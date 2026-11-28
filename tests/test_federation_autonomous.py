from __future__ import annotations

import base64
import json
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from omega.audit import canonical_json
from omega.federation import _sign, node_id_of
from omega import federation_autonomous as autonomous


class FakeFederationNode:
    def __init__(self):
        self.node_id = "1" * 16
        self.served = frozenset({"knowledge.search"})
        self.peers = {}

    @staticmethod
    def verify_publication(publication):
        from omega.federation import Node
        return Node.verify_publication(publication)

    @staticmethod
    def clock():
        return time.time()

    def _validate_peer_contract(self, contract):
        assert contract["capabilities"] == ["knowledge.search"]
        assert contract["endpoint"].endswith("/fed/v1/message")
        assert contract["lease_expires_at"] > self.clock()

    def enroll(self, contract, *, granted_capabilities):
        self.peers[contract["peer_id"]] = {
            **contract, "granted_capabilities": granted_capabilities,
            "revoked": False,
        }


def setup_peer(monkeypatch, tmp_path, *, consent=True, revoked=False):
    remote_key = Ed25519PrivateKey.generate()
    pub = remote_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    peer_id = node_id_of(pub)
    origin = "https://peer.example.org"
    endpoint = origin + "/fed/v1/message"
    now = time.time()
    body = {
        "protocol": "iao-federation-publication",
        "version": 1,
        "node_id": peer_id,
        "public_key": pub.hex(),
        "endpoint": endpoint,
        "capabilities": ["knowledge.search"],
        "consent": consent,
        "lease_expires_at": now + 3600,
        "issued_at": now,
    }
    publication = {
        **body,
        "sig": base64.b64encode(remote_key.sign(canonical_json(body))).decode(),
    }
    identity = {
        "protocol": "iao-federation", "version": 1,
        "node_id": peer_id, "public_key": pub.hex(),
    }
    contract = {
        "peer_id": peer_id,
        "pubkey": base64.b64encode(pub).decode(),
        "capabilities": ["knowledge.search"],
        "lease_expires_at": now + 3600,
        "rate_limit_per_min": 30,
    }
    def fake_get(url, *, timeout, max_bytes):
        if url.endswith("/fed/v1/publication"): return publication
        if url.endswith("/fed/v1/identity"): return identity
        if url.endswith("/fed/v1/contract"): return contract
        raise AssertionError(url)
    def fake_post(url, payload, *, timeout, max_bytes):
        proof = {
            "v": 1, "protocol": "iao-federation",
            "from": peer_id, "to": payload["from"],
            "nonce": payload["nonce"],
            "request_ts": float(payload["ts"]),
            "ts": time.time(),
        }
        return 200, _sign(remote_key, proof)
    from omega import federation_transport
    monkeypatch.setattr(federation_transport, "fetch_public_json", fake_get)
    monkeypatch.setattr(federation_transport, "post_public_json", fake_post)
    node = FakeFederationNode()
    if revoked:
        node.peers[peer_id] = {"pub": pub, "endpoint": endpoint, "revoked": True}
    candidate = {
        "candidate_id": "a" * 64, "node_id": peer_id,
        "origin": origin, "status": "DISCOVERED_UNVERIFIED",
        "identity_verified": False, "enrolled": False,
    }
    registry = tmp_path / "registry.json"
    registry.write_text(json.dumps({
        "schema": 1, "candidates": {candidate["candidate_id"]: candidate},
        "p2p_peers": {},
    }))
    return node, registry, candidate, peer_id


def test_discovered_peer_enrolls_only_after_signed_consent_and_challenge(monkeypatch, tmp_path):
    node, registry, candidate, peer_id = setup_peer(monkeypatch, tmp_path)
    result = autonomous.run_discovered_cycle(node, tmp_path, registry)
    saved = json.loads(registry.read_text())["candidates"][candidate["candidate_id"]]
    assert result["enrolled"] == 1
    assert peer_id in node.peers
    assert node.peers[peer_id]["granted_capabilities"] == []
    assert saved["status"] == "ENROLLED"
    assert saved["identity_verified"] is True
    assert saved["remote_code_execution"] is False


def test_discovered_peer_without_explicit_consent_is_not_enrolled(monkeypatch, tmp_path):
    node, registry, candidate, peer_id = setup_peer(
        monkeypatch, tmp_path, consent=False
    )
    result = autonomous.run_discovered_cycle(node, tmp_path, registry)
    saved = json.loads(registry.read_text())["candidates"][candidate["candidate_id"]]
    assert result["enrolled"] == 0
    assert peer_id not in node.peers
    assert saved["identity_verified"] is False


def test_local_revocation_cannot_be_overridden_by_automatic_reenrollment(monkeypatch, tmp_path):
    node, registry, candidate, peer_id = setup_peer(
        monkeypatch, tmp_path, revoked=True
    )
    result = autonomous.run_discovered_cycle(node, tmp_path, registry)
    assert result["enrolled"] == 0
    assert node.peers[peer_id]["revoked"] is True


def test_discovered_origin_rejects_non_public_or_ambiguous_urls():
    for value in (
        "http://peer.example.org", "https://user:pass@peer.example.org",
        "https://peer.example.org:8443", "https://peer.example.org/path",
        "https://127.0.0.1",
    ):
        try:
            autonomous._origin(value)
        except ValueError:
            continue
        raise AssertionError("unsafe origin accepted: " + value)


def test_registry_write_is_atomic_private_and_rejects_symlink_target(tmp_path):
    import os
    import pytest
    from omega.federation_autonomous import _write_registry

    target = tmp_path / "registry.json"
    _write_registry(target, {"schema": 1, "candidates": {}})
    assert json.loads(target.read_text()) == {"schema": 1, "candidates": {}}
    if os.name == "posix":
        assert target.stat().st_mode & 0o777 == 0o600

    outside = tmp_path / "outside.json"
    outside.write_text("preserve-me", encoding="utf-8")
    link = tmp_path / "linked-registry.json"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    with pytest.raises(RuntimeError, match="REGISTRY_SYMLINK_REFUSED"):
        _write_registry(link, {"schema": 1, "candidates": {"bad": {}}})
    assert outside.read_text(encoding="utf-8") == "preserve-me"


def test_registry_write_rejects_symlink_parent(tmp_path):
    import pytest
    from omega.federation_autonomous import _write_registry

    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "linked-dir"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    with pytest.raises(RuntimeError, match="REGISTRY_PARENT_REFUSED"):
        _write_registry(link / "registry.json", {"schema": 1, "candidates": {}})
    assert list(outside.iterdir()) == []
