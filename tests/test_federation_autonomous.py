from __future__ import annotations

import base64
import json
import time

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
        if url.endswith("/fed/v1/publication"):
            return publication
        if url.endswith("/fed/v1/identity"):
            return identity
        if url.endswith("/fed/v1/contract"):
            return contract
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



def test_public_candidate_origin_accepts_native_message_endpoint_only():
    from tools.iao_federation_autonomous import _public_candidate_origin

    assert _public_candidate_origin("https://peer.example.org") == "https://peer.example.org"
    assert _public_candidate_origin(
        "https://peer.example.org/fed/v1/message"
    ) == "https://peer.example.org"
    assert _public_candidate_origin(
        "https://peer.example.org/"
    ) == "https://peer.example.org"

    for value in (
        "http://peer.example.org/fed/v1/message",
        "https://peer.example.org/fed/v1/identity",
        "https://peer.example.org/fed/v1/message?next=https://127.0.0.1",
        "https://user:pass@peer.example.org/fed/v1/message",
        "https://127.0.0.1/fed/v1/message",
        "https://peer.example.org:8443/fed/v1/message",
    ):
        assert _public_candidate_origin(value) is None
