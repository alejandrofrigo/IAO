from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from omega.audit import canonical_json
from omega.federation import node_id_of
from omega.p2p_presence import verify_presence


def signed_presence(*, now=1_800_000_000, nonce="a" * 64):
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    body = {
        "protocol": "iao-p2p-presence",
        "version": 1,
        "node_id": node_id_of(public),
        "public_key": public.hex(),
        "libp2p_peer_id": "Qm" + "a" * 44,
        "onion_endpoint": None,
        "nonce": nonce,
        "issued_at": now - 10,
        "expires_at": now + 300,
    }
    return {**body, "signature": base64.b64encode(
        key.sign(canonical_json(body))
    ).decode("ascii")}


def test_signed_presence_verifies_but_does_not_enroll_or_bind_transport():
    nonce = "b" * 64
    result = verify_presence(signed_presence(nonce=nonce), expected_nonce=nonce,
                             now=1_800_000_000)
    assert result["ok"] is True
    assert result["identity_state"] == "SIGNED_IAO_KEY_VERIFIED"
    assert result["transport_binding"] == "SIGNED_ASSERTION_ONLY"
    assert result["connectivity_verified"] is False
    assert result["participation_state"] == "CANDIDATE_ONLY"
    assert result["granted_capabilities"] == []
    assert result["remote_code_execution"] is False
    assert result["control_authority"] is False
    assert result["enrollment_allowed"] is False


def test_signed_presence_rejects_replayed_or_wrong_nonce():
    result = verify_presence(signed_presence(), expected_nonce="c" * 64,
                             now=1_800_000_000)
    assert result == {
        "ok": False, "error": "PRESENCE_NONCE_MISMATCH",
        "enrollment_allowed": False,
    }


def test_signed_presence_rejects_modified_claim():
    document = signed_presence()
    document["libp2p_peer_id"] = "Qm" + "z" * 44
    result = verify_presence(document, expected_nonce="a" * 64,
                             now=1_800_000_000)
    assert result["ok"] is False
    assert result["error"] == "BAD_PRESENCE_SIGNATURE"


def test_signed_presence_rejects_expired_lease():
    document = signed_presence(now=1_800_000_000)
    result = verify_presence(document, expected_nonce="a" * 64,
                             now=1_800_000_500)
    assert result["ok"] is False
    assert result["error"] == "PRESENCE_EXPIRED_OR_INVALID_LEASE"


def test_signed_presence_rejects_key_node_id_mismatch():
    document = signed_presence()
    document["node_id"] = "0" * 16
    result = verify_presence(document, expected_nonce="a" * 64,
                             now=1_800_000_000)
    assert result["ok"] is False
    assert result["error"] == "PRESENCE_NODE_ID_KEY_MISMATCH"
