"""Cryptographic verification for externally discovered IAO P2P presence.

A valid signature proves control of the advertised IAO signing key and binds
its claims to a fresh challenge. It does not prove transport reachability,
libp2p Peer ID ownership, operator consent, or permission to execute tasks.
"""
from __future__ import annotations

import base64
import math
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from omega.audit import canonical_json
from omega.federation import node_id_of
from omega.federation_transport import FederationTransportError, _parse_onion_url

PROTOCOL = "iao-p2p-presence"
VERSION = 1
MAX_LEASE_SECONDS = 3600
MAX_CLOCK_SKEW_SECONDS = 60
_NODE_ID = re.compile(r"^[0-9a-f]{16}$")
_NONCE = re.compile(r"^[0-9a-f]{64}$")
_PEER_ID = re.compile(r"^[A-Za-z0-9]{20,120}$")


def verify_presence(
    document: Any,
    *,
    expected_nonce: str,
    now: float,
    max_lease_seconds: int = MAX_LEASE_SECONDS,
) -> dict[str, Any]:
    """Verify a nonce-bound Ed25519 presence claim; fail closed on all errors."""
    def fail(code: str) -> dict[str, Any]:
        return {"ok": False, "error": code, "enrollment_allowed": False}

    if not isinstance(document, dict):
        return fail("INVALID_PRESENCE_DOCUMENT")
    if document.get("protocol") != PROTOCOL or document.get("version") != VERSION:
        return fail("UNSUPPORTED_PRESENCE_PROTOCOL")

    public_hex = document.get("public_key")
    node_id = document.get("node_id")
    nonce = document.get("nonce")
    signature = document.get("signature")
    if (not isinstance(public_hex, str) or len(public_hex) != 64
            or not re.fullmatch(r"[0-9a-f]{64}", public_hex)
            or not isinstance(node_id, str) or not _NODE_ID.fullmatch(node_id)
            or not isinstance(nonce, str) or not _NONCE.fullmatch(nonce)
            or not isinstance(signature, str) or len(signature) > 128):
        return fail("INVALID_PRESENCE_IDENTITY")
    if nonce != expected_nonce or not _NONCE.fullmatch(expected_nonce):
        return fail("PRESENCE_NONCE_MISMATCH")

    try:
        public_raw = bytes.fromhex(public_hex)
        if node_id_of(public_raw) != node_id:
            return fail("PRESENCE_NODE_ID_KEY_MISMATCH")
        signature_raw = base64.b64decode(signature, validate=True)
        if len(signature_raw) != 64:
            return fail("INVALID_PRESENCE_SIGNATURE")
        body = {key: value for key, value in document.items() if key != "signature"}
        Ed25519PublicKey.from_public_bytes(public_raw).verify(
            signature_raw, canonical_json(body)
        )
    except (InvalidSignature, ValueError, TypeError):
        return fail("BAD_PRESENCE_SIGNATURE")

    issued_at, expires_at = document.get("issued_at"), document.get("expires_at")
    if any(isinstance(value, bool) or not isinstance(value, (int, float))
           or not math.isfinite(float(value))
           for value in (issued_at, expires_at, now)):
        return fail("INVALID_PRESENCE_TIME")
    issued_at, expires_at, now = float(issued_at), float(expires_at), float(now)
    if (expires_at <= issued_at
            or expires_at - issued_at > max_lease_seconds
            or issued_at > now + MAX_CLOCK_SKEW_SECONDS
            or now > expires_at
            or now - issued_at > max_lease_seconds + MAX_CLOCK_SKEW_SECONDS):
        return fail("PRESENCE_EXPIRED_OR_INVALID_LEASE")

    peer_id = document.get("libp2p_peer_id")
    onion_endpoint = document.get("onion_endpoint")
    if peer_id is not None and (
        not isinstance(peer_id, str) or not _PEER_ID.fullmatch(peer_id)
    ):
        return fail("INVALID_LIBP2P_PEER_ID_CLAIM")
    if onion_endpoint is not None:
        if not isinstance(onion_endpoint, str) or len(onion_endpoint) > 512:
            return fail("INVALID_ONION_ENDPOINT_CLAIM")
        try:
            _parse_onion_url(onion_endpoint)
        except (FederationTransportError, TypeError, ValueError):
            return fail("INVALID_ONION_ENDPOINT_CLAIM")
    if peer_id is None and onion_endpoint is None:
        return fail("PRESENCE_HAS_NO_EXTERNAL_ENDPOINT")

    return {
        "ok": True,
        "node_id": node_id,
        "public_key": public_hex,
        "libp2p_peer_id": peer_id,
        "onion_endpoint": onion_endpoint,
        "identity_state": "SIGNED_IAO_KEY_VERIFIED",
        "transport_binding": "SIGNED_ASSERTION_ONLY",
        "connectivity_verified": False,
        "participation_state": "CANDIDATE_ONLY",
        "granted_capabilities": [],
        "remote_code_execution": False,
        "control_authority": False,
        "enrollment_allowed": False,
        "lease_expires_at": expires_at,
    }
