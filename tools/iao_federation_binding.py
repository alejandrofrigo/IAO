#!/usr/bin/env python3
"""IAO: bind a verified Ed25519 identity to an operator-expected node ID."""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from omega.federation import verify_identity_challenge  # noqa: E402

NODE_ID_RE = re.compile(r"^[0-9a-f]{16}$")


def verify_binding(
    identity: dict,
    response: dict,
    *,
    expected_node_id: str,
    requester_id: str,
    nonce: str,
    request_ts: float,
    now: float,
    skew: float = 60.0,
) -> dict:
    if not isinstance(expected_node_id, str) or not NODE_ID_RE.fullmatch(
        expected_node_id
    ):
        return {"ok": False, "error": "EXPECTED_NODE_ID_REQUIRED"}

    result = verify_identity_challenge(
        identity,
        response,
        requester_id=requester_id,
        nonce=nonce,
        request_ts=request_ts,
        now=now,
        skew=skew,
    )
    if not result.get("ok"):
        return result

    actual = result.get("peer_id")
    if actual != expected_node_id:
        return {
            "ok": False,
            "error": "EXPECTED_IDENTITY_MISMATCH",
            "expected_node_id": expected_node_id,
            "actual_node_id": actual,
        }

    return {
        "ok": True,
        "verified": True,
        "peer_id": actual,
        "identity_bound_to_expected_id": True,
        "enrollment_performed": False,
        "authorization_granted": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Comprueba la vinculación criptográfica de una identidad IAO."
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if not args.self_test:
        parser.error("Por ahora solo está disponible --self-test")

    from datetime import datetime, timezone

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives import serialization
        import hashlib
        import secrets

        key = Ed25519PrivateKey.generate()
        public_raw = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        node_id = hashlib.sha256(public_raw).hexdigest()[:16]

        # Prueba con un nodo real de protocolo, usando una clave efímera.
        from omega.federation import _sign

        requester_id = secrets.token_hex(8)
        nonce = secrets.token_hex(32)
        now = datetime.now(timezone.utc).timestamp()

        identity = {
            "protocol": "iao-federation",
            "version": 1,
            "node_id": node_id,
            "public_key": public_raw.hex(),
        }
        envelope = {
            "v": 1,
            "protocol": "iao-federation",
            "from": node_id,
            "to": requester_id,
            "nonce": nonce,
            "request_ts": float(now),
            "ts": float(now),
        }
        response = _sign(key, envelope)

        valid = verify_binding(
            identity,
            response,
            expected_node_id=node_id,
            requester_id=requester_id,
            nonce=nonce,
            request_ts=now,
            now=now,
        )
        assert valid["ok"] is True

        mismatch = verify_binding(
            identity,
            response,
            expected_node_id="0000000000000000",
            requester_id=requester_id,
            nonce=nonce,
            request_ts=now,
            now=now,
        )
        assert mismatch["error"] == "EXPECTED_IDENTITY_MISMATCH"

        missing = verify_binding(
            identity,
            response,
            expected_node_id="",
            requester_id=requester_id,
            nonce=nonce,
            request_ts=now,
            now=now,
        )
        assert missing["error"] == "EXPECTED_NODE_ID_REQUIRED"

        print("VALID_SIGNATURE_AND_EXPECTED_ID=PASS")
        print("IDENTITY_MISMATCH_REJECTED=PASS")
        print("MISSING_EXPECTED_ID_REJECTED=PASS")
        print("ENROLLMENT_PERFORMED=False")
        print("AUTHORIZATION_GRANTED=False")
        return 0

    except Exception as exc:
        print("SELF_TEST=FAIL")
        print("ERROR_CLASS=" + type(exc).__name__)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
