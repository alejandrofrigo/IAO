"""Verification utility for federation proposals signed with Ed25519.

The complementary counterpart to ``omega.federation_proposal_builder``.  It
extracts the signature and public key from a proposal, re‑creates the canonical
payload (candidate + timestamp) and verifies the authenticity of the signature.
If verification succeeds, the function returns ``True``; otherwise it returns
``False``.
"""

import base64
import json
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

__all__ = ["verify_proposal_signature"]


def _canonical_payload(candidate: Mapping[str, Any], timestamp: int) -> bytes:
    """Re‑create the exact bytes that were signed by the builder.

    This must match the algorithm used in ``federation_proposal_builder``.
    """
    payload_dict = {
        "candidate": candidate,
        "timestamp": timestamp,
    }
    return json.dumps(payload_dict, separators=(',', ':'), sort_keys=True).encode("utf-8")


def verify_proposal_signature(proposal: Mapping[str, Any]) -> bool:
    """Verify the Ed25519 signature of a federation proposal.

    Parameters
    ----------
    proposal: Mapping[str, Any]
        The proposal dictionary produced by ``build_and_sign_proposal``.

    Returns
    -------
    bool
        ``True`` if the signature is valid and the payload can be reconstructed;
        ``False`` otherwise.
    """
    try:
        candidate = proposal["candidate"]
        timestamp = proposal["timestamp"]
        signature_b64 = proposal["signature"]
        public_key_b64 = proposal["public_key"]
    except KeyError:
        return False

    try:
        signature = base64.b64decode(signature_b64)
        public_bytes = base64.b64decode(public_key_b64)
        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
    except Exception:
        return False

    payload = _canonical_payload(candidate, timestamp)
    try:
        public_key.verify(signature, payload)
        return True
    except Exception:
        return False
