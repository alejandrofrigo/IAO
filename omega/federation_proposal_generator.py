# -*- coding: utf-8 -*-
"""Utility for creating signed federation proposals.

This module provides a deterministic, offline function to assemble a federation
proposal (a descriptor dict) and attach an Ed25519 signature.  It is intended
for use in tests, tooling, and operator workflows where a signed proposal must
be generated without performing any network operations.

The implementation relies on the ``nacl`` (PyNaCl) library, which is already a
dependency of the IAO codebase for Ed25519 verification.  If the library is not
available, an informative ``ImportError`` is raised.
"""

from __future__ import annotations

import json
from typing import Any, Dict

try:
    from nacl.signing import SigningKey
    from nacl.encoding import HexEncoder
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "PyNaCl is required for federation proposal signing. Install it via "
        "'pip install pynacl'"
    ) from exc

__all__ = ["generate_signed_proposal"]


def _canonical_json(data: Any) -> bytes:
    """Serialize *data* to a canonical JSON byte string.

    The serialization uses ``sort_keys=True`` and the most compact separators
    to guarantee that the same logical descriptor always yields the same byte
    representation, which is essential for deterministic signatures.
    """
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode("utf-8")


def generate_signed_proposal(
    descriptor: Dict[str, Any],
    signing_key_hex: str,
) -> Dict[str, Any]:
    """Create a signed federation proposal.

    Parameters
    ----------
    descriptor:
        The proposal payload as a JSON‑compatible dictionary.  The function does
        not modify the input dictionary.
    signing_key_hex:
        Ed25519 private signing key encoded as a 64‑character hexadecimal
        string (32‑byte key).  The corresponding public key can be derived from
        this value.

    Returns
    -------
    dict
        A new dictionary with two top‑level fields:
        ``"descriptor"`` – the original descriptor (deep‑copied), and
        ``"signature"`` – the hexadecimal Ed25519 signature of the canonical JSON
        representation of the descriptor.
    """
    if not isinstance(descriptor, dict):
        raise TypeError("descriptor must be a dict")

    # Prepare the canonical byte representation
    payload_bytes = _canonical_json(descriptor)

    # Create the signing key from the provided hex string
    signing_key = SigningKey(signing_key_hex, encoder=HexEncoder)

    # Sign the payload; ``sign`` returns the concatenation of signature+message.
    signed = signing_key.sign(payload_bytes)
    signature_hex = signed.signature.hex()

    # Return a new proposal structure without mutating the input
    return {
        "descriptor": json.loads(json.dumps(descriptor)),  # deep copy via JSON round‑trip
        "signature": signature_hex,
        "signing_key": signing_key_hex,  # optional: helpful for debugging/tracing
    }
