"""Utility for signing federation proposals using Ed25519.

This module complements :pymod:`omega.federation_signature` which provides
verification of signatures.  It offers a single public function
:func:`sign_proposal` that takes a proposal dictionary and an Ed25519 private
key (bytes) and returns a new dictionary containing the original proposal
payload plus a hex‑encoded ``signature`` field.

The signing process:

1. Serialize the proposal deterministically with ``json.dumps`` using sorted
   keys and the most compact separators.  This guarantees that two identical
   proposals produce the same byte representation regardless of Python dict
   ordering.
2. Compute the Ed25519 signature over the UTF‑8 encoded JSON string.
3. Attach the signature (hex string) to a shallow copy of the proposal and
   return it.

The function raises :class:`ValueError` if the input already contains a
``signature`` field, if the private key length is incorrect, or if any other
unexpected condition occurs.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Dict

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

__all__ = ["sign_proposal"]


def _serialize_proposal(proposal: Dict[str, Any]) -> bytes:
    """Serialize *proposal* to a deterministic UTF‑8 JSON payload.

    The function sorts keys and removes any whitespace that is not required
    for JSON validity.  It is deliberately isolated to make unit‑testing
    straightforward.
    """
    # ``separators`` removes the default spaces after commas and colons.
    json_str = json.dumps(proposal, sort_keys=True, separators=(",", ":"))
    return json_str.encode("utf-8")


def sign_proposal(proposal: Dict[str, Any], private_key_bytes: bytes) -> Dict[str, Any]:
    """Return a signed copy of *proposal*.

    Parameters
    ----------
    proposal:
        The dictionary representing the federation proposal to be signed.
        It **must not** contain a ``"signature"`` key; the function will raise
        :class:`ValueError` if such a key is present.
    private_key_bytes:
        A 32‑byte Ed25519 private key.  The function constructs an
        :class:`Ed25519PrivateKey` instance from these raw bytes.

    Returns
    -------
    dict
        A shallow copy of *proposal* enriched with a ``"signature"`` entry that
        holds the hexadecimal representation of the Ed25519 signature.

    Raises
    ------
    ValueError
        If the proposal already includes a ``"signature"`` field or if the
        private key does not have the required length.
    """
    if "signature" in proposal:
        raise ValueError("Proposal already contains a 'signature' field.")

    if len(private_key_bytes) != 32:
        raise ValueError("Ed25519 private key must be exactly 32 bytes.")

    # Serialize the proposal deterministically.
    payload = _serialize_proposal(proposal)

    # Create a private key object and sign the payload.
    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    signature_bytes = private_key.sign(payload)
    signature_hex = signature_bytes.hex()

    # Return a new dict with the signature attached.
    signed_proposal = copy.copy(proposal)
    signed_proposal["signature"] = signature_hex
    return signed_proposal
