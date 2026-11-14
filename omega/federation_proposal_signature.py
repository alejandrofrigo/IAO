"""Utility for verifying Ed25519 signatures on federation proposals.

This module provides a single public function :func:`verify_proposal_signature` that
checks the cryptographic signature attached to a proposal dictionary.  The
expected structure of a proposal is::

    {
        "id": "<unique-id>",
        "payload": { ... },
        "signature": "<hex-encoded ed25519 signature>",
        "signer_public_key": "<hex-encoded ed25519 public key>"
    }

Only the ``payload`` (canonical JSON representation) is signed.  The function
serialises the payload with ``json.dumps(..., separators=(',', ':'), sort_keys=True)``
to obtain a deterministic byte sequence, then verifies the signature using the
provided public key.

The implementation relies on the *cryptography* library, which is part of the
standard runtime for the IAO platform.  All errors are caught and result in a
``False`` return value, allowing callers to decide how to handle unauthenticated
proposals.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

_logger = logging.getLogger(__name__)


def _canonical_json(data: Any) -> bytes:
    """Return a deterministic JSON representation of *data* as UTF‑8 bytes.

    The function uses ``sort_keys=True`` and the most compact separators to
    guarantee that the same logical payload always yields the same byte string.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_proposal_signature(proposal: Dict[str, Any]) -> bool:
    """Verify the Ed25519 signature of a federation proposal.

    Parameters
    ----------
    proposal: dict
        A dictionary containing at least the keys ``payload``, ``signature``
        and ``signer_public_key``.  ``signature`` and ``signer_public_key`` must
        be hex‑encoded strings.

    Returns
    -------
    bool
        ``True`` if the signature is valid, ``False`` otherwise.
    """
    try:
        payload = proposal["payload"]
        signature_hex = proposal["signature"]
        pubkey_hex = proposal["signer_public_key"]
    except KeyError as exc:
        _logger.error("Proposal missing required field %s", exc.args[0])
        return False

    try:
        signature = bytes.fromhex(signature_hex)
        public_key_bytes = bytes.fromhex(pubkey_hex)
    except ValueError as exc:
        _logger.error("Invalid hex encoding in proposal: %s", exc)
        return False

    try:
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    except ValueError as exc:
        _logger.error("Invalid Ed25519 public key bytes: %s", exc)
        return False

    message = _canonical_json(payload)
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        _logger.warning("Ed25519 signature verification failed for proposal %s", proposal.get("id"))
        return False
    except Exception as exc:  # pragma: no cover – defensive programming
        _logger.exception("Unexpected error during signature verification: %s", exc)
        return False
