'''omega/federation_proposal_crypto.py

Utility functions for creating, signing, and verifying federation proposals.

The IAO core uses Ed25519 keys for identity and authorization.  These helpers
operate on plain ``dict`` objects representing a proposal, add a deterministic
JSON canonical representation, and embed a base64‑encoded signature under the
``"signature"`` field.

The module deliberately avoids any external network I/O and depends only on
the widely‑available ``pynacl`` library (available in the execution environment).
All functions raise clear, typed exceptions so that callers – including the
high‑level ``omega.submit_federation_candidate`` entrypoint – can react to
cryptographic failures without crashing the process.
''' 

from __future__ import annotations

import json
import base64
from typing import Any, Dict

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ProposalCryptoError(Exception):
    """Base class for errors raised by this module."""

class InvalidProposalError(ProposalCryptoError):
    """Raised when a proposal payload is malformed or missing required fields."""

class SignatureVerificationError(ProposalCryptoError):
    """Raised when a proposal's signature cannot be verified with the supplied key."""

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _canonical_json(data: Dict[str, Any]) -> bytes:
    """Return a deterministic JSON representation of *data*.

    The JSON is encoded as UTF‑8 and sorted by keys to guarantee that the same
    dictionary always yields the same byte sequence, which is essential for
    reproducible signatures.
    """
    # ``separators`` removes the space after commas/colons, producing a compact
    # representation while still being valid JSON.
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def sign_proposal(proposal: Dict[str, Any], private_key_b64: str) -> Dict[str, Any]:
    """Sign *proposal* with the Ed25519 *private_key* (base64 encoded).

    The function returns a **new** dictionary that contains every original field
    plus a ``"signature"`` entry.  The original ``proposal`` dict is left
    untouched to avoid accidental mutation.

    Parameters
    ----------
    proposal:
        Arbitrary mapping representing the proposal payload.  It must be JSON‑
        serialisable.
    private_key_b64:
        Base64‑encoded 32‑byte Ed25519 private key.

    Returns
    -------
    dict
        A copy of ``proposal`` with an added ``"signature"`` field containing a
        base64‑encoded signature.
    """
    if not isinstance(proposal, dict):
        raise InvalidProposalError("Proposal must be a dictionary")

    # Ensure deterministic ordering before signing.
    payload_bytes = _canonical_json(proposal)

    try:
        signing_key = SigningKey(base64.b64decode(private_key_b64))
    except Exception as exc:
        raise InvalidProposalError("Unable to decode private key") from exc

    signature = signing_key.sign(payload_bytes).signature
    signed_proposal = dict(proposal)  # shallow copy
    signed_proposal["signature"] = base64.b64encode(signature).decode("ascii")
    return signed_proposal


def verify_proposal_signature(signed_proposal: Dict[str, Any], public_key_b64: str) -> Dict[str, Any]:
    """Verify the ``"signature"`` field of *signed_proposal* using *public_key*.

    If verification succeeds the function returns a **new** dictionary identical
    to the input but **without** the ``"signature"`` field, representing the
    original payload.  If verification fails a :class:`SignatureVerificationError`
    is raised.

    Parameters
    ----------
    signed_proposal:
        Dictionary that must contain a ``"signature"`` entry produced by
        :func:`sign_proposal`.
    public_key_b64:
        Base64‑encoded 32‑byte Ed25519 public key corresponding to the private
        key used for signing.
    """
    if not isinstance(signed_proposal, dict):
        raise InvalidProposalError("Signed proposal must be a dictionary")
    if "signature" not in signed_proposal:
        raise InvalidProposalError("Missing 'signature' field in proposal")

    signature_b64 = signed_proposal["signature"]
    try:
        signature_bytes = base64.b64decode(signature_b64)
        public_key = VerifyKey(base64.b64decode(public_key_b64))
    except Exception as exc:
        raise InvalidProposalError("Unable to decode signature or public key") from exc

    # Re‑create the payload without the signature field for verification.
    payload = {k: v for k, v in signed_proposal.items() if k != "signature"}
    payload_bytes = _canonical_json(payload)

    try:
        public_key.verify(payload_bytes, signature_bytes)
    except BadSignatureError as exc:
        raise SignatureVerificationError("Signature verification failed") from exc

    # Return a clean copy of the original payload.
    return payload


def extract_proposal_fields(signed_proposal: Dict[str, Any], fields: list[str]) -> Dict[str, Any]:
    """Convenience helper to pull selected *fields* from a verified proposal.

    The function first verifies the signature (using the same public key supplied
    to :func:`verify_proposal_signature`) and then returns a dictionary containing
    only the requested keys.  Missing keys are omitted from the result.
    """
    raise NotImplementedError("This helper is intentionally left for higher‑level code to implement specific extraction logic.")

# The module's public interface is deliberately small; higher‑level orchestration
# code can import ``sign_proposal`` and ``verify_proposal_signature`` directly.
