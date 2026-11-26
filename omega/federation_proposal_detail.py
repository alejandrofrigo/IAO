"""Utilities for detailed inspection of stored federation proposals.

This module offers a single public function ``get_proposal_detail`` that
aggregates the raw proposal payload, cryptographic verification status and
lifecycle state (active, revoked, expired, unknown). It is built on top of the
existing federation proposal store, verifier and status helpers, providing a
deterministic, testable API for operators and automated tests.
"""

from __future__ import annotations

from typing import Any, Dict

# The implementation deliberately uses safe imports with graceful fallback so
# that it works regardless of the internal storage implementation details.


def _load_proposal(proposal_id: str) -> Dict[str, Any]:
    """Retrieve a stored proposal by *proposal_id*.

    The function first attempts to use the dedicated proposal‑store API. If that
    fails (e.g., the store module is unavailable or its API changed), it falls
    back to the generic ``omega.store`` helpers. A ``KeyError`` is raised when the
    proposal cannot be found.
    """
    # Primary path – use the dedicated proposal‑store if it exists.
    try:
        from omega.federation_proposal_store import get_proposal_store
        store = get_proposal_store()
        proposal = store.get(proposal_id)  # type: ignore[attr-defined]
        if proposal is not None:
            return proposal
    except Exception:
        # Either the module does not exist or the API is different; ignore and
        # attempt the fallback.
        pass

    # Fallback path – generic key‑value store used elsewhere in the code base.
    try:
        from omega.store import get_federation_proposal
        proposal = get_federation_proposal(proposal_id)
        if proposal is not None:
            return proposal
    except Exception as exc:
        raise KeyError(f"Federation proposal '{proposal_id}' not found") from exc

    # If both attempts return ``None`` raise an explicit error.
    raise KeyError(f"Federation proposal '{proposal_id}' not found")


def _verify_signature(proposal: Dict[str, Any]) -> bool:
    """Return ``True`` if the proposal's Ed25519 signature is valid.

    The verification logic lives in ``omega.federation_proposal_verifier``.
    Any exception is interpreted as a verification failure and results in
    ``False``.
    """
    try:
        from omega.federation_proposal_verifier import (
            verify_federation_proposal_signature,
        )
        return bool(verify_federation_proposal_signature(proposal))
    except Exception:
        return False


def _determine_status(proposal_id: str) -> str:
    """Retrieve the lifecycle status of *proposal_id*.

    Expected return values are ``"active"``, ``"revoked"``, ``"expired"`` or
    ``"unknown"`` as defined by ``omega.federation_proposal_status``.
    """
    try:
        from omega.federation_proposal_status import get_proposal_status
        return str(get_proposal_status(proposal_id))
    except Exception:
        return "unknown"


def get_proposal_detail(proposal_id: str) -> Dict[str, Any]:
    """Return a comprehensive description of a stored federation proposal.

    The returned dictionary contains:

    * ``id`` – the identifier used to store the proposal.
    * ``proposal`` – the raw proposal payload as persisted in the store.
    * ``signature_verified`` – boolean indicating whether the Ed25519 signature
      on the proposal is cryptographically valid.
    * ``status`` – lifecycle state (active, revoked, expired, unknown).

    Raises
    ------
    KeyError
        If the proposal does not exist in any recognised store.
    """
    proposal = _load_proposal(proposal_id)
    signature_verified = _verify_signature(proposal)
    status = _determine_status(proposal_id)

    return {
        "id": proposal_id,
        "proposal": proposal,
        "signature_verified": signature_verified,
        "status": status,
    }

# Export the primary utility as part of the module's public API.
__all__ = ["get_proposal_detail"]
