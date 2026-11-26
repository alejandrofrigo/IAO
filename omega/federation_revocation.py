"""Utilities for revoking a stored federation proposal.

This module provides a high‑level, deterministic function that:

1. Retrieves the proposal from the persistent store.
2. Verifies the Ed25519 signature to ensure authenticity.
3. Marks the proposal as revoked using the internal revocation engine.
4. Returns ``True`` on success or ``False`` on any failure (missing
   proposal, signature mismatch, internal error).

All operations are performed using the existing internal components:
* :pyclass:`omega.federation_proposal_store.ProposalStore`
* :pyfunc:`omega.federation_proposal_verifier.verify_federation_proposal_signature`
* :pyfunc:`omega.federation_assimilation_revocation.revoke_proposal_by_id`

The function raises no exceptions; failures are signaled via the boolean
return value, making it safe for use in automated workflows and tests.
"""

from __future__ import annotations

from typing import Any

# Helper to perform lazy, safe imports without breaking package import if
# optional dependencies are unavailable.
def _safe_import(module_path: str) -> Any:
    try:
        module = __import__(module_path, fromlist=["*"])
        return module
    except Exception:
        return None

# Import internal components lazily.
_ProposalStore = _safe_import("omega.federation_proposal_store")
_VerifySignature = _safe_import("omega.federation_proposal_verifier")
_RevocationEngine = _safe_import("omega.federation_assimilation_revocation")


def revoke_federation_proposal(proposal_id: str) -> bool:
    """Revoke a stored federation proposal.

    Parameters
    ----------
    proposal_id: str
        The unique identifier of the proposal to revoke.

    Returns
    -------
    bool
        ``True`` if the proposal existed, its signature was valid, and it
        was successfully marked as revoked; ``False`` otherwise.
    """
    if not all([_ProposalStore, _VerifySignature, _RevocationEngine]):
        # Core components missing – cannot perform revocation safely.
        return False

    store_cls = getattr(_ProposalStore, "ProposalStore", None)
    if store_cls is None:
        return False
    store = store_cls.get_instance()

    # Retrieve the raw proposal data (assumed to be a dict with at least
    # ``payload`` and ``signature`` fields).
    proposal = store.get_proposal(proposal_id)
    if proposal is None:
        return False

    # Verify the Ed25519 signature before revoking.
    verify_fn = getattr(_VerifySignature, "verify_federation_proposal_signature", None)
    if verify_fn is None or not verify_fn(proposal):
        return False

    # Perform the revocation using the internal revocation helper.
    revoke_fn = getattr(_RevocationEngine, "revoke_proposal_by_id", None)
    if revoke_fn is None:
        return False
    try:
        revoke_fn(proposal_id)
    except Exception:
        return False

    return True
