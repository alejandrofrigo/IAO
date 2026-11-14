'''omega/federation_process_proposal.py

High‑level orchestration for handling a stored federation proposal.

The function ``process_federation_proposal`` performs the following steps
in a safe, deterministic order:

1. Retrieve the proposal from the persistent proposal store.
2. Verify the Ed25519 signature of the proposal.
3. Determine the current lifecycle status (active, expired, revoked).
4. If the proposal is active and signature‑valid, invoke the assimilation
   routine to apply the candidate into the local IAO instance.
5. Return a concise dictionary describing the outcome.

All optional sub‑modules are imported via the package‑wide ``_safe_import``
helper defined in ``omega.__init__`` so that the function degrades gracefully
if a particular capability is unavailable (e.g., during partial deployments
or in constrained test environments).
''' 

from __future__ import annotations

from typing import Any, Dict, Optional

# Re‑use the tolerant import helper from the package root.
# The import is performed lazily to avoid circular‑import issues.
from omega import _safe_import


def _load_store() -> Any:
    """Return the proposal‑store module or raise a clear error.

    The store module is expected to provide ``get_proposal(proposal_id)``
    which returns a dict‑like object representing the signed proposal.
    """
    store = _safe_import("omega.federation_proposal_store")
    if store is None:
        raise RuntimeError(
            "Federation proposal store is unavailable – cannot process proposals."
        )
    return store


def _verify_signature(proposal: Any) -> bool:
    """Verify the Ed25519 signature of *proposal*.

    Returns ``True`` if verification succeeds, ``False`` otherwise. If the
    verifier utility is missing, the function conservatively returns ``False``
    to avoid processing potentially tampered data.
    """
    verifier = _safe_import(
        "omega.federation_proposal_verifier", "verify_federation_proposal_signature"
    )
    if verifier is None:
        return False
    try:
        return bool(verifier(proposal))
    except Exception:
        # Any unexpected exception is treated as a verification failure.
        return False


def _current_status(proposal_id: str) -> Optional[str]:
    """Query the lifecycle status of *proposal_id*.

    Expected return values are ``"active"``, ``"expired"``, ``"revoked"`` or
    ``None`` if the status utility is absent.
    """
    status_fn = _safe_import("omega.federation_proposal_status", "get_proposal_status")
    if status_fn is None:
        return None
    try:
        return status_fn(proposal_id)
    except Exception:
        return None


def _assimilate(proposal: Any) -> Any:
    """Run the assimilation routine for a valid *proposal*.

    The assimilation function is expected to return a result object (often a
    dict) describing what was applied. If the assimilation module is missing,
    the function returns ``None``.
    """
    assimilator = _safe_import("omega.federation_assimilation", "assimilate_proposal")
    if assimilator is None:
        return None
    try:
        return assimilator(proposal)
    except Exception as exc:
        # Propagate the exception so the caller can see the failure reason.
        raise RuntimeError(f"Assimilation failed: {exc}") from exc


def process_federation_proposal(proposal_id: str) -> Dict[str, Any]:
    """Process a stored federation proposal.

    Parameters
    ----------
    proposal_id: str
        The unique identifier (e.g., hash or UUID) of the proposal to be
        processed.

    Returns
    -------
    dict
        A serialisable outcome structure with at least a ``"status"`` key.
        Possible statuses:
        * ``"not_found"`` – the proposal does not exist in the store.
        * ``"invalid_signature"`` – signature verification failed.
        * ``"inactive"`` – the proposal is not active (expired or revoked);
          the reason is provided under ``"reason"``.
        * ``"assimilated"`` – the proposal was successfully assimilated; the
          assimilation result is returned under ``"result"``.
        * ``"error"`` – an unexpected internal error occurred; details are in
          ``"error"``.
    """
    try:
        store = _load_store()
        proposal = store.get_proposal(proposal_id)  # type: ignore[attr-defined]
        if proposal is None:
            return {"status": "not_found"}

        # Step 2 – signature verification.
        if not _verify_signature(proposal):
            return {"status": "invalid_signature"}

        # Step 3 – lifecycle status.
        status = _current_status(proposal_id)
        if status != "active":
            # Treat missing status function as non‑active to stay safe.
            reason = status if status is not None else "unknown"
            return {"status": "inactive", "reason": reason}

        # Step 4 – assimilation.
        result = _assimilate(proposal)
        if result is None:
            # Assimilation capability missing – report as error.
            return {"status": "error", "error": "assimilation_unavailable"}

        return {"status": "assimilated", "result": result}

    except Exception as exc:  # pragma: no cover – defensive catch‑all.
        return {"status": "error", "error": str(exc)}
