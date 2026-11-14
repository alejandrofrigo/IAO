"""Revocation‑aware federation assimilation.

This module provides a safe entry‑point that checks whether a candidate has been
revoked before forwarding the proposal to the standard assimilation routine.
It logs the attempt via the audit log facility and raises a clear exception if
revocation is detected.

Usage example
-------------
>>> from omega.federation_assimilation_revocation import assimilate_candidate
>>> assimilate_candidate(candidate_id, signed_proposal)

The function returns the result of ``omega.federation_assimilation.assimilate``
when the candidate is not revoked.
"""

from __future__ import annotations

from typing import Any

# Import the core assimilation logic (may raise ImportError if optional).
from . import federation_assimilation as _assimilation
from . import federation_revocation as _revocation
from . import federation_audit_log as _audit_log

__all__ = ["RevokedCandidateError", "assimilate_candidate"]


class RevokedCandidateError(RuntimeError):
    """Raised when an attempt is made to assimilate a revoked candidate."""

    def __init__(self, candidate_id: str):
        super().__init__(f"Candidate '{candidate_id}' has been revoked and cannot be assimilated.")
        self.candidate_id = candidate_id


def _log_attempt(candidate_id: str, success: bool, detail: str | None = None) -> None:
    """Record an assimilation attempt in the audit log.

    Parameters
    ----------
    candidate_id: str
        Identifier of the candidate being processed.
    success: bool
        Whether the assimilation succeeded.
    detail: str | None
        Optional additional information (e.g., error message).
    """
    event = {
        "action": "federation_assimilation",
        "candidate_id": candidate_id,
        "success": success,
        "detail": detail,
    }
    # The audit log API is thread‑safe and writes to an in‑memory list.
    _audit_log.record_event(event)


def assimilate_candidate(candidate_id: str, signed_proposal: Any) -> Any:
    """Assimilate a federation candidate after revocation check.

    This wrapper performs three steps:

    1. Verify that ``candidate_id`` is not present in the revocation store.
    2. Forward the ``signed_proposal`` to the core assimilation function.
    3. Record the outcome in the audit log.

    Parameters
    ----------
    candidate_id: str
        Unique identifier of the federation candidate.
    signed_proposal: Any
        The cryptographically signed proposal object expected by
        ``omega.federation_assimilation.assimilate``.

    Returns
    -------
    Any
        The result returned by the underlying assimilation logic.

    Raises
    ------
    RevokedCandidateError
        If the candidate has been revoked.
    Exception
        Propagates any exception raised by the underlying assimilation routine.
    """
    # Step 1: revocation check.
    if _revocation.is_revoked(candidate_id):
        _log_attempt(candidate_id, success=False, detail="revoked")
        raise RevokedCandidateError(candidate_id)

    # Step 2: delegate to core assimilation.
    try:
        result = _assimilation.assimilate(signed_proposal)
    except Exception as exc:  # pragma: no cover – unexpected errors bubble up.
        _log_attempt(candidate_id, success=False, detail=str(exc))
        raise
    else:
        # Step 3: successful assimilation.
        _log_attempt(candidate_id, success=True)
        return result
