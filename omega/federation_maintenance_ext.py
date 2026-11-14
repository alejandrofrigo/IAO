'''omega/federation_maintenance_ext.py

Utility helpers for federation maintenance tasks that operate on the existing
`FederationManager` and `FederationTracker` implementations.  The helpers are
intentionally lightweight and defensive: they import the public manager
classes, detect the presence of the required pruning methods, and invoke them
in a try/except block so that the call never crashes the process.

These functions are **not** responsible for discovering or authorizing new
participants; they only provide a safe entry point for operators to clean up
stale state that may accumulate over long‑running deployments.
''' 

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Optional

logger = logging.getLogger(__name__)

# The core federation manager is exported from ``omega.__init__`` as
# ``FederationManager``.  Importing through the package ensures we use the
# public API and respect any runtime configuration that the package may have
# performed (e.g., singleton creation, dependency injection, etc.).
try:
    from . import FederationManager  # type: ignore
except Exception as exc:  # pragma: no cover – import failures are logged
    FederationManager = None  # type: ignore
    logger.error("Failed to import FederationManager: %s", exc)


def _get_manager() -> Optional[object]:
    """Return a FederationManager instance if the class is available.

    The function attempts to instantiate the manager with its default
    constructor.  If the class cannot be imported or instantiation fails, the
    function returns ``None`` and logs the problem.  This defensive approach
    prevents accidental crashes in environments where the manager is not
    configured.
    """
    if FederationManager is None:
        logger.debug("FederationManager is not available; maintenance helpers will be no‑ops.")
        return None
    try:
        return FederationManager()
    except Exception as exc:  # pragma: no cover – unexpected init errors
        logger.error("Could not instantiate FederationManager: %s", exc)
        return None


def prune_stale_candidates(max_age: timedelta) -> int:
    """Prune candidates that have not been updated within *max_age*.

    The function delegates to the underlying ``FederationManager`` implementation
    (if it provides a ``prune_stale_candidates`` method).  The manager method is
    expected to return the number of candidates removed.  If the manager does
    not expose such a method, the function logs a warning and returns ``0``.

    Parameters
    ----------
    max_age: datetime.timedelta
        The maximum allowed age for a candidate's ``last_updated`` timestamp.
        Candidates older than this threshold are considered stale.

    Returns
    -------
    int
        The count of candidates that were removed.  ``0`` indicates that no
        pruning occurred (either because the manager lacks the capability or
        because there were no stale entries).
    """
    manager = _get_manager()
    if manager is None:
        return 0

    prune_method = getattr(manager, "prune_stale_candidates", None)
    if not callable(prune_method):
        logger.warning(
            "FederationManager does not implement 'prune_stale_candidates'; "
            "maintenance helper is a no‑op."
        )
        return 0

    try:
        result = prune_method(max_age)
        if isinstance(result, int):
            logger.info("Pruned %d stale federation candidates.", result)
            return result
        # If the manager returns a non‑int (e.g., None), treat as zero.
        logger.debug(
            "prune_stale_candidates returned non‑int value %r; treating as 0.", result
        )
        return 0
    except Exception as exc:  # pragma: no cover – defensive logging
        logger.error("Error during prune_stale_candidates: %s", exc)
        return 0


def revoke_candidate(candidate_id: str, reason: str | None = None) -> bool:
    """Mark a candidate as revoked.

    This helper forwards the revocation request to the underlying manager
    (if it implements a ``revoke_candidate`` method).  It returns ``True`` when
    the revocation succeeds, otherwise ``False``.

    Parameters
    ----------
    candidate_id: str
        Identifier of the candidate to revoke.
    reason: str, optional
        Optional human‑readable explanation for the revocation.  The reason is
        passed through to the manager for audit logging.
    """
    manager = _get_manager()
    if manager is None:
        return False

    revoke_method = getattr(manager, "revoke_candidate", None)
    if not callable(revoke_method):
        logger.warning(
            "FederationManager does not implement 'revoke_candidate'; revocation ignored."
        )
        return False

    try:
        result = revoke_method(candidate_id, reason)
        # Managers may return True/False or raise on failure.
        success = bool(result)
        if success:
            logger.info("Candidate %s revoked%s.", candidate_id, f": {reason}" if reason else "")
        else:
            logger.warning("Revocation of candidate %s reported failure by manager.", candidate_id)
        return success
    except Exception as exc:  # pragma: no cover – defensive logging
        logger.error("Error revoking candidate %s: %s", candidate_id, exc)
        return False
