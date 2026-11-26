"""Utilities to list federation proposals filtered by their lifecycle status.

This module builds on the existing high‑level APIs:
- :func:`omega.federation_active_proposals.get_active_proposal_ids`
- :func:`omega.federation_revocation.get_revoked_proposal_ids`
- :func:`omega.store.list_all_proposal_ids`

It provides a deterministic, testable entry point that returns the identifiers of
proposals matching the requested *status*.
"""

from __future__ import annotations

from typing import List

# Import existing helpers. They are lazily imported inside the functions to avoid
# circular‑import issues and to keep the module lightweight.


def _get_active_ids() -> List[str]:
    """Return identifiers of active (non‑revoked, non‑expired) proposals.

    Delegates to the dedicated ``federation_active_proposals`` utility.
    """
    from .federation_active_proposals import get_active_proposal_ids

    return list(get_active_proposal_ids())


def _get_revoked_ids() -> List[str]:
    """Return identifiers of proposals that have been explicitly revoked.

    Uses the ``federation_revocation`` module which tracks revocation records.
    """
    from .federation_revocation import get_revoked_proposal_ids

    return list(get_revoked_proposal_ids())


def _get_all_ids() -> List[str]:
    """Return identifiers of every stored proposal, regardless of status.

    Relies on the generic store accessor.
    """
    from .store import list_all_proposal_ids

    return list(list_all_proposal_ids())


def list_federation_proposals(status: str = "active") -> List[str]:
    """List federation proposal identifiers filtered by *status*.

    Parameters
    ----------
    status: str, optional
        The desired filter. Supported values are:
        - ``"active"``  – proposals that are currently valid (default).
        - ``"revoked"`` – proposals that have been revoked.
        - ``"all"``     – every proposal present in the store.
        Any other value raises :class:`ValueError`.

    Returns
    -------
    List[str]
        A list of proposal identifiers matching the requested status.
    """
    normalized = status.strip().lower()
    if normalized == "active":
        return _get_active_ids()
    elif normalized == "revoked":
        return _get_revoked_ids()
    elif normalized == "all":
        return _get_all_ids()
    else:
        raise ValueError(
            f"Unsupported status '{status}'. Expected 'active', 'revoked' or 'all'."
        )
