"""Utilities for querying federation candidate information.

This module offers a lightweight, read‑only helper that returns the current
lifecycle state of a federation candidate as known by the global
``FederationTracker``.  It does **not** perform any network activity, proposal
creation or assimilation – it simply inspects the in‑memory tracking data.

Typical usage::

    from omega.federation_query import fetch_candidate_status

    status = fetch_candidate_status("candidate-1234")
    if status is None:
        print("candidate not found")
    else:
        print(f"candidate state: {status}")

The function is thread‑safe because the underlying ``FederationTracker``
employs its own synchronization primitives.
"""

from __future__ import annotations

from typing import Optional

# Import the singleton tracker that maintains candidate lifecycle information.
# The tracker implementation provides a ``get_state(candidate_id)`` method
# returning the textual state (e.g., "discovered", "validated", "proposal_signed",
# "assimilated", "revoked") or ``None`` if the candidate is unknown.
from .federation_tracker import FederationTracker


def fetch_candidate_status(candidate_id: str) -> Optional[str]:
    """Return the current lifecycle state of *candidate_id*.

    Parameters
    ----------
    candidate_id: str
        The unique identifier of the federation candidate.

    Returns
    -------
    Optional[str]
        The textual state of the candidate as stored by the tracker, or ``None``
        if the candidate is not registered.
    """
    if not isinstance(candidate_id, str) or not candidate_id:
        raise ValueError("candidate_id must be a non‑empty string")

    # ``FederationTracker`` is designed as a singleton; ``instance()`` returns the
    # shared object that holds all candidate records.
    tracker = FederationTracker.instance()
    # The tracker may raise its own exceptions; we surface them to the caller
    # because they indicate a serious internal error.
    return tracker.get_state(candidate_id)
