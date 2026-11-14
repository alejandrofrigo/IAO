"""Utility helpers for federation state checks.

This module provides small, testable functions that operate on the
federation tracker without introducing side‑effects. They are intended
for operator tooling and automated test suites.
"""

from typing import Any


def is_candidate_ready(candidate_id: str, tracker: Any) -> bool:
    """Return ``True`` if the candidate identified by *candidate_id*
    has reached the ``'signed'`` lifecycle state.

    Parameters
    ----------
    candidate_id: str
        The unique identifier of the federation candidate.
    tracker: Any
        An instance of the federation tracker (e.g. ``FederationTracker``).
        The tracker is expected to implement a ``get_state`` method that
        returns the current lifecycle state as a string.

    Returns
    -------
    bool
        ``True`` when the candidate is ready for assimilation, otherwise
        ``False``.
    """
    try:
        state = tracker.get_state(candidate_id)
    except Exception:
        # If the tracker does not expose the expected API, treat as not ready.
        return False
    return state == "signed"
