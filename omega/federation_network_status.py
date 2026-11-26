# -*- coding: utf-8 -*-
"""Utilities for reporting high‑level federation network status.

This module provides a deterministic function ``get_federation_network_summary``
that aggregates information from participant registry and proposal stores.
It is intentionally lightweight and relies only on public APIs of the
federation subsystem, handling missing components gracefully.
"""

from __future__ import annotations

from typing import Dict, List, Optional

# Import public helpers if available; fall back to safe defaults.
try:
    from .federation_participant_registry import get_all_participants
except Exception:  # pragma: no cover
    def get_all_participants() -> List[object]:  # type: ignore
        return []

try:
    # The proposal module provides utilities to list proposals by state.
    from .federation_proposals import list_federation_proposals
except Exception:  # pragma: no cover
    def list_federation_proposals(state: str = "all") -> List[object]:  # type: ignore
        return []


def _count_proposals_by_state(state: str) -> int:
    """Return the number of proposals for a given *state*.

    The underlying ``list_federation_proposals`` function is expected to accept a
    ``state`` argument with values like ``"active"``, ``"revoked"`` or ``"all"``.
    If the implementation differs, the function gracefully returns ``0``.
    """
    try:
        proposals = list_federation_proposals(state)
        return len(proposals)
    except Exception:  # pragma: no cover
        return 0


def get_federation_network_summary() -> Dict[str, int]:
    """Return a dictionary summarising the federation network.

    Keys:
        - ``participant_count``: Number of registered participants.
        - ``active_proposal_count``: Proposals currently active.
        - ``revoked_proposal_count``: Proposals that have been revoked.
        - ``total_proposal_count``: All proposals known to the system.
    """
    participant_count = len(get_all_participants())
    active_proposal_count = _count_proposals_by_state("active")
    revoked_proposal_count = _count_proposals_by_state("revoked")
    total_proposal_count = _count_proposals_by_state("all")

    return {
        "participant_count": participant_count,
        "active_proposal_count": active_proposal_count,
        "revoked_proposal_count": revoked_proposal_count,
        "total_proposal_count": total_proposal_count,
    }
