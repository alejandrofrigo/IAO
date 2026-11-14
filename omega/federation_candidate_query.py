"""Utilities for querying federation candidates.

This module provides a thin, thread‑safe wrapper around the in‑memory
:class:`omega.federation_candidate_registry.FederationCandidateRegistry`
to retrieve the current set of known federation candidates.  It is useful
for operators, monitoring tools, and tests that need to inspect the
lifecycle state of candidates without modifying the registry.
"""

from __future__ import annotations

from typing import List, Dict, Optional

# Import the singleton registry instance.  The registry module defines a
# ``get_registry`` function that returns the thread‑safe singleton.
from omega.federation_candidate_registry import get_registry


def list_candidates(status_filter: Optional[str] = None) -> List[Dict[str, object]]:
    """Return a list of candidate descriptors from the federation registry.

    Args:
        status_filter: If provided, only candidates whose ``status`` attribute
            matches the filter (case‑insensitive) are returned.  When ``None``
            all candidates are listed.

    Returns:
        A list of dictionaries, each representing a candidate.  The dictionary
        contains at least the following keys:

        * ``candidate_id`` – The unique identifier assigned by the registry.
        * ``status`` – Current lifecycle status (e.g., ``"discovered"``,
          ``"validated"``, ``"approved"``, ``"revoked"``).
        * ``metadata`` – Arbitrary metadata supplied during discovery or
          validation (may be empty).

    The function acquires the registry's internal lock to guarantee a
    consistent snapshot of the candidates.
    """
    registry = get_registry()
    # The registry provides a ``snapshot`` method that returns a shallow copy
    # of its internal mapping under the protection of its lock.
    candidates_map = registry.snapshot()

    result: List[Dict[str, object]] = []
    for cid, candidate in candidates_map.items():
        # ``candidate`` is expected to expose ``status`` and ``metadata``
        # attributes.  We fallback to ``getattr`` with defaults to stay robust
        # against future changes.
        cand_status = getattr(candidate, "status", None)
        if status_filter is not None and cand_status is not None:
            if str(cand_status).lower() != str(status_filter).lower():
                continue
        result.append({
            "candidate_id": cid,
            "status": cand_status,
            "metadata": getattr(candidate, "metadata", {}),
        })
    return result
