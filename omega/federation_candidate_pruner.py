# -*- coding: utf-8 -*-
"""Utility to prune stale federation candidates from the registry.

A candidate is considered stale when its ``registered_at`` timestamp is older
than *max_age_seconds* (default: 24 hours). The function removes such
candidates safely, returning a list with the IDs of removed entries.
"""

from __future__ import annotations

import datetime
import logging
from typing import List

# The candidate registry is a singleton providing thread‑safe access to the
# in‑memory collection of discovered federation candidates.
from .federation_candidate_registry import CandidateRegistry

log = logging.getLogger(__name__)


def prune_stale_candidates(max_age_seconds: int = 86_400) -> List[str]:
    """Remove candidates that have been registered longer than *max_age_seconds*.

    Parameters
    ----------
    max_age_seconds: int
        Age in seconds after which a candidate is considered stale. The default
        corresponds to 24 hours.

    Returns
    -------
    List[str]
        The identifiers of the candidates that were removed from the registry.
    """
    now = datetime.datetime.utcnow()
    removed: List[str] = []

    # Obtain the singleton registry instance. The concrete implementation is
    # expected to provide ``iter_candidates`` (yielding candidate objects) and
    # ``remove_candidate`` (removing by candidate identifier).
    registry = CandidateRegistry.get_instance()

    for candidate in list(registry.iter_candidates()):
        # Each candidate must expose an ``id`` attribute and a ``registered_at``
        # datetime in UTC. We defensively handle malformed entries.
        candidate_id = getattr(candidate, "id", None)
        registered_at = getattr(candidate, "registered_at", None)
        if not isinstance(candidate_id, str) or not isinstance(registered_at, datetime.datetime):
            log.debug(
                "Skipping candidate with missing or invalid metadata: id=%s, registered_at=%s",
                candidate_id,
                registered_at,
            )
            continue

        age_seconds = (now - registered_at).total_seconds()
        if age_seconds > max_age_seconds:
            try:
                registry.remove_candidate(candidate_id)
                removed.append(candidate_id)
                log.info(
                    "Pruned stale federation candidate %s (age %.0f seconds)",
                    candidate_id,
                    age_seconds,
                )
            except Exception as exc:  # pragma: no cover
                # Removal should never raise in normal operation; log and move on.
                log.warning("Failed to prune stale candidate %s: %s", candidate_id, exc)

    return removed
