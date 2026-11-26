"""Utilities for querying active federation proposals.

This module offers a single public function :func:`list_active_proposals` that returns
a list of proposal dictionaries which are currently valid – i.e. they have not been
revoked and have not passed their expiration time.  It builds on the existing
:mod:`omega.federation_proposal_store` and :mod:`omega.federation_proposal_status`
helpers, so no new storage semantics are introduced.

The implementation is deliberately lightweight and side‑effect free; it only
reads from the in‑memory store and performs simple timestamp checks.  All
operations are thread‑safe because the underlying store already guarantees
concurrency safety.
"""

from __future__ import annotations

import datetime as _dt
from typing import List, Dict, Any

# The proposal store provides thread‑safe access to the persisted proposals.
# It is expected to expose ``get_all_proposals() -> List[Dict[str, Any]]``.
from . import federation_proposal_store as _store

# The status helper knows how to interpret a proposal's timestamps and revocation flag.
# It must provide ``is_expired(proposal) -> bool`` and ``is_revoked(proposal) -> bool``.
from . import federation_proposal_status as _status

__all__ = ["list_active_proposals"]


def list_active_proposals() -> List[Dict[str, Any]]:
    """Return all proposals that are currently active.

    A proposal is considered *active* when:

    1. It exists in the central proposal store.
    2. Its ``revoked`` flag is ``False`` (or absent).
    3. Its expiration timestamp (if present) is in the future.

    The function performs no mutation; it merely filters the full proposal list.
    The returned list contains shallow copies of the stored dictionaries to avoid
    accidental modification of the internal store state.
    """
    # Retrieve a snapshot of all stored proposals.
    all_proposals = _store.get_all_proposals()

    active: List[Dict[str, Any]] = []
    for proposal in all_proposals:
        # Defensive copy – callers should not mutate the store directly.
        proposal_copy = dict(proposal)

        if _status.is_revoked(proposal_copy):
            continue
        if _status.is_expired(proposal_copy):
            continue
        active.append(proposal_copy)

    return active
