"""Public API wrappers for federation proposal storage.

This module offers a safe, high‑level interface to list and retrieve
persisted federation proposals that have been stored using
``omega.federation_proposal_store``.  It abstracts the concrete storage
implementation and ensures that callers receive ``None`` instead of
exceptions when a proposal cannot be loaded.

Typical usage::

    from omega.federation_proposal_api import (
        list_stored_proposals,
        get_stored_proposal,
    )

    hashes = list_stored_proposals()
    for h in hashes:
        proposal = get_stored_proposal(h)
        if proposal is not None:
            # process proposal
            ...

The functions are deliberately simple and thread‑safe because the
underlying ``ProposalStore`` uses internal locking.
"""

from __future__ import annotations

from typing import List, Optional, Dict, Any

# Import the concrete store with a tolerant helper to avoid import‑time
# failures if optional dependencies are missing.  The store module is part
# of the core package, so this import is expected to succeed; however, we
# guard against unexpected errors to keep the public API robust.

try:
    from omega.federation_proposal_store import ProposalStore
except Exception:  # pragma: no cover – defensive fallback
    ProposalStore = None  # type: ignore

# Initialise a singleton store instance if possible.
_store: Optional[ProposalStore] = ProposalStore() if ProposalStore is not None else None


def _ensure_store() -> ProposalStore:
    """Return the global ``ProposalStore`` instance or raise a clear error.

    The function centralises the check that the store has been created
    successfully, providing a deterministic exception message for callers.
    """
    if _store is None:
        raise RuntimeError(
            "ProposalStore is unavailable – the federation proposal storage "
            "module could not be loaded."
        )
    return _store


def list_stored_proposals() -> List[str]:
    """Return a list of proposal hashes that are currently persisted.

    The underlying ``ProposalStore`` supplies a deterministic ordering; the
    wrapper simply forwards the result.  An empty list indicates that no
    proposals have been stored yet.
    """
    store = _ensure_store()
    try:
        return store.list_hashes()
    except Exception as exc:  # pragma: no cover – defensive
        # If the store raises an unexpected error we surface an empty list
        # rather than bubbling the exception, keeping the API safe for
        # read‑only callers.
        return []


def get_stored_proposal(proposal_hash: str) -> Optional[Dict[str, Any]]:
    """Load a stored proposal by its hash.

    Parameters
    ----------
    proposal_hash: str
        The canonical hash identifier of the proposal as returned by
        :func:`list_stored_proposals`.

    Returns
    -------
    dict | None
        The deserialized proposal dictionary if it exists and can be
        successfully validated; otherwise ``None``.
    """
    store = _ensure_store()
    try:
        return store.load(proposal_hash)
    except Exception:
        # Any problem (missing file, corruption, validation failure) results
        # in a ``None`` return, allowing callers to handle the absence
        # gracefully.
        return None


__all__ = [
    "list_stored_proposals",
    "get_stored_proposal",
]
