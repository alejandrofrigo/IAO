"""Federation proposal status helper.

This module defines a deterministic, thread‑safe function that inspects a stored
federation proposal and reports its lifecycle state:

* ``active``   – the proposal exists, is not revoked and has not expired.
* ``revoked``  – the proposal exists and has been explicitly revoked.
* ``expired``  – the proposal exists but its time‑to‑live has elapsed.
* ``unknown``  – no proposal with the given identifier is present in the store.

The implementation leverages the existing in‑memory proposal store
(`omega.federation_proposal_store`) and the expiration validator
(`omega.federation_proposal_expiration`). It avoids any network activity and
does not modify stored data, making it safe for use in audit, monitoring and
testing contexts.
"""

from __future__ import annotations

from typing import Literal

# Import the singleton store instance. The store provides ``get`` and ``list``
# operations that are thread‑safe.
from .federation_proposal_store import get_proposal_store

# The expiration utility knows how to interpret the ``timestamp`` and
# ``ttl_seconds`` fields that are attached to each signed proposal.
try:
    from .federation_proposal_expiration import is_proposal_expired
except Exception:  # pragma: no cover – defensive fallback if the module is missing
    def is_proposal_expired(_proposal: dict) -> bool:  # type: ignore
        """Fallback stub that never reports expiration.

        The real implementation lives in ``federation_proposal_expiration``.
        If for any reason it cannot be imported, we conservatively treat the
        proposal as **not** expired, allowing the status function to continue
        operating.
        """
        return False


Status = Literal["active", "revoked", "expired", "unknown"]


def get_proposal_status(proposal_id: str) -> Status:
    """Return the lifecycle status of a federation proposal.

    Parameters
    ----------
    proposal_id: str
        The identifier (hash) of the proposal as stored by the proposal store.

    Returns
    -------
    Status
        One of ``"active"``, ``"revoked"``, ``"expired"`` or ``"unknown"``.
    """
    store = get_proposal_store()
    proposal = store.get(proposal_id)

    if proposal is None:
        return "unknown"

    # A revoked proposal is explicitly marked by the revocation workflow.
    if proposal.get("revoked", False):
        return "revoked"

    # Check expiration using the shared utility.
    if is_proposal_expired(proposal):
        return "expired"

    return "active"
