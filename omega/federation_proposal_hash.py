"""Utility for deterministic hashing of federation proposals.

This module offers a single public function :func:`proposal_hash` that accepts a
Python ``dict`` representing a federation proposal and returns a SHA‑256
hex‑digest of its *canonical* JSON serialization.  The serialization follows the
canonical format used by :mod:`omega.federation_proposal_serialization`, ensuring
that the same logical proposal always yields the same hash regardless of key
ordering or whitespace.

The hash is useful for:

* Auditing – storing a short identifier alongside signed proposals.
* Deduplication – detecting when the same proposal has been processed multiple
  times.
* Quick integrity checks – verifying that a loaded proposal matches the hash
  recorded in logs or databases.

The implementation relies only on the Python standard library and the
canonical‑serialization helper already present in the codebase.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

# Import the canonical serializer from the existing module.  If the import
# fails (e.g., the module is missing in a future revision), we fall back to a
# deterministic ``json.dumps`` with ``sort_keys=True`` and ``separators`` that
# match the behaviour of the original serializer.
try:
    from omega.federation_proposal_serialization import serialize_proposal_canonical
except Exception:  # pragma: no cover
    def serialize_proposal_canonical(proposal: Mapping[str, Any]) -> bytes:
        """Fallback canonical JSON serializer.

        The fallback mirrors the expected canonical format: keys are sorted
        alphabetically, ASCII separators are used, and the result is UTF‑8
        encoded bytes without trailing whitespace.
        """
        return json.dumps(
            proposal,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

__all__ = ["proposal_hash"]


def proposal_hash(proposal: Mapping[str, Any]) -> str:
    """Return a SHA‑256 hex‑digest for a federation proposal.

    Parameters
    ----------
    proposal:
        The federation proposal as a JSON‑serialisable mapping.  The function
        does **not** modify the input.

    Returns
    -------
    str
        A 64‑character hexadecimal string representing the SHA‑256 digest of the
        proposal's canonical JSON representation.
    """
    if not isinstance(proposal, Mapping):
        raise TypeError("proposal must be a mapping (e.g., dict)")

    # Obtain the canonical bytes; the helper guarantees deterministic ordering.
    canonical_bytes: bytes = serialize_proposal_canonical(proposal)

    # Compute SHA‑256 hash.
    digest = hashlib.sha256(canonical_bytes).hexdigest()
    return digest
