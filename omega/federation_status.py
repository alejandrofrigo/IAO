"""Utilities for determining the current status of a federation proposal.

This module offers a single public function :func:`get_federation_proposal_status` that
returns a human‑readable status string for a proposal identified by its id. The
function works with the existing proposal store and, when available, re‑uses the
legacy ``get_proposal_status`` implementation from ``omega.federation_proposals``.
It deliberately avoids any network activity and performs only local, deterministic
checks (revocation flag and expiration timestamp).

Possible return values:

* ``"active"``   – the proposal exists, is not revoked and has not expired.
* ``"revoked"``  – the proposal has been explicitly revoked.
* ``"expired"``  – the proposal’s ``expires_at`` timestamp is in the past.
* ``"missing"``  – no proposal with the supplied identifier is stored.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helper: try to import a legacy status function. If the legacy module provides
# ``get_proposal_status`` we will defer to it, guaranteeing compatibility with
# any future internal refactorings.
# ---------------------------------------------------------------------------
try:
    from .federation_proposals import get_proposal_status as _legacy_get_status  # type: ignore
except Exception:  # pragma: no cover – optional import may fail silently
    _legacy_get_status = None  # type: ignore


def _load_proposal(proposal_id: str) -> Optional[Mapping[str, Any]]:
    """Load a proposal record from the persistent store.

    The repository defines a generic ``store`` module that contracts a ``ProposalStore``
    class exposing a ``get`` method returning a mapping or ``None`` when the id is
    unknown.  Import errors are caught and logged; the function returns ``None``
    in that case, allowing the caller to treat the proposal as *missing*.
    """
    try:
        from .store import ProposalStore  # pylint: disable=import-error
    except Exception as exc:  # pragma: no cover
        logger.debug("ProposalStore could not be imported: %s", exc)
        return None

    try:
        store = ProposalStore()
        proposal = store.get(proposal_id)  # type: ignore[arg-type]
        return proposal  # may be None
    except Exception as exc:  # pragma: no cover
        logger.debug("Error retrieving proposal %s: %s", proposal_id, exc)
        return None


def _is_revoked(proposal: Mapping[str, Any]) -> bool:
    """Return ``True`` if the proposal carries a revocation flag.

    The exact field name differs between implementations; we check a set of
    common identifiers.
    """
    for flag in ("revoked", "is_revoked", "revocation", "revoked_at"):
        if flag in proposal:
            value = proposal[flag]
            # ``revoked`` may be a boolean, a timestamp or any truthy marker.
            if isinstance(value, bool):
                return value
            if isinstance(value, (int, float)):
                return value != 0
            if isinstance(value, str):
                # non‑empty string usually means revoked (e.g., a timestamp).
                return bool(value.strip())
    return False


def _is_expired(proposal: Mapping[str, Any]) -> bool:
    """Return ``True`` if the proposal has an ``expires_at`` timestamp in the past.
    The timestamp is expected to be ISO‑8601 compatible.
    """
    expiry = proposal.get("expires_at") or proposal.get("expiry") or proposal.get("expires")
    if not expiry:
        return False
    try:
        # ``fromisoformat`` handles both naïve and aware datetime strings.
        dt = datetime.fromisoformat(str(expiry))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt < datetime.now(timezone.utc)
    except Exception as exc:  # pragma: no cover
        logger.debug("Failed to parse expiration %r: %s", expiry, exc)
        return False


def get_federation_proposal_status(proposal_id: str) -> str:
    """Return a concise status string for the proposal identified by ``proposal_id``.

    The function follows a deterministic decision order:

    1. If a legacy ``get_proposal_status`` is available, its result is returned
       directly.  This ensures backward compatibility with any specialised
       logic that may exist elsewhere in the code base.
    2. Otherwise the proposal is loaded from the persistent store.  When the
       proposal cannot be found, ``"missing"`` is returned.
    3. If the proposal carries a revocation marker, ``"revoked"`` is returned.
    4. If the proposal has an ``expires_at`` timestamp that is earlier than the
       current UTC time, ``"expired"`` is returned.
    5. In all other cases the proposal is considered ``"active"``.
    """
    if _legacy_get_status is not None:
        try:
            return _legacy_get_status(proposal_id)  # type: ignore[no-any-return]
        except Exception as exc:  # pragma: no cover
            logger.debug("Legacy get_proposal_status failed: %s", exc)
            # fall back to the local implementation

    proposal = _load_proposal(proposal_id)
    if proposal is None:
        return "missing"

    if _is_revoked(proposal):
        return "revoked"

    if _is_expired(proposal):
        return "expired"

    return "active"

__all__ = ["get_federation_proposal_status"]
