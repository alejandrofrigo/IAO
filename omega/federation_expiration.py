# -*- coding: utf-8 -*-
"""Utility for automatic expiration handling of federation proposals.

This module inspects stored federation proposals, determines whether they have
expired based on timestamps or explicit ``expires_at`` fields, and revokes
them using the existing revocation API. It returns the list of proposal IDs
that were marked as expired.

The implementation relies solely on internal federation modules:

* ``omega.federation`` – provides functions to list and load proposals.
* ``omega.federation_revocation`` – provides the ``revoke_federation_proposal``
  function used to mark a proposal as revoked.

No external network calls or side‑effects beyond the revocation operation are
performed.
"""

from __future__ import annotations

import datetime as _dt
from typing import List

# Import low‑level federation storage utilities safely.
# If the expected functions are not present, the module degrades gracefully
# by raising a clear RuntimeError, ensuring that callers are aware of a
# misconfiguration rather than encountering obscure AttributeErrors.
try:
    from omega import federation as _fed
except Exception as exc:  # pragma: no cover
    raise RuntimeError(
        "Failed to import omega.federation required for expiration handling"
    ) from exc

try:
    from omega import federation_revocation as _rev
except Exception as exc:  # pragma: no cover
    raise RuntimeError(
        "Failed to import omega.federation_revocation required for revocation"
    ) from exc


def _parse_iso_datetime(value: str) -> _dt.datetime:
    """Parse an ISO‑8601 datetime string.

    The function supports both ``YYYY‑MM‑DDTHH:MM:SS`` and the extended
    ``YYYY‑MM‑DDTHH:MM:SS.sssZ`` formats. A trailing ``Z`` is interpreted as UTC.
    """
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        return _dt.datetime.fromisoformat(value)
    except ValueError as exc:  # pragma: no cover
        raise ValueError(f"Invalid ISO datetime format: {value!r}") from exc


def _is_expired(proposal: dict, now: _dt.datetime) -> bool:
    """Determine whether *proposal* is expired at *now*.

    The function checks for the following fields (in order of precedence):

    1. ``expires_at`` – an ISO‑8601 timestamp.
    2. ``created_at`` together with ``validity_seconds`` – calculates the
       expiration moment.
    3. If none are present, the proposal is considered non‑expiring.
    """
    # Direct expiration timestamp
    expires_at = proposal.get("expires_at")
    if isinstance(expires_at, str):
        try:
            expiry = _parse_iso_datetime(expires_at)
            return now >= expiry
        except ValueError:
            # Fall back to secondary logic if format is unexpected
            pass

    # Compute from creation time + validity period
    created_at = proposal.get("created_at")
    validity_seconds = proposal.get("validity_seconds")
    if isinstance(created_at, str) and isinstance(validity_seconds, (int, float)):
        try:
            created_dt = _parse_iso_datetime(created_at)
            expiry = created_dt + _dt.timedelta(seconds=validity_seconds)
            return now >= expiry
        except ValueError:
            pass

    # No expiration information – treat as non‑expiring
    return False


def expire_federated_proposals(max_batch: int | None = None) -> List[str]:
    """Revoke all federation proposals that have expired.

    Parameters
    ----------
    max_batch:
        Optional limit on the number of proposals to process in a single call.
        If ``None`` (default) all proposals are examined.

    Returns
    -------
    List[str]
        A list containing the identifiers of proposals that were revoked
        during this invocation.

    Notes
    -----
    * The function is idempotent – invoking it multiple times will only act on
      proposals that remain unrevoked and have an expiration timestamp in the
      past.
    * Revocation is performed via ``omega.federation_revocation.
      revoke_federation_proposal`` with the reason ``"expired"``.
    """
    now = _dt.datetime.utcnow().replace(tzinfo=_dt.timezone.utc)
    revoked_ids: List[str] = []

    # Retrieve the complete set of stored proposal identifiers.
    try:
        all_ids = _fed.list_federation_proposal_ids()
    except AttributeError as exc:  # pragma: no cover
        raise RuntimeError(
            "The underlying federation module does not expose "
            "'list_federation_proposal_ids'."
        ) from exc

    if max_batch is not None:
        all_ids = all_ids[:max_batch]

    for pid in all_ids:
        try:
            proposal = _fed.load_federation_proposal(pid)
        except Exception:
            # Skip malformed or inaccessible proposals; they will be handled
            # elsewhere (e.g., by audit tools).
            continue

        if _is_expired(proposal, now):
            try:
                _rev.revoke_federation_proposal(pid, reason="expired")
                revoked_ids.append(pid)
            except Exception:  # pragma: no cover
                # If revocation fails, we continue processing other proposals.
                continue

    return revoked_ids
