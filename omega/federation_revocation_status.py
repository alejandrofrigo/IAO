# -*- coding: utf-8 -*-
"""Utility module to query participant revocation status in the federation.

This module offers a deterministic, offline API that wraps the internal
revocation registry implementation (if present). It provides two public
functions:

* ``get_revoked_participants()`` – returns a list of participant IDs that have
  been revoked.
* ``is_revoked(participant_id)`` – returns ``True`` if the given participant
  identifier is revoked, ``False`` otherwise.

The implementation gracefully degrades when the internal revocation registry
is unavailable, corrupted, or raises an exception, returning an empty list and
``False`` respectively. No external network calls are performed.
"""

from __future__ import annotations

from typing import List


def _load_revocation_registry():
    """Attempt to load the internal revocation registry.

    The federation subsystem may provide a ``RevocationRegistry`` class with a
    ``load`` class‑method that returns an instance containing revocation data.
    If such a class or method is missing, or loading fails, this helper returns
    ``None`` so that callers can fall back to a safe default.
    """
    try:
        # Import lazily to avoid pulling heavy dependencies unless needed.
        from .federation_assimilation_revocation import RevocationRegistry  # type: ignore
    except Exception:
        return None

    # The registry is expected to expose a ``revoked_ids`` method that returns
    # an iterable of participant identifiers. If the API differs, we catch the
    # AttributeError and treat the registry as unavailable.
    try:
        return RevocationRegistry.load()  # type: ignore
    except Exception:
        return None


def get_revoked_participants() -> List[str]:
    """Return a list of participant identifiers that have been revoked.

    The function reads the revocation registry using the internal helper. If the
    registry cannot be loaded, an empty list is returned, guaranteeing that the
    caller receives a deterministic result without raising.
    """
    registry = _load_revocation_registry()
    if registry is None:
        return []
    try:
        revoked = list(registry.revoked_ids())  # type: ignore
    except Exception:
        # Protect against unexpected API shapes.
        revoked = []
    return revoked


def is_revoked(participant_id: str) -> bool:
    """Check whether a specific participant identifier is revoked.

    Parameters
    ----------
    participant_id: str
        The identifier of the participant to check.

    Returns
    -------
    bool
        ``True`` if the participant appears in the revocation list, ``False``
        otherwise.
    """
    if not isinstance(participant_id, str):
        raise TypeError("participant_id must be a string")
    revoked = get_revoked_participants()
    return participant_id in revoked


__all__ = [
    "get_revoked_participants",
    "is_revoked",
]
