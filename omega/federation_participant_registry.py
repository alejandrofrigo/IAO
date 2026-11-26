# -*- coding: utf-8 -*-
"""Utilities for managing a registry of federation participants.

This module implements a lightweight, thread‑safe in‑memory registry that
stores participant descriptors.  Each descriptor is a ``dict`` with at least
the keys ``"id"`` (a unique string identifier) and ``"endpoint"`` (the base
URL of the participant).  The registry is deliberately simple – it does not
perform persistent I/O, making it safe for unit‑test environments and for
use in contexts where external storage is not yet configured.

Public API
~~~~~~~~~~
* ``register_participant(participant: dict) -> None``
* ``list_registered_participants() -> list[dict]``
* ``revoke_participant(participant_id: str) -> bool``

All operations are atomic with respect to the internal lock, ensuring that
concurrent callers cannot corrupt the registry state.
"""

from __future__ import annotations

import threading
from typing import Dict, List

# Internal storage – a list of participant dictionaries.
_registry: List[Dict[str, str]] = []
_registry_lock = threading.RLock()


def _validate_descriptor(descriptor: Dict) -> None:
    """Validate that a participant descriptor contains the required fields.

    The function raises ``ValueError`` if validation fails.
    """
    if not isinstance(descriptor, dict):
        raise ValueError("Participant descriptor must be a dict")
    required_keys = {"id", "endpoint"}
    missing = required_keys - descriptor.keys()
    if missing:
        raise ValueError(f"Missing required participant fields: {', '.join(sorted(missing))}")
    if not isinstance(descriptor["id"], str) or not descriptor["id"]:
        raise ValueError("Participant 'id' must be a non‑empty string")
    if not isinstance(descriptor["endpoint"], str) or not descriptor["endpoint"]:
        raise ValueError("Participant 'endpoint' must be a non‑empty string")


def register_participant(participant: Dict) -> None:
    """Register a new federation participant.

    The participant descriptor is validated and then stored in the in‑memory
    registry.  If a participant with the same ``id`` already exists, the
    existing entry is replaced (idempotent registration).
    """
    _validate_descriptor(participant)
    with registry_lock:
        # Remove any existing entry with the same id.
        global registry
        registry = [p for p in registry if p["id"] != participant["id"]]
        registry.append({"id": participant["id"], "endpoint": participant["endpoint"]})


def list_registered_participants() -> List[Dict]:
    """Return a shallow copy of the current participant registry.

    The returned list may be safely inspected or iterated over by callers
    without affecting the internal state.
    """
    with registry_lock:
        return list(registry)


def revoke_participant(participant_id: str) -> bool:
    """Remove a participant from the registry.

    Returns ``True`` if a participant was found and removed, ``False``
    otherwise.
    """
    if not isinstance(participant_id, str) or not participant_id:
        raise ValueError("participant_id must be a non‑empty string")
    with registry_lock:
        global registry
        original_len = len(registry)
        registry = [p for p in registry if p["id"] != participant_id]
        return len(registry) < original_len
