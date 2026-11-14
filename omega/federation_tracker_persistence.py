"""Utilities for persisting and restoring the FederationTracker state.

This module offers two high‑level functions:

* ``persist_tracker(tracker, file_path)`` – Serialises the current in‑memory state of a
  :class:`~omega.federation_tracker.FederationTracker` instance to a JSON file.
* ``load_tracker(file_path)`` – Deserialises the JSON file back into a new
  :class:`~omega.federation_tracker.FederationTracker` instance.

The implementation deliberately avoids storing any cryptographic secrets; it only
records candidate identifiers, lifecycle states and timestamps, which are already
public within the tracker.  JSON is used for human‑readability and ease of
verification.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict

from .federation_tracker import FederationTracker, CandidateState

__all__ = [
    "persist_tracker",
    "load_tracker",
]


def _tracker_to_serialisable(tracker: FederationTracker) -> Dict[str, Any]:
    """Convert a ``FederationTracker`` instance into a JSON‑serialisable dict.

    The function extracts the internal mapping of candidate IDs to their
    :class:`~omega.federation_tracker.CandidateState`.  Only primitive types are
    retained (str, int, float, bool, None) to ensure the JSON output is safe and
    reproducible.
    """
    serialised: Dict[str, Any] = {}
    for candidate_id, state in tracker.iter_candidates():
        # ``state`` is expected to be a dataclass or simple object with public
        # attributes describing the lifecycle.  We serialise the ``__dict__``
        # representation, filtering out any private attributes.
        state_dict = {
            key: value
            for key, value in vars(state).items()
            if not key.startswith("_")
        }
        serialised[candidate_id] = state_dict
    return serialised


def _serialisable_to_tracker(data: Dict[str, Any]) -> FederationTracker:
    """Recreate a ``FederationTracker`` from a serialised representation.

    The function builds a fresh ``FederationTracker`` and populates it with
    ``CandidateState`` objects reconstructed from the stored dictionaries.
    """
    tracker = FederationTracker()
    for candidate_id, state_dict in data.items():
        # Re‑create a CandidateState instance.  The constructor of CandidateState
        # must accept keyword arguments that match the original attributes.
        state = CandidateState(**state_dict)  # type: ignore[arg-type]
        tracker._set_state(candidate_id, state)  # Access the internal method safely.
    return tracker


def persist_tracker(tracker: FederationTracker, file_path: str) -> None:
    """Persist the given ``tracker`` to *file_path* as pretty‑printed JSON.

    The directory hierarchy is created if it does not exist.  The function is
    idempotent – writing to an existing file overwrites it atomically using a
    temporary file.
    """
    if not isinstance(tracker, FederationTracker):
        raise TypeError("tracker must be an instance of FederationTracker")

    serialised = _tracker_to_serialisable(tracker)
    os.makedirs(os.path.dirname(file_path) or ".", exist_ok=True)
    temp_path = f"{file_path}.tmp"
    with open(temp_path, "w", encoding="utf-8") as fp:
        json.dump(serialised, fp, indent=2, sort_keys=True)
    os.replace(temp_path, file_path)


def load_tracker(file_path: str) -> FederationTracker:
    """Load a ``FederationTracker`` instance from *file_path*.

    Raises ``FileNotFoundError`` if the path does not exist and ``json.JSONDecodeError``
    if the file contents are malformed.
    """
    with open(file_path, "r", encoding="utf-8") as fp:
        data = json.load(fp)
    if not isinstance(data, dict):
        raise ValueError("Invalid tracker file format: top‑level JSON must be an object")
    return _serialisable_to_tracker(data)
