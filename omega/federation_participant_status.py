# -*- coding: utf-8 -*-
"""Utility for retrieving a deterministic status snapshot of a federation participant.

The function :func:`get_participant_status` aggregates information from the
participant registry, the capability validator and the last‑seen tracker.
It performs **no external network calls** and raises clear exceptions when
required subsystems are unavailable. This module is deliberately lightweight
and safe to import in any environment where the ``omega`` package is
available.
"""

from __future__ import annotations

import datetime
import json
import os
from typing import Any, Dict

# The registry of participants is maintained by ``omega.federation_candidate_registry``
# if it exists. We import it lazily to avoid hard dependencies when the module is
# not part of the current deployment.

def _load_registry() -> Dict[str, Any]:
    """Load the participant registry from the default JSON store.

    The registry file location is taken from the ``IAO_FEDERATION_REGISTRY``
    environment variable; if not set, a fallback path relative to the package
    directory is used. An empty dictionary is returned when the file does not
    exist.
    """
    registry_path = os.getenv(
        "IAO_FEDERATION_REGISTRY",
        os.path.join(os.path.dirname(__file__), "_registry.json"),
    )
    if not os.path.isfile(registry_path):
        return {}
    try:
        with open(registry_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        raise RuntimeError(f"Failed to load federation registry: {exc}") from exc


def _load_last_seen() -> Dict[str, str]:
    """Load a mapping of participant identifiers to ISO‑8601 timestamps.

    The data is stored in ``_last_seen.json`` in the same directory as the
    registry. Missing files are treated as an empty mapping.
    """
    last_seen_path = os.path.join(os.path.dirname(__file__), "_last_seen.json")
    if not os.path.isfile(last_seen_path):
        return {}
    try:
        with open(last_seen_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        raise RuntimeError(f"Failed to load last‑seen data: {exc}") from exc


def _validate_capabilities(participant_record: Dict[str, Any]) -> bool:
    """Validate the declared capabilities of a participant.

    The actual validation logic lives in ``omega.federation_capability_validator``.
    If that module is unavailable, we conservatively return ``False``.
    """
    try:
        from omega.federation_capability_validator import (
            validate_capabilities,
        )
    except Exception:
        # Validator not present – safest default is to consider the capabilities
        # unvalidated.
        return False
    try:
        return bool(validate_capabilities(participant_record))
    except Exception:
        # Any validation error is treated as a failed validation.
        return False


def get_participant_status(participant_id: str) -> Dict[str, Any]:
    """Return a deterministic status snapshot for *participant_id*.

    The returned dictionary contains the following keys:

    - ``registered`` (bool): ``True`` if the participant appears in the registry.
    - ``last_seen`` (str | None): ISO‑8601 timestamp of the most recent activity,
      or ``None`` when no record exists.
    - ``capabilities_valid`` (bool): Result of capability validation; ``False``
      when the validator is missing or the participant fails validation.
    - ``metadata`` (dict): The raw participant record from the registry (empty
      when not registered).

    Example
    -------
    >>> from omega.federation_participant_status import get_participant_status
    >>> status = get_participant_status("node‑123")
    >>> status["registered"]
    True
    """
    if not isinstance(participant_id, str) or not participant_id:
        raise ValueError("participant_id must be a non‑empty string")

    registry = _load_registry()
    participant_record = registry.get(participant_id, {})
    registered = bool(participant_record)

    last_seen_map = _load_last_seen()
    last_seen_iso = last_seen_map.get(participant_id)
    if last_seen_iso:
        # Validate ISO‑8601 format; fallback to None on parsing error.
        try:
            datetime.datetime.fromisoformat(last_seen_iso)
        except Exception:
            last_seen_iso = None
    else:
        last_seen_iso = None

    capabilities_valid = _validate_capabilities(participant_record) if registered else False

    return {
        "registered": registered,
        "last_seen": last_seen_iso,
        "capabilities_valid": capabilities_valid,
        "metadata": participant_record,
    }


__all__ = ["get_participant_status"]
