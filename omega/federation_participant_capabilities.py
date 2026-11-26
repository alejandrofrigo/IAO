# -*- coding: utf-8 -*-
"""Utilities for fetching and validating participant capabilities.

This module implements a deterministic, high‑level function
`get_participant_capabilities` that:

1. Looks up a participant by its identifier in the in‑memory participant
   registry (`omega.federation_participant_registry`).
2. Retrieves the participant's advertised endpoint.
3. Runs the capability validator (`omega.federation_capability_validator`) to
   obtain a structured list of supported capabilities.
4. Returns a dict with the participant information and validation result, or
   an error description if any step fails.

The function is safe to import and call in test environments – it catches
all unexpected exceptions and reports them in the returned structure rather
than raising, ensuring the public API remains robust.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

# Local imports – wrapped in try/except to avoid import‑time failures if
# optional components are missing.
try:
    from .federation_participant_registry import (
        get_participant_by_id,
        ParticipantRecord,
    )
except Exception:  # pragma: no cover
    get_participant_by_id = None  # type: ignore
    ParticipantRecord = None  # type: ignore

try:
    from .federation_capability_validator import validate_capabilities
except Exception:  # pragma: no cover
    validate_capabilities = None  # type: ignore

__all__: List[str] = ["get_participant_capabilities"]


def _error(message: str) -> Dict[str, Any]:
    """Standardised error payload used by the public API."""
    return {"success": False, "error": message}


def get_participant_capabilities(participant_id: str) -> Dict[str, Any]:
    """Return the capabilities advertised by a registered participant.

    Parameters
    ----------
    participant_id: str
        The unique identifier of the participant as stored in the registry.

    Returns
    -------
    dict
        A deterministic payload with the following keys:

        * ``success`` (bool) – ``True`` when capabilities are successfully
          retrieved and validated.
        * ``participant`` (dict) – Basic participant data (id, endpoint) when
          ``success`` is ``True``.
        * ``capabilities`` (list) – List of capability strings returned by the
          validator when ``success`` is ``True``.
        * ``error`` (str) – Human‑readable explanation when ``success`` is
          ``False``.
    """
    # Step 1: verify registry is available
    if get_participant_by_id is None:
        return _error("Participant registry component is unavailable.")

    # Step 2: fetch participant record
    try:
        record: Optional[ParticipantRecord] = get_participant_by_id(participant_id)
    except Exception as exc:  # pragma: no cover
        return _error(f"Error querying participant registry: {exc}")

    if not record:
        return _error(f"Participant with id '{participant_id}' not found.")

    endpoint: str = getattr(record, "endpoint", None)  # type: ignore
    if not endpoint:
        return _error("Participant record does not contain a valid endpoint.")

    # Step 3: run capability validation if the validator is present
    if validate_capabilities is None:
        return _error("Capability validator component is unavailable.")

    try:
        capabilities: List[str] = validate_capabilities(endpoint)
    except Exception as exc:  # pragma: no cover
        return _error(f"Capability validation failed: {exc}")

    # Step 4: compose successful payload
    return {
        "success": True,
        "participant": {
            "id": participant_id,
            "endpoint": endpoint,
        },
        "capabilities": capabilities,
    }
