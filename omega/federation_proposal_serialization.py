'''omega/federation_proposal_serialization.py

Utility functions for deterministic JSON serialization/deserialization of federation
proposals.  The federation workflow builds proposals as plain Python ``dict``
objects.  For cryptographic signing (Ed25519) the exact byte sequence must be
stable across platforms and runs.  This module provides a single source of
truth for that transformation, guaranteeing:

* Canonical ordering of keys (``sort_keys=True``)
* UTF‑8 encoded ``bytes`` output for signing APIs
* Validation of required top‑level fields during deserialization
* Human‑readable JSON string representation for storage/logging

The implementation is deliberately lightweight and has no external runtime
dependencies beyond the Python standard library.
'''  # noqa: D400

from __future__ import annotations

import json
from typing import Any, Dict, Iterable

# The set of fields that every federation proposal must contain.  These are
# defined by the protocol and used by the signing/verification utilities.
_REQUIRED_FIELDS: Iterable[str] = (
    "proposal_id",
    "issuer",
    "timestamp",
    "capabilities",
    "endpoint",
    "signature",  # The Ed25519 signature (base64‑encoded string)
)


def _validate_proposal_structure(proposal: Dict[str, Any]) -> None:
    """Validate that *proposal* contains all required top‑level keys.

    Raises:
        ValueError: If any required field is missing.
    """
    missing = [field for field in _REQUIRED_FIELDS if field not in proposal]
    if missing:
        raise ValueError(
            f"Federation proposal is missing required fields: {', '.join(missing)}"
        )


def serialize_proposal(proposal: Dict[str, Any]) -> bytes:
    """Serialize *proposal* to a deterministic ``bytes`` payload.

    The function first validates the proposal structure, then dumps it to a
    JSON string with sorted keys and no whitespace, finally encodes the string
    as UTF‑8 bytes.  The resulting ``bytes`` object is suitable for hashing and
    Ed25519 signing.

    Args:
        proposal: The federation proposal dictionary.

    Returns:
        A ``bytes`` object containing the canonical JSON representation.
    """
    _validate_proposal_structure(proposal)
    # ``separators`` removes the default space after commas/colons.
    json_str = json.dumps(proposal, sort_keys=True, separators=(',', ':'))
    return json_str.encode('utf-8')


def deserialize_proposal(payload: bytes | str) -> Dict[str, Any]:
    """Deserialize a JSON *payload* back into a proposal dictionary.

    The function accepts either a UTF‑8 ``bytes`` object or a ``str``.  After
    parsing the JSON it validates that all required fields are present.

    Args:
        payload: JSON data representing a federation proposal.

    Returns:
        A ``dict`` with the proposal contents.

    Raises:
        ValueError: If the JSON is malformed or required fields are missing.
    """
    if isinstance(payload, bytes):
        try:
            payload = payload.decode('utf-8')
        except UnicodeDecodeError as exc:
            raise ValueError("Proposal payload is not valid UTF‑8") from exc
    try:
        proposal = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid JSON payload for federation proposal") from exc
    if not isinstance(proposal, dict):
        raise ValueError("Deserialized proposal must be a JSON object (dict)")
    _validate_proposal_structure(proposal)
    return proposal


def proposal_to_pretty_json(proposal: Dict[str, Any]) -> str:
    """Return a human‑readable, pretty‑printed JSON string for *proposal*.

    This helper is useful for logging or persisting proposals in a format that
    developers can inspect.  It performs the same structural validation as the
    canonical serializer.
    """
    _validate_proposal_structure(proposal)
    return json.dumps(proposal, sort_keys=True, indent=2, ensure_ascii=False)
