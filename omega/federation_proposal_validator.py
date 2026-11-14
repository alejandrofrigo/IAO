# -*- coding: utf-8 -*-
"""Utility for validating the structure of federation proposals.

The federation subsystem operates on proposal objects stored as dictionaries
with a strict schema.  Functions that create, verify or assimilate proposals
expect the following top‑level keys:

* ``id`` – a non‑empty ``str`` uniquely identifying the proposal.
* ``candidate`` – a ``dict`` describing the candidate; it must contain at least
  an ``id`` field of type ``str``.
* ``signature`` – the Ed25519 signature; accepted as ``bytes`` (64 bytes) or a
  lower‑case hexadecimal ``str`` of length 128.
* ``timestamp`` – an ``int`` representing Unix epoch seconds when the proposal
  was created.

The ``validate_federation_proposal`` function checks these constraints and
raises a ``ValueError`` with a descriptive message for any violation.  This
validator is deterministic, does not perform any I/O, and can be safely used
by high‑level orchestration utilities and unit tests.
"""

from __future__ import annotations

import binascii
from typing import Any, Mapping

__all__: list[str] = ["validate_federation_proposal"]


def _is_hex_string(value: str, length: int) -> bool:
    """Return ``True`` if *value* is a hex string of exactly *length* characters.

    The check is case‑insensitive and ensures the string contains only valid
    hexadecimal characters.
    """
    if len(value) != length:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def validate_federation_proposal(proposal: Mapping[str, Any]) -> None:
    """Validate that *proposal* conforms to the expected federation schema.

    Parameters
    ----------
    proposal: Mapping[str, Any]
        The proposal object to validate.  It is typically a ``dict`` loaded from
        persistent storage.

    Raises
    ------
    ValueError
        If any required field is missing, has the wrong type, or fails content
        constraints.
    """
    if not isinstance(proposal, Mapping):
        raise ValueError("Proposal must be a mapping type (e.g., dict)")

    # ---------------------------------------------------------------------
    # Validate top‑level ``id``
    # ---------------------------------------------------------------------
    if "id" not in proposal:
        raise ValueError("Proposal missing required key: 'id'")
    if not isinstance(proposal["id"], str) or not proposal["id"].strip():
        raise ValueError("Proposal 'id' must be a non‑empty string")

    # ---------------------------------------------------------------------
    # Validate ``candidate`` sub‑object
    # ---------------------------------------------------------------------
    if "candidate" not in proposal:
        raise ValueError("Proposal missing required key: 'candidate'")
    candidate = proposal["candidate"]
    if not isinstance(candidate, Mapping):
        raise ValueError("Proposal 'candidate' must be a mapping (dict)")
    if "id" not in candidate:
        raise ValueError("Candidate object missing required key: 'id'")
    if not isinstance(candidate["id"], str) or not candidate["id"].strip():
        raise ValueError("Candidate 'id' must be a non‑empty string")

    # ---------------------------------------------------------------------
    # Validate ``signature``
    # ---------------------------------------------------------------------
    if "signature" not in proposal:
        raise ValueError("Proposal missing required key: 'signature'")
    sig = proposal["signature"]
    if isinstance(sig, bytes):
        if len(sig) != 64:
            raise ValueError("Signature bytes must be exactly 64 bytes for Ed25519")
    elif isinstance(sig, str):
        # Accept hex‑encoded signature (128 hex characters)
        if not _is_hex_string(sig.lower(), 128):
            raise ValueError(
                "Signature string must be a 128‑character hex representation"
            )
    else:
        raise ValueError(
            "Signature must be either bytes (64) or a 128‑char hex string"
        )

    # ---------------------------------------------------------------------
    # Validate ``timestamp``
    # ---------------------------------------------------------------------
    if "timestamp" not in proposal:
        raise ValueError("Proposal missing required key: 'timestamp'")
    ts = proposal["timestamp"]
    if not isinstance(ts, int) or ts < 0:
        raise ValueError("Timestamp must be a non‑negative integer representing Unix epoch seconds")

    # If all checks pass, the function simply returns ``None``.
    return None
