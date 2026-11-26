# -*- coding: utf-8 -*-
"""Utility to safely onboard federation participants.

This module provides a high‑level function :func:`onboard_participant` that
performs minimal yet essential validation of a participant description before
registering it in the federation participant registry.

The validation includes:

* Presence of required keys (``id``, ``domain``, ``endpoint``).
* ``id`` must be a non‑empty string.
* ``domain`` must be a non‑empty string.
* ``endpoint`` must be a HTTPS URL whose host matches the supplied ``domain``.

The function raises :class:`ValueError` with an explanatory message when a
validation check fails, ensuring that only well‑formed participant entries are
added to the registry.  Upon successful validation the participant is stored via
the existing :class:`ParticipantRegistry` implementation located in
``omega.federation_participant_registry``.

This utility does **not** perform network I/O (DNS look‑ups, TLS handshakes,
or capability probing) because such operations are optional and may require
operator‑controlled policies.  Operators that need deeper checks can invoke the
lower‑level validators (e.g. ``omega.federation_connectivity``) before calling
this function.
"""

from __future__ import annotations

import urllib.parse
from typing import Mapping

# The participant registry provides a thread‑safe, in‑memory store for federation
# participants.  It is expected to expose a ``register`` method that accepts a
# mapping representing the participant and raises a ``KeyError`` if the entry
# already exists.
from .federation_participant_registry import ParticipantRegistry

__all__ = ["onboard_participant"]


def _validate_participant_structure(participant: Mapping) -> None:
    """Validate that the participant mapping contains required fields.

    Parameters
    ----------
    participant: Mapping
        The participant description supplied by the operator.

    Raises
    ------
    ValueError
        If any required key is missing or has an invalid type/value.
    """
    required_keys = {"id", "domain", "endpoint"}
    missing = required_keys - participant.keys()
    if missing:
        raise ValueError(f"Participant description missing required keys: {missing}")

    # Validate ``id``
    pid = participant["id"]
    if not isinstance(pid, str) or not pid.strip():
        raise ValueError("Participant 'id' must be a non‑empty string")

    # Validate ``domain``
    domain = participant["domain"]
    if not isinstance(domain, str) or not domain.strip():
        raise ValueError("Participant 'domain' must be a non‑empty string")

    # Validate ``endpoint``
    endpoint = participant["endpoint"]
    if not isinstance(endpoint, str) or not endpoint.strip():
        raise ValueError("Participant 'endpoint' must be a non‑empty string")
    parsed = urllib.parse.urlparse(endpoint)
    if parsed.scheme.lower() != "https":
        raise ValueError("Participant 'endpoint' must use HTTPS scheme")
    if not parsed.netloc:
        raise ValueError("Participant 'endpoint' must contain a network location (host)")
    # Ensure the endpoint's host matches the declared domain (allow optional www.)
    endpoint_host = parsed.hostname or ""
    if endpoint_host != domain and endpoint_host != f"www.{domain}":
        raise ValueError(
            f"Endpoint host '{endpoint_host}' does not match declared domain '{domain}'"
        )


def onboard_participant(participant: Mapping) -> bool:
    """Validate and register a federation participant.

    This function is the public entry point used by operators and tests to add a
    new participant to the federation network in a safe, deterministic manner.

    Parameters
    ----------
    participant: Mapping
        A dictionary with at least the keys ``id``, ``domain`` and ``endpoint``.
        Additional metadata may be included but will be stored verbatim.

    Returns
    -------
    bool
        ``True`` if the participant was successfully registered.

    Raises
    ------
    ValueError
        If the participant description fails validation.
    KeyError
        If a participant with the same ``id`` is already present in the registry.
    """
    # Perform structural and basic format validation.
    _validate_participant_structure(participant)

    # Register the participant using the central registry.
    registry = ParticipantRegistry.instance()
    registry.register(dict(participant))  # Store a shallow copy to avoid mutations.
    return True
