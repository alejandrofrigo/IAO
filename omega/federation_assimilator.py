"""Federation proposal assimilation utilities.

This module provides a high‑level function to ingest a signed federation proposal,
verify its cryptographic integrity, validate the declared candidate capabilities,
and register the candidate in the in‑memory federation candidate registry.

It relies on existing, tested building blocks:

* ``omega.federation_proposal_crypto.verify_signature`` – Ed25519 signature check.
* ``omega.federation_capability_validator.validate_candidate_capabilities`` –
  deterministic capability validation.
* ``omega.federation_candidate_registry.FederationCandidateRegistry`` – thread‑safe
  in‑memory store for discovered candidates.

The function raises ``ValueError`` with a clear message on any failure, allowing
callers (e.g., higher‑level orchestration code or tests) to handle errors
appropriately.
"""

from __future__ import annotations

from typing import Any, Dict

from .federation_proposal_crypto import verify_signature
from .federation_capability_validator import (
    validate_candidate_capabilities,
)
from .federation_candidate_registry import FederationCandidateRegistry

__all__ = ["assimilate_federation_proposal"]


def assimilate_federation_proposal(
    proposal: Dict[str, Any],
    *,
    registry: FederationCandidateRegistry | None = None,
) -> bool:
    """Validate and ingest a federation proposal.

    Parameters
    ----------
    proposal:
        The proposal dictionary expected to contain at least the keys:
        ``candidate``, ``signature`` and ``public_key``. The ``candidate`` entry
        must itself be a mapping describing the federated node.
    registry:
        Optional ``FederationCandidateRegistry`` instance. If omitted a global
        singleton registry is used. Supplying a custom registry eases testing
        and enables separation of state across different environments.

    Returns
    -------
    bool
        ``True`` if the proposal was successfully verified, validated and the
        candidate registered. ``False`` is never returned – errors raise a
        ``ValueError`` describing the failure reason.

    Raises
    ------
    ValueError
        If the proposal is malformed, signature verification fails, or the
        candidate capabilities do not pass validation.
    """

    # ---------------------------------------------------------------------
    # Basic structural checks
    # ---------------------------------------------------------------------
    required_keys = {"candidate", "signature", "public_key"}
    missing = required_keys.difference(proposal.keys())
    if missing:
        raise ValueError(f"Proposal is missing required fields: {sorted(missing)}")

    candidate = proposal["candidate"]
    signature = proposal["signature"]
    public_key = proposal["public_key"]

    # ---------------------------------------------------------------------
    # Cryptographic verification
    # ---------------------------------------------------------------------
    if not verify_signature(candidate, signature, public_key):
        raise ValueError("Invalid signature for the federation proposal")

    # ---------------------------------------------------------------------
    # Capability validation – ensures the candidate conforms to the expected
    # schema and declares only allowed capabilities.
    # ---------------------------------------------------------------------
    validation_errors = validate_candidate_capabilities(candidate)
    if validation_errors:
        # ``validate_candidate_capabilities`` returns a list of textual errors.
        # An empty list indicates success.
        raise ValueError(
            "Candidate capability validation failed: " + "; ".join(validation_errors)
        )

    # ---------------------------------------------------------------------
    # Registration
    # ---------------------------------------------------------------------
    # Use a global singleton if no explicit registry is supplied. The registry
    # implementation is thread‑safe and provides ``register`` which raises if a
    # duplicate identifier is used.
    if registry is None:
        from .federation_candidate_registry import get_global_registry

        registry = get_global_registry()

    candidate_id = candidate.get("id")
    if candidate_id is None:
        raise ValueError("Candidate dictionary must contain an 'id' field")

    try:
        registry.register(candidate_id, candidate)
    except Exception as exc:
        raise ValueError(f"Failed to register candidate {candidate_id!r}: {exc}") from exc

    return True

