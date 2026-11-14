"""High‑level entrypoint for the federation workflow.

This module provides ``submit_federation_candidate`` which coordinates the
different federation stages (validation, proposal building, signing,
verification and assimilation) and updates the in‑memory state tracker.
It is imported by ``omega.__init__`` and re‑exported as part of the public
API.
"""

from typing import Any

# Imports are performed lazily via the package's safe import helper to avoid
# import‑time side effects.
from . import (
    federation,
    federation_proposals,
    federation_assimilation,
    federation_state_tracker,
)


def submit_federation_candidate(candidate: Any, private_key: bytes) -> Any:
    """Execute the full federation pipeline for *candidate*.

    The implementation mirrors the convenience wrapper exported from
    ``omega.__init__`` but is kept as a separate module so that advanced users can
    import it directly without pulling the whole package namespace.
    """
    # Validation (optional).
    validator = getattr(federation, "validate_candidate", None)
    if callable(validator):
        validator(candidate)

    # Build proposal.
    builder = getattr(federation_proposals, "build_proposal", None)
    if not callable(builder):
        raise RuntimeError("Missing build_proposal in federation_proposals")
    proposal = builder(candidate)

    # Sign.
    signer = getattr(federation_proposals, "sign_proposal", None)
    if not callable(signer):
        raise RuntimeError("Missing sign_proposal in federation_proposals")
    signed = signer(proposal, private_key)

    # Verify.
    verifier = getattr(federation_proposals, "verify_proposal", None)
    if not callable(verifier):
        raise RuntimeError("Missing verify_proposal in federation_proposals")
    verifier(signed)

    # Assimilate.
    assimilate = getattr(federation_assimilation, "assimilate_proposal", None)
    if not callable(assimilate):
        raise RuntimeError("Missing assimilate_proposal in federation_assimilation")
    result = assimilate(signed)

    # State tracking.
    if federation_state_tracker is not None:
        tracker_fn = getattr(federation_state_tracker, "get_tracker", None)
        if callable(tracker_fn):
            tracker_fn().record(candidate_id=getattr(candidate, "id", None), status="assimilated")

    return result
