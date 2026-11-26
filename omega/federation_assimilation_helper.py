"""Helper utilities for secure federation proposal assimilation.

This module provides a high‑level function that first verifies the Ed25519
signature of a federation proposal using the existing signature utilities
and, upon successful verification, delegates the actual assimilation to the
core assimilation logic.  It returns a boolean indicating success, allowing
callers (e.g., orchestrators, facades, or tests) to handle failures
gracefully.

The implementation purposefully avoids any side effects such as network
communication or automatic participant registration; it only updates the
in‑memory tracker supplied by the caller.
"""

from __future__ import annotations

from typing import Any, Dict

# Import the existing signature verification utility. The utility is
# expected to expose a function `verify_proposal_signature(proposal: dict,
# signature: bytes) -> bool` that returns True when the signature is valid.
from .federation_proposal_signature import verify_proposal_signature

# Import the core assimilation routine. It is assumed to provide a function
# `assimilate_proposal(proposal: dict, tracker: Any) -> None` which records the
# proposal as assimilated in the provided tracker.
from .federation_assimilation import assimilate_proposal


def verify_and_assimilate(
    proposal: Dict[str, Any],
    signature: bytes,
    tracker: Any,
) -> bool:
    """Verify a signed federation proposal and assimilate it on success.

    Parameters
    ----------
    proposal: dict
        The federation proposal payload to be verified.
    signature: bytes
        The Ed25519 signature that authenticates ``proposal``.
    tracker: Any
        An instance of the federation tracker (e.g., ``FederationTracker``) that
        records the state of candidates. The helper forwards this to the core
        assimilation function without interpreting its internals.

    Returns
    -------
    bool
        ``True`` if the signature is valid and the proposal was assimilated;
        ``False`` otherwise.
    """
    # Step 1: Verify the cryptographic binding between the proposal and the
    # signature.  Any exception raised by the verification utility is caught
    # and treated as a verification failure, preserving the contract of a
    # simple boolean return value.
    try:
        if not verify_proposal_signature(proposal, signature):
            return False
    except Exception:
        # Defensive: unexpected errors should not propagate to callers that
        # expect a boolean outcome.
        return False

    # Step 2: Delegate to the core assimilation logic.  The assimilation
    # function is responsible for updating the tracker, performing any
    # additional validation, and raising only on critical internal errors.
    try:
        assimilate_proposal(proposal, tracker)
    except Exception:
        # If assimilation fails (e.g., malformed proposal), we consider the
        # overall operation unsuccessful.
        return False

    return True
