# -*- coding: utf-8 -*-
"""High‑level federation orchestration utilities.

This module offers a single deterministic entry point that processes a stored
federation proposal end‑to‑end. It composes the existing low‑level building
blocks:

* ``verify_federation_proposal_signature`` – cryptographic integrity check.
* ``get_federation_proposal_status`` – lifecycle state (active, revoked, …).
* ``assimilate_federation_proposal`` – apply the proposal to the local node
  when it is active and verified.

The function returns a structured dict that can be used by operators, tests
or monitoring tools to understand what happened during processing.
"""

from __future__ import annotations

from typing import Dict, Any

# Local imports are performed lazily inside the function to avoid import‑time
# side effects if optional components are unavailable.

def process_federation_proposal(proposal_id: str) -> Dict[str, Any]:
    """Process a stored federation proposal end‑to‑end.

    The workflow is:

    1. **Signature verification** – ensures the proposal was created by a
       trusted participant.
    2. **Status evaluation** – determines whether the proposal is ``active``,
       ``revoked``, ``expired`` or ``unknown``.
    3. **Assimilation** – if the proposal is active *and* the signature is
       valid, the proposal is assimilated into the local node.

    The function returns a dictionary with the following keys:

    * ``proposal_id`` – the identifier supplied by the caller.
    * ``verified`` – ``True`` if the signature check succeeded.
    * ``status`` – the lifecycle status string (or ``None`` if unavailable).
    * ``assimilated`` – ``True`` when assimilation was performed successfully.
    * ``error`` – ``None`` on success or a string describing the exception
      that occurred.

    Parameters
    ----------
    proposal_id: str
        The unique identifier of the stored federation proposal.

    Returns
    -------
    dict
        A report of the processing outcome.
    """
    result: Dict[str, Any] = {
        "proposal_id": proposal_id,
        "verified": False,
        "status": None,
        "assimilated": False,
        "error": None,
    }

    try:
        # Import inside the try block to keep the module importable even if
        # any of the low‑level utilities are temporarily unavailable.
        from .federation_proposal_verifier import verify_federation_proposal_signature
        from .federation_status import get_federation_proposal_status
        from .federation_assimilation import assimilate_federation_proposal

        # Step 1 – cryptographic verification.
        result["verified"] = verify_federation_proposal_signature(proposal_id)

        # Step 2 – fetch lifecycle status.
        result["status"] = get_federation_proposal_status(proposal_id)

        # Step 3 – assimilate only when the proposal is active and verified.
        if result["verified"] and result["status"] == "active":
            result["assimilated"] = assimilate_federation_proposal(proposal_id)
    except Exception as exc:  # pragma: no cover – exercised via tests.
        # Capture the error message for diagnostic purposes while preserving
        # the exception for callers that rely on it.
        result["error"] = str(exc)
        raise

    return result

__all__ = ["process_federation_proposal"]
