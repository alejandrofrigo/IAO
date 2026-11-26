# -*- coding: utf-8 -*-
"""High‑level API for verifying federation proposal signatures.

This module offers a single deterministic function that loads a stored
federation proposal, runs the Ed25519 signature verification using the
core federation utilities, and returns a structured result wrapper.  It
isolates import‑time errors and translates internal exceptions into a
clear JSON‑compatible dictionary, making it safe for automated tests and
operator tooling.
"""

from __future__ import annotations

from typing import Any, Dict

# Lazy import helper to avoid importing heavy federation modules unless
# this function is actually used.
def _lazy_import(module_name: str) -> Any:
    """Import *module_name* lazily and return the module object.

    This mirrors the ``_safe_import`` pattern used in ``omega.__init__``
    but is scoped to this file to keep the implementation self‑contained.
    """
    import importlib
    return importlib.import_module(module_name)


def verify_federation_proposal_signature(proposal_id: str) -> Dict[str, Any]:
    """Verify the Ed25519 signature of a stored federation proposal.

    Parameters
    ----------
    proposal_id: str
        The unique identifier of the proposal to verify.  The identifier
        should correspond to the key used by the proposal storage layer
        (e.g., a UUID or hash string).

    Returns
    -------
    dict
        A dictionary with the following keys:
        - ``valid`` (bool): ``True`` if the signature is verified, ``False``
          otherwise.
        - ``detail`` (Any): The raw verification payload returned by the
          underlying verifier when ``valid`` is ``True``.
        - ``error`` (str, optional): Human‑readable error message when the
          verification cannot be performed (e.g., proposal missing or
          unexpected exception).
    """
    # Import the low‑level federation helpers only when needed.
    federation_mod = _lazy_import("omega.federation")
    # Expected low‑level helpers:
    #   - get_stored_proposal(proposal_id) -> dict | None
    #   - verify_proposal_signature(proposal_dict) -> (bool, Any)
    get_proposal = getattr(federation_mod, "get_stored_proposal", None)
    verify_sig = getattr(federation_mod, "verify_proposal_signature", None)

    if not callable(get_proposal) or not callable(verify_sig):
        return {
            "valid": False,
            "error": "Required federation utilities are unavailable",
        }

    proposal = get_proposal(proposal_id)
    if proposal is None:
        return {
            "valid": False,
            "error": f"Proposal with id '{proposal_id}' not found",
        }

    try:
        is_valid, detail = verify_sig(proposal)
        return {
            "valid": bool(is_valid),
            "detail": detail,
        }
    except Exception as exc:  # pragma: no cover – defensive safety net
        return {
            "valid": False,
            "error": str(exc),
        }
