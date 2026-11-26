# -*- coding: utf-8 -*-
"""High‑level controller for federation proposal assimilation.

This module offers a deterministic, side‑effect‑controlled function that
orchestrates the full lifecycle of a federation proposal:

1. Load the proposal from a local JSON/YAML file.
2. Validate its structural integrity and cryptographic signature.
3. Verify that the declared capabilities are acceptable.
4. Assimilate the proposal into the local federation state.
5. Record audit events for success, rejection, or failure.

No network I/O is performed; all operations rely on the existing local
utilities in the ``omega`` package. The controller is deliberately thin – it
delegates to the specialised low‑level modules and concentrates error handling
and audit logging in one place, making it easy to test and reuse.
"""

from __future__ import annotations

import typing as _t

# Type aliases for clarity – the concrete types are defined in the imported
# federation modules. Using ``_t.Any`` keeps the module import‑time lightweight
# and avoids circular import issues.
Proposal = _t.Any


def _import_modules() -> _t.Tuple[_t.Any, _t.Any, _t.Any]:
    """Import required federation sub‑modules lazily.

    Returns a tuple ``(proposals_mod, assimilation_mod, audit_mod)``. Any import
    errors are re‑raised as ``ImportError`` with a clear message so that callers
    understand why the controller cannot operate.
    """
    try:
        from . import federation_proposals as proposals_mod
        from . import federation_assimilation as assimilation_mod
        from . import federation_audit as audit_mod
    except Exception as exc:  # pragma: no cover – import failures are fatal
        raise ImportError(
            f"Failed to import required federation modules: {exc}"
        ) from exc
    return proposals_mod, assimilation_mod, audit_mod


def process_and_assimilate_proposal(proposal_path: str) -> bool:
    """Load, validate, and assimilate a federation proposal.

    Parameters
    ----------
    proposal_path: str
        Absolute or relative filesystem path to the proposal file.

    Returns
    -------
    bool
        ``True`` if the proposal was successfully assimilated, ``False`` if it
        was rejected due to validation failure or an internal error occurred.

    This function performs **no external network calls**; it operates purely on
    local data and uses the existing audit facility to record what happened.
    """
    proposals_mod, assimilation_mod, audit_mod = _import_modules()

    # ---------------------------------------------------------------------
    # 1. Load the raw proposal document.
    # ---------------------------------------------------------------------
    try:
        raw_proposal: Proposal = proposals_mod.load_proposal(proposal_path)  # type: ignore[attr-defined]
    except Exception as exc:  # pragma: no cover – loading errors are logged
        audit_mod.log_event(
            "proposal_load_failed",
            {"path": proposal_path, "error": str(exc)},
        )
        return False

    # ---------------------------------------------------------------------
    # 2. Structural and cryptographic validation.
    # ---------------------------------------------------------------------
    try:
        is_valid: bool = proposals_mod.validate_proposal(raw_proposal)  # type: ignore[attr-defined]
    except Exception as exc:  # pragma: no cover – validation errors are logged
        audit_mod.log_event(
            "proposal_validation_error",
            {"path": proposal_path, "error": str(exc)},
        )
        return False

    if not is_valid:
        audit_mod.log_event("proposal_rejected", {"path": proposal_path})
        return False

    # ---------------------------------------------------------------------
    # 3. Assimilation into the local federation state.
    # ---------------------------------------------------------------------
    try:
        assimilation_mod.assimilate_proposal(raw_proposal)  # type: ignore[attr-defined]
    except Exception as exc:  # pragma: no cover – assimilation errors are logged
        audit_mod.log_event(
            "proposal_assimilation_failed",
            {"path": proposal_path, "error": str(exc)},
        )
        return False

    # ---------------------------------------------------------------------
    # 4. Success path – record the event.
    # ---------------------------------------------------------------------
    audit_mod.log_event("proposal_assimilated", {"path": proposal_path})
    return True
