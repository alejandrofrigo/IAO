"""High‑level orchestration for a single federation candidate.

The function ``run_federation_pipeline`` performs the end‑to‑end processing
required to discover, validate, propose, sign and assimilate a candidate using
the existing federation sub‑modules. It updates the in‑memory state tracker so
that external tools can query the lifecycle status.
"""

from typing import Any, Dict, Optional

# Import sub‑modules via the package's public symbols; they may be ``None`` if
# optional parts of the system are not present.
from . import (
    federation_candidate_registry,
    federation_state_tracker,
    federation_proposals,
    federation_assimilation,
    federation_connectivity,
)


def _record_state(candidate_id: str, state: str, details: Optional[Dict[str, Any]] = None) -> None:
    """Record the current *state* of *candidate_id* in the global tracker.

    The tracker is expected to provide an ``update`` method with the signature
    ``update(candidate_id, state, details)``. If the tracker is unavailable the
    call is silently ignored.
    """
    tracker = (
        federation_state_tracker.get_tracker()
        if federation_state_tracker and hasattr(federation_state_tracker, "get_tracker")
        else None
    )
    if tracker and hasattr(tracker, "update"):
        try:
            tracker.update(candidate_id, state, details or {})
        except Exception:
            # Never let state‑tracking failures break the pipeline.
            pass


def run_federation_pipeline(candidate_data: Dict[str, Any]) -> Dict[str, Any]:
    """Process *candidate_data* through the full federation workflow.

    Args:
        candidate_data: Dictionary describing the candidate (must contain an
            ``id`` key and any endpoint information required by the lower‑level
            modules).

    Returns:
        A dictionary containing at least ``candidate_id`` and ``status``. On
        success ``status`` is ``"completed"`` and ``result`` holds the assimilated
        data. On failure ``status`` is ``"failed"`` and ``error`` describes the
        problem.
    """
    candidate_id = candidate_data.get("id")
    if not candidate_id:
        raise ValueError("Candidate data must include an 'id' field")

    _record_state(candidate_id, "received", {"candidate": candidate_data})

    # Register the candidate if a registry is available.
    if federation_candidate_registry and hasattr(federation_candidate_registry, "register_candidate"):
        try:
            federation_candidate_registry.register_candidate(candidate_id, candidate_data)
        except Exception as exc:
            _record_state(candidate_id, "registration_failed", {"error": str(exc)})
            return {"candidate_id": candidate_id, "status": "failed", "error": str(exc)}

    # Validate connectivity (optional step).
    if federation_connectivity and hasattr(federation_connectivity, "check_connectivity"):
        try:
            reachable = federation_connectivity.check_connectivity(candidate_data)
        except Exception as exc:
            _record_state(candidate_id, "connectivity_error", {"error": str(exc)})
            return {"candidate_id": candidate_id, "status": "failed", "error": str(exc)}
        if not reachable:
            _record_state(candidate_id, "unreachable")
            return {"candidate_id": candidate_id, "status": "failed", "error": "Unreachable"}

    _record_state(candidate_id, "validated")

    # Build a proposal.
    if not federation_proposals or not hasattr(federation_proposals, "create_proposal"):
        _record_state(candidate_id, "proposal_failed", {"error": "Proposals module missing"})
        return {"candidate_id": candidate_id, "status": "failed", "error": "Proposals module missing"}
    try:
        proposal = federation_proposals.create_proposal(candidate_data)
    except Exception as exc:
        _record_state(candidate_id, "proposal_error", {"error": str(exc)})
        return {"candidate_id": candidate_id, "status": "failed", "error": str(exc)}

    # Assume the proposal is already signed or can be signed via a ``sign`` method.
    signed_proposal = proposal
    if hasattr(proposal, "sign"):
        try:
            signed_proposal = proposal.sign()
        except Exception as exc:
            _record_state(candidate_id, "signing_error", {"error": str(exc)})
            return {"candidate_id": candidate_id, "status": "failed", "error": str(exc)}

    # Assimilate the signed proposal.
    if not federation_assimilation or not hasattr(federation_assimilation, "assimilate_signed_proposal"):
        _record_state(candidate_id, "assimilation_failed", {"error": "Assimilation module missing"})
        return {"candidate_id": candidate_id, "status": "failed", "error": "Assimilation module missing"}
    try:
        result = federation_assimilation.assimilate_signed_proposal(signed_proposal)
    except Exception as exc:
        _record_state(candidate_id, "assimilation_error", {"error": str(exc)})
        return {"candidate_id": candidate_id, "status": "failed", "error": str(exc)}

    _record_state(candidate_id, "completed", {"result": result})
    return {"candidate_id": candidate_id, "status": "completed", "result": result}
