"""omega.federation_cycle
================================

High‑level helper that executes a complete federation workflow for a set of
candidate specifications.  It stitches together the building blocks that have
already been introduced in the code base:

* ``FederationCandidate`` – model for a candidate.
* ``validate_and_track_candidate`` – validates connectivity and updates the
  candidate tracker.
* ``build_signed_proposal`` – creates and signs a federation proposal.
* ``assimilate_signed_proposal`` – verifies the signature and assimilates the
  proposal into the local federation state.

The function is deliberately lightweight and defensive: it catches
exceptions from each stage, records them, and continues processing the rest of
the candidates.  The returned summary can be used by tests or monitoring tools
to assert that the federation pipeline behaves as expected.

Only standard library modules and the already‑approved ``omega`` sub‑modules
are used, respecting all security and policy constraints.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .federation_candidate import FederationCandidate
from .federation_utils import validate_and_track_candidate
from .federation_proposal_builder import build_signed_proposal
from .federation_assimilation_api import assimilate_signed_proposal

__all__ = ["run_federation_cycle"]


def _candidate_from_dict(data: Dict[str, Any]) -> FederationCandidate:
    """Create a :class:`FederationCandidate` from a plain dictionary.

    The expected keys are a subset of the ``FederationCandidate`` constructor
    arguments.  Missing optional fields are filled with ``None``.
    """
    return FederationCandidate(**data)


def run_federation_cycle(candidates_data: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Execute the full federation pipeline for a list of candidate definitions.

    Parameters
    ----------
    candidates_data:
        A list where each element is a ``dict`` describing a federation
        candidate.  The dict must contain at least the fields required by
        ``FederationCandidate`` (e.g., ``identifier``, ``endpoint``).  Additional
        optional metadata is accepted.

    Returns
    -------
    dict
        Summary of the execution with the following keys:

        * ``total`` – number of candidate definitions received.
        * ``processed`` – candidates that made it through validation.
        * ``assimilated`` – proposals successfully assimilated.
        * ``failed`` – count of candidates that raised an exception at any
          stage.
        * ``errors`` – list of error messages for the failed candidates.
    """
    summary: Dict[str, Any] = {
        "total": len(candidates_data),
        "processed": 0,
        "assimilated": 0,
        "failed": 0,
        "errors": [],
    }

    for raw in candidates_data:
        try:
            candidate = _candidate_from_dict(raw)
            # Step 1: validate connectivity and update tracker state.
            validate_and_track_candidate(candidate)
            summary["processed"] += 1

            # Step 2: build and sign a proposal for the validated candidate.
            signed_proposal = build_signed_proposal(candidate)

            # Step 3: assimilate the signed proposal into the local federation.
            assimilate_signed_proposal(signed_proposal)
            summary["assimilated"] += 1
        except Exception as exc:  # pragma: no cover – exercised by tests.
            summary["failed"] += 1
            summary["errors"].append(str(exc))

    return summary
