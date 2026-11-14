"""Batch processing utilities for federation candidates.

This module defines :class:`FederationBatchProcessor` which orchestrates the
high‑level ``submit_federation_candidate`` workflow for an iterable of candidate
specifications.  Each candidate is processed independently; successes and
failures are captured and returned as a list of result dictionaries.

The implementation purposefully avoids any network side‑effects beyond what
the underlying ``submit_federation_candidate`` performs, and it never swallows
unexpected exceptions – they are recorded in the result for diagnostic
purposes.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

# The high‑level entrypoint is provided by ``omega.federation_entrypoint``.
# Import it lazily to avoid circular import problems.
try:
    from .federation_entrypoint import submit_federation_candidate  # type: ignore
except Exception:  # pragma: no cover
    # In environments where the entrypoint is not available we expose a stub
    # that raises a clear error when used.
    def submit_federation_candidate(*_args: Any, **_kwargs: Any) -> Any:  # type: ignore
        raise RuntimeError(
            "submit_federation_candidate is unavailable – the federation "
            "entrypoint could not be imported."
        )


class FederationBatchProcessor:
    """Process multiple federation candidates in a batch.

    Parameters
    ----------
    candidates: Iterable[Dict[str, Any]]
        An iterable yielding candidate descriptors.  Each descriptor is passed
        directly to :func:`submit_federation_candidate`.
    """

    def __init__(self, candidates: Iterable[Dict[str, Any]]):
        self._candidates = list(candidates)

    def process(self) -> List[Dict[str, Any]]:
        """Execute the federation workflow for each candidate.

        Returns
        -------
        List[Dict[str, Any]]
            A list with one entry per input candidate.  Each entry contains at
            least the keys ``candidate`` (the original descriptor) and ``status``
            (``"success"`` or ``"error"``).  On error an additional ``error`` key
            holds the string representation of the exception.
        """
        results: List[Dict[str, Any]] = []
        for cand in self._candidates:
            try:
                # The entrypoint returns a proposal object or raises on failure.
                proposal = submit_federation_candidate(cand)
                results.append({
                    "candidate": cand,
                    "status": "success",
                    "proposal": proposal,
                })
            except Exception as exc:  # pylint: disable=broad-except
                results.append({
                    "candidate": cand,
                    "status": "error",
                    "error": str(exc),
                })
        return results
