"""Federation Tracker

Este módulo gestiona el ciclo de vida de los candidatos federados, manteniendo
información sobre su estado (p. ej., descubiertos, validados, propuestos,
asimilados, revocados). Provee una API de registro y consulta basada en un
almacenamiento en memoria thread‑safe.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, asdict
from enum import Enum, auto
from typing import Dict, List, Optional


class CandidateState(Enum):
    DISCOVERED = auto()
    VALIDATED = auto()
    PROPOSAL_CREATED = auto()
    ASSIMILATED = auto()
    REVOKED = auto()


@dataclass(frozen=True)
class CandidateRecord:
    candidate_id: str
    state: CandidateState
    metadata: Dict[str, str]


class FederationTracker:
    """Thread‑safe registry for federation candidates.

    The tracker stores :class:`CandidateRecord` instances keyed by candidate_id.
    It offers basic CRUD operations and utilities for querying the current
    registry.  All mutating operations acquire an internal lock to guarantee
    consistency when accessed from concurrent contexts (e.g., discovery
    threads, validation workers, or orchestration routines).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._registry: Dict[str, CandidateRecord] = {}

    # ---------------------------------------------------------------------
    # Mutating operations
    # ---------------------------------------------------------------------
    def add_candidate(self, candidate_id: str, metadata: Optional[Dict[str, str]] = None) -> None:
        """Register a new candidate.

        If the candidate already exists the call is ignored – the caller can
        decide whether to update via :meth:`update_state`.
        """
        if metadata is None:
            metadata = {}
        with self._lock:
            if candidate_id not in self._registry:
                self._registry[candidate_id] = CandidateRecord(
                    candidate_id=candidate_id,
                    state=CandidateState.DISCOVERED,
                    metadata=metadata,
                )

    def update_state(self, candidate_id: str, new_state: CandidateState) -> None:
        """Transition a candidate to *new_state*.

        Raises
        ------
        KeyError
            If the candidate is unknown.
        """
        with self._lock:
            record = self._registry[candidate_id]
            self._registry[candidate_id] = CandidateRecord(
                candidate_id=record.candidate_id,
                state=new_state,
                metadata=record.metadata,
            )

    def set_metadata(self, candidate_id: str, metadata: Dict[str, str]) -> None:
        """Replace the metadata dictionary for *candidate_id*.

        Raises
        ------
        KeyError
            If the candidate is unknown.
        """
        with self._lock:
            record = self._registry[candidate_id]
            self._registry[candidate_id] = CandidateRecord(
                candidate_id=record.candidate_id,
                state=record.state,
                metadata=metadata,
            )

    # ---------------------------------------------------------------------
    # Query operations
    # ---------------------------------------------------------------------
    def get_candidate(self, candidate_id: str) -> CandidateRecord:
        """Return the stored :class:`CandidateRecord` for *candidate_id*.

        Raises
        ------
        KeyError
            If the candidate does not exist.
        """
        with self._lock:
            return self._registry[candidate_id]

    def list_candidates(self) -> List[Dict[str, object]]:
        """Return a **summary list** of all registered candidates.

        The returned list contains plain dictionaries that are safe to serialize
        to JSON, e.g. ::

            [
                {"candidate_id": "node-1", "state": "VALIDATED", "metadata": {"ip": "10.0.0.5"}},
                {"candidate_id": "node-2", "state": "DISCOVERED", "metadata": {}},
            ]

        This helper is intentionally lightweight and does not expose the
        internal ``CandidateRecord`` objects, preserving encapsulation while
        providing the information needed by monitoring tools and test suites.
        """
        with self._lock:
            return [
                {
                    "candidate_id": rec.candidate_id,
                    "state": rec.state.name,
                    "metadata": rec.metadata,
                }
                for rec in self._registry.values()
            ]

    def filter_by_state(self, state: CandidateState) -> List[CandidateRecord]:
        """Return a list of records whose ``state`` matches *state*.
        """
        with self._lock:
            return [rec for rec in self._registry.values() if rec.state == state]

    # ---------------------------------------------------------------------
    # Maintenance utilities
    # ---------------------------------------------------------------------
    def purge(self) -> None:
        """Remove **all** entries from the tracker.

        Primarily used in test setups to ensure a clean environment.
        """
        with self._lock:
            self._registry.clear()


# -------------------------------------------------------------------------
# Public singleton instance
# -------------------------------------------------------------------------
_tracker_instance = FederationTracker()

__all__ = [
    "CandidateState",
    "CandidateRecord",
    "FederationTracker",
    "_tracker_instance",
]
