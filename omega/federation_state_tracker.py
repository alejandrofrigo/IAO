"""Omega Federation State Tracker

Este módulo proporciona una capa ligera y en‑memoria para el registro y la gestión
ciclo‑vida de propuestas federadas dentro del proceso IAO. Permite registrar
propuestas, obtenerlas mediante su identificador, listarlas y revocarlas de forma
segura usando un bloqueo de threading para garantizar consistencia en entornos
concurridos.

El tracker está pensado como un componente interno utilizado por los servicios
de orquestación (p. ej., ``federation_candidate_service`` o ``federation_proposal_service``)
pero también es útil para pruebas unitarias que requieren inspeccionar el
estado sin acceder a persistencia externa.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional


class ProposalStatus(Enum):
    """Estados posibles de una propuesta federada."""

    PENDING = auto()
    ACCEPTED = auto()
    REVOKED = auto()
    EXPIRED = auto()


@dataclass(frozen=True)
class ProposalRecord:
    """Representación inmutable de una propuesta almacenada en el tracker.

    Attributes
    ----------
    proposal_id: str
        Identificador único (hash) de la propuesta.
    payload: dict
        Contenido original de la propuesta (se almacena tal cual se recibió).
    status: ProposalStatus
        Estado actual de la propuesta.
    """

    proposal_id: str
    payload: dict
    status: ProposalStatus = field(default=ProposalStatus.PENDING)


class _FederationStateTracker:
    """Implementación singleton del tracker de propuestas.

    Se utiliza un lock para proteger el acceso concurrente a la estructura interna
    ``_store`` que mantiene los registros por ``proposal_id``.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._store: Dict[str, ProposalRecord] = {}

    def add_proposal(self, proposal_id: str, payload: dict) -> None:
        """Registra una nueva propuesta con estado *PENDING*.

        Si el ``proposal_id`` ya existe, se sobrescribe el registro manteniendo el
        estado anterior (para permitir actualizaciones controladas).
        """
        with self._lock:
            self._store[proposal_id] = ProposalRecord(
                proposal_id=proposal_id, payload=payload, status=ProposalStatus.PENDING
            )

    def get_proposal(self, proposal_id: str) -> Optional[ProposalRecord]:
        """Obtiene el registro de una propuesta o ``None`` si no está presente."""
        with self._lock:
            return self._store.get(proposal_id)

    def list_proposals(self, status: Optional[ProposalStatus] = None) -> List[ProposalRecord]:
        """Devuelve todas las propuestas, opcionalmente filtradas por ``status``."""
        with self._lock:
            if status is None:
                return list(self._store.values())
            return [rec for rec in self._store.values() if rec.status == status]

    def set_status(self, proposal_id: str, new_status: ProposalStatus) -> bool:
        """Actualiza el estado de una propuesta existente.

        Retorna ``True`` si la actualización tuvo éxito, ``False`` si la propuesta
        no se encontró.
        """
        with self._lock:
            record = self._store.get(proposal_id)
            if record is None:
                return False
            # Reemplazamos el registro inmutable con uno nuevo que lleva el nuevo estado.
            self._store[proposal_id] = ProposalRecord(
                proposal_id=record.proposal_id, payload=record.payload, status=new_status
            )
            return True

    def revoke_proposal(self, proposal_id: str) -> bool:
        """Marca una propuesta como *REVOKED*.

        Es equivalente a ``set_status`` con ``ProposalStatus.REVOKED``.
        """
        return self.set_status(proposal_id, ProposalStatus.REVOKED)

    def clear(self) -> None:
        """Elimina todos los registros del tracker (útil para pruebas)."""
        with self._lock:
            self._store.clear()


# Instancia global única del tracker a usar por toda la aplicación.
_federation_state_tracker = _FederationStateTracker()


def add_proposal(proposal_id: str, payload: dict) -> None:
    """API de alto nivel para registrar una propuesta.

    Parámetros
    ----------
    proposal_id: str
        Identificador calculado previamente (por ejemplo, hash SHA‑256 del JSON).
    payload: dict
        Estructura completa de la propuesta.
    """
    _federation_state_tracker.add_proposal(proposal_id, payload)


def get_proposal(proposal_id: str) -> Optional[ProposalRecord]:
    """Obtiene un registro de propuesta mediante su ID."""
    return _federation_state_tracker.get_proposal(proposal_id)


def list_proposals(status: Optional[ProposalStatus] = None) -> List[ProposalRecord]:
    """Lista todas las propuestas, opcionalmente filtradas por ``status``."""
    return _federation_state_tracker.list_proposals(status)


def revoke_proposal(proposal_id: str) -> bool:
    """Revoca la propuesta indicada, cambiando su estado a ``REVOKED``.

    Devuelve ``True`` si la propuesta existía y fue revocada, ``False`` en caso
    contrario.
    """
    return _federation_state_tracker.revoke_proposal(proposal_id)


def clear_tracker() -> None:
    """Borra todo el contenido del tracker. Sólo debe usarse en entornos de test."""
    _federation_state_tracker.clear()
