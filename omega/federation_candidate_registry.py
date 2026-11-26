"""Omega Federation Candidate Registry

Este módulo provee un registro thread‑safe para almacenar y gestionar el
estado de los candidatos federados descubiertos en la red. Cada candidato
está identificado por un `candidate_id` (string) y tiene un diccionario de
metadatos que incluye información esencial como:

- `status`: uno de "discovered", "validated", "connected", "revoked".
- `discovered_at`: timestamp ISO 8601 de cuándo se descubrió.
- `validated_at`: timestamp opcional de validación.
- `info`: datos arbitrarios proporcionados por los procesos de descubrimiento
  o validación (por ejemplo, direcciones, capacidades, firma, etc.).

El registro está pensado para ser utilizado por los módulos de descubrimiento,
validación y asimilación, ofreciendo una única fuente de verdad para el
ciclo de vida de cada candidato.

Ejemplo de uso::

    from omega.federation_candidate_registry import (
        register_candidate,
        update_candidate_status,
        get_candidate,
        list_candidates,
        revoke_candidate,
    )

    register_candidate("candidate-123", {"info": {"host": "example.com"}})
    update_candidate_status("candidate-123", "validated")
    info = get_candidate("candidate-123")
    revoke_candidate("candidate-123")

"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

__all__ = [
    "register_candidate",
    "update_candidate_status",
    "get_candidate",
    "list_candidates",
    "revoke_candidate",
    "CandidateRegistry",
]


class CandidateRegistry:
    """Registro thread‑safe para candidatos federados.

    Internamente mantiene un diccionario ``_store`` cuyo clave es el
    ``candidate_id`` y cuyo valor es un diccionario con los metadatos del
    candidato.
    """

    def __init__(self) -> None:
        self._store: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()

    # ---------------------------------------------------------------------
    # API pública
    # ---------------------------------------------------------------------
    def register(self, candidate_id: str, info: Optional[Dict[str, Any]] = None) -> None:
        """Registrar un nuevo candidato.

        Si el candidato ya existe se lanza ``ValueError`` para evitar
        sobrescritura accidental.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        with self._lock:
            if candidate_id in self._store:
                raise ValueError(f"Candidate '{candidate_id}' already registered")
            self._store[candidate_id] = {
                "status": "discovered",
                "discovered_at": timestamp,
                "validated_at": None,
                "connected_at": None,
                "revoked_at": None,
                "info": info or {},
            }

    def update_status(self, candidate_id: str, new_status: str) -> None:
        """Actualizar el estado de un candidato existente.

        ``new_status`` debe ser uno de los valores aceptados; se valida
        mínimamente y se actualizan los timestamps asociados.
        """
        valid_statuses = {"discovered", "validated", "connected", "revoked"}
        if new_status not in valid_statuses:
            raise ValueError(f"Invalid status '{new_status}'. Valid: {valid_statuses}")
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._lock:
            if candidate_id not in self._store:
                raise KeyError(f"Candidate '{candidate_id}' not found")
            entry = self._store[candidate_id]
            entry["status"] = new_status
            if new_status == "validated":
                entry["validated_at"] = now_iso
            elif new_status == "connected":
                entry["connected_at"] = now_iso
            elif new_status == "revoked":
                entry["revoked_at"] = now_iso

    def revoke(self, candidate_id: str) -> None:
        """Marcar un candidato como revocado.

        Equivale a ``update_status(..., "revoked")`` pero con semántica explícita.
        """
        self.update_status(candidate_id, "revoked")

    def get(self, candidate_id: str) -> Dict[str, Any]:
        """Obtener la información completa de un candidato.

        Se devuelve una copia para evitar mutaciones externas.
        """
        with self._lock:
            if candidate_id not in self._store:
                raise KeyError(f"Candidate '{candidate_id}' not found")
            # Copia superficial (los valores internos son inmutables o controlados)
            return dict(self._store[candidate_id])

    def list_all(self) -> List[Dict[str, Any]]:
        """Listar información de todos los candidatos registrados.
        """
        with self._lock:
            return [dict(entry) for entry in self._store.values()]

    def exists(self, candidate_id: str) -> bool:
        """Comprobar si un candidato está registrado.
        """
        with self._lock:
            return candidate_id in self._store

    # ---------------------------------------------------------------------
    # Métodos auxiliares (no expuestos directamente)
    # ---------------------------------------------------------------------
    def _clear(self) -> None:
        """Vaciar el registro. Utilizado exclusivamente en pruebas.
        """
        with self._lock:
            self._store.clear()


# Instancia singleton utilizada por el resto del código
_registry = CandidateRegistry()


def register_candidate(candidate_id: str, info: Optional[Dict[str, Any]] = None) -> None:
    """Conveniencia: registrar un candidato en el registro global.
    """
    _registry.register(candidate_id, info)


def update_candidate_status(candidate_id: str, new_status: str) -> None:
    """Conveniencia: actualizar el estado de un candidato en el registro global.
    """
    _registry.update_status(candidate_id, new_status)


def revoke_candidate(candidate_id: str) -> None:
    """Conveniencia: revocar un candidato en el registro global.
    """
    _registry.revoke(candidate_id)


def get_candidate(candidate_id: str) -> Dict[str, Any]:
    """Conveniencia: obtener datos de un candidato del registro global.
    """
    return _registry.get(candidate_id)


def list_candidates() -> List[Dict[str, Any]]:
    """Conveniencia: listar todos los candidatos del registro global.
    """
    return _registry.list_all()
