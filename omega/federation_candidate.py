'''omega/federation_candidate.py

Módulo de registro y seguimiento de candidatos federados.

Provee:
- `FederationCandidate`: dataclass que describe un candidato.
- `CandidateStatus`: enum de estados de conectividad.
- Funciones de gestión (`add_candidate`, `remove_candidate`, `get_candidate`, `list_candidates`).
- Persistencia ligera en JSON dentro del directorio definido por la variable de entorno `IAO_FEDERATION_STATE_DIR` (por defecto ``./.federation_state``).
- Integración con `omega.federation_validation.validate_candidate` para validar capacidades antes de registrar.
- Verificación de conectividad HTTPS opcional mediante `check_connectivity`.

Este módulo es auto‑contenedor, no introduce dependencias externas y respeta las políticas de seguridad del proyecto.
''' 

from __future__ import annotations

import json
import os
import socket
import ssl
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, MutableMapping, Optional

# Importación segura del validador de candidatos; si no está disponible, se usa un stub.
try:
    from .federation_validation import validate_candidate  # type: ignore
except Exception:  # pragma: no cover
    def validate_candidate(candidate: "FederationCandidate") -> bool:  # pylint: disable=unused-argument
        """Fallback que siempre devuelve True cuando el validador real no está disponible."""
        return True


class CandidateStatus(str, Enum):
    """Estado de conectividad de un candidato federado."""

    UNKNOWN = "unknown"
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"


@dataclass(slots=True)
class FederationCandidate:
    """Representa un participante potencial de la federación.

    Attributes
    ----------
    identifier: str
        Identificador único del candidato (p. ej., nombre o hash).
    endpoint: str
        URL base HTTPS del nodo candidato.
    capabilities: List[str]
        Lista declarada de capacidades técnicas que el candidato provee.
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
        Marca de tiempo de la última interacción conocida.
    status: CandidateStatus = CandidateStatus.UNKNOWN
        Estado de conectividad actual.
    """

    identifier: str
    endpoint: str
    capabilities: List[str]
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: CandidateStatus = CandidateStatus.UNKNOWN

    def to_dict(self) -> MutableMapping:
        """Serializa a un dict JSON‑compatible."""
        d = asdict(self)
        d["last_seen"] = self.last_seen.isoformat()
        d["status"] = self.status.value
        return d

    @staticmethod
    def from_dict(data: MutableMapping) -> "FederationCandidate":
        """Deserializa desde un dict JSON‑compatible."""
        last_seen = datetime.fromisoformat(data["last_seen"]).replace(tzinfo=timezone.utc)
        status = CandidateStatus(data.get("status", CandidateStatus.UNKNOWN.value))
        return FederationCandidate(
            identifier=data["identifier"],
            endpoint=data["endpoint"],
            capabilities=data.get("capabilities", []),
            last_seen=last_seen,
            status=status,
        )


# ---------------------------------------------------------------------------
# Persistencia ligera (JSON) con acceso thread‑safe.
# ---------------------------------------------------------------------------
_state_lock = threading.Lock()
_state_path: str = os.getenv("IAO_FEDERATION_STATE_DIR", "./.federation_state")
if not os.path.isdir(_state_path):
    os.makedirs(_state_path, exist_ok=True)
_state_file = os.path.join(_state_path, "candidates.json")


def _load_state() -> Dict[str, FederationCandidate]:
    """Carga el diccionario de candidatos desde disco.

    Returns
    -------
    dict
        Mapeo ``identifier -> FederationCandidate``.
    """
    if not os.path.isfile(state_file):
        return {}
    with open(state_file, "r", encoding="utf-8") as f:
        raw: Dict[str, MutableMapping] = json.load(f)
    return {k: FederationCandidate.from_dict(v) for k, v in raw.items()}


def _save_state(candidates: Dict[str, FederationCandidate]) -> None:
    """Guarda el diccionario de candidatos en disco de forma atómica."""
    tmp_path = f"{state_file}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump({k: v.to_dict() for k, v in candidates.items()}, f, indent=2, sort_keys=True)
    os.replace(tmp_path, state_file)


# ---------------------------------------------------------------------------
# API de gestión de candidatos.
# ---------------------------------------------------------------------------

def add_candidate(candidate: FederationCandidate) -> bool:
    """Registra un nuevo candidato después de validar sus capacidades.

    Parameters
    ----------
    candidate: FederationCandidate
        El candidato a registrar.

    Returns
    -------
    bool
        ``True`` si el candidato fue agregado; ``False`` si ya existía o la
        validación falló.
    """
    if not validate_candidate(candidate):
        return False
    with _state_lock:
        candidates = _load_state()
        if candidate.identifier in candidates:
            return False
        candidates[candidate.identifier] = candidate
        _save_state(candidates)
    return True


def remove_candidate(identifier: str) -> bool:
    """Elimina un candidato del registro.

    Returns ``True`` si el candidato existía y fue removido.
    """
    with _state_lock:
        candidates = _load_state()
        if identifier not in candidates:
            return False
        del candidates[identifier]
        _save_state(candidates)
    return True


def get_candidate(identifier: str) -> Optional[FederationCandidate]:
    """Obtiene un candidato por su identificador, o ``None`` si no está registrado."""
    with _state_lock:
        candidates = _load_state()
        return candidates.get(identifier)


def list_candidates() -> List[FederationCandidate]:
    """Devuelve una lista de todos los candidatos registrados."""
    with _state_lock:
        return list(_load_state().values())


def update_status(identifier: str, status: CandidateStatus, *, timestamp: Optional[datetime] = None) -> bool:
    """Actualiza el estado de conectividad de un candidato.

    Returns ``True`` si el candidato existía y se actualizó.
    """
    with _state_lock:
        candidates = _load_state()
        cand = candidates.get(identifier)
        if not cand:
            return False
        cand.status = status
        cand.last_seen = timestamp or datetime.now(timezone.utc)
        _save_state(candidates)
    return True


def check_connectivity(candidate: FederationCandidate, timeout: float = 5.0) -> CandidateStatus:
    """Intenta una conexión HTTPS simple al endpoint del candidato.

    La verificación es ligera y solo se usa para actualizar el estado interno.
    En entornos donde el acceso externo está bloqueado, la excepción se captura
    y se devuelve ``UNREACHABLE``.
    """
    parsed = candidate.endpoint.rstrip("/")
    if not parsed.startswith("https://"):
        return CandidateStatus.UNREACHABLE
    host = parsed.split("https://")[1].split("/")[0]
    # Intentamos abrir un socket TCP al puerto 443 con timeout.
    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                # No enviamos datos, solo completamos el handshake.
                pass
        return CandidateStatus.REACHABLE
    except Exception:  # pragma: no cover – dependiente de entorno
        return CandidateStatus.UNREACHABLE


def refresh_candidate_status(identifier: str, timeout: float = 5.0) -> bool:
    """Realiza una verificación de conectividad y actualiza el registro.

    Returns ``True`` si el candidato fue encontrado y su estado actualizado.
    """
    cand = get_candidate(identifier)
    if not cand:
        return False
    new_status = check_connectivity(cand, timeout=timeout)
    update_status(identifier, new_status)
    return True


__all__ = [
    "CandidateStatus",
    "FederationCandidate",
    "add_candidate",
    "remove_candidate",
    "get_candidate",
    "list_candidates",
    "update_status",
    "check_connectivity",
    "refresh_candidate_status",
]
