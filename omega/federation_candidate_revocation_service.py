"""omega.federation_candidate_revocation_service

Servicio de revocación de candidatos federados.

Este módulo provee una API de alto nivel para marcar candidatos como revocados
y consultar su estado de revocación. La información se mantiene en memoria
(sólo válida durante la vida del proceso) y está protegida por un lock para
ser thread‑safe.

Uso típico:
    from omega.federation_candidate_revocation_service import (
        revoke_candidate,
        is_candidate_revoked,
    )

    revoke_candidate('candidate-123')
    assert is_candidate_revoked('candidate-123')

Esta funcionalidad complementa los módulos existentes de descubrimiento, validación
y registro de candidatos, completando el ciclo de vida de un participante federado.
"""

from __future__ import annotations

import threading
from typing import Set

# ---------------------------------------------------------------------------
# Estado interno (in‑memory). En una instalación real este estado debería
# persistirse en un almacén confiable (por ejemplo, base de datos o registro de
# auditoría). Para los propósitos de la prueba y la demostración, mantenemos los
# datos en una estructura de conjunto protegida por un lock.
# ---------------------------------------------------------------------------
_revoked_candidates: Set[str] = set()
_lock = threading.RLock()


def revoke_candidate(candidate_id: str) -> None:
    """Marca el candidato indicado como revocado.

    Args:
        candidate_id: Identificador único del candidato a revocar.

    La operación es idempotente; revocar un candidato ya revocado no produce
    error.
    """
    if not isinstance(candidate_id, str) or not candidate_id:
        raise ValueError("candidate_id must be a non‑empty string")
    with _lock:
        _revoked_candidates.add(candidate_id)


def is_candidate_revoked(candidate_id: str) -> bool:
    """Comprueba si el candidato ha sido revocado.

    Args:
        candidate_id: Identificador único del candidato.

    Returns:
        True si el candidato está en la lista de revocados, False en caso
        contrario.
    """
    if not isinstance(candidate_id, str) or not candidate_id:
        raise ValueError("candidate_id must be a non‑empty string")
    with _lock:
        return candidate_id in _revoked_candidates


def list_revoked_candidates() -> Set[str]:
    """Devuelve una copia inmutable del conjunto de candidatos revocados.

    Esto permite inspeccionar el estado actual sin exponer la estructura interna
    mutable.
    """
    with _lock:
        return frozenset(_revoked_candidates)

# Exportación explícita para que el lazy‑loader del paquete ``omega`` lo incluya
# automáticamente al detectar el prefijo ``federation``.
__all__ = [
    "revoke_candidate",
    "is_candidate_revoked",
    "list_revoked_candidates",
]
