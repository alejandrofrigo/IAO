"""omega.federation_assimilation_processor

Módulo de alto nivel que orquesta la asimilación de una propuesta federada.
Incluye:
* Validación de la firma Ed25519 usando la clave pública declarada en la propuesta.
* Actualización del estado interno de la propuesta mediante ``ProposalManager``.
* Registro estructurado de la operación para auditoría.
* Manejo de errores coherente mediante la excepción ``AssimilationError``.

Este módulo cierra la brecha entre los componentes críticos de la infraestructura
federada (``omega.federation``, ``omega.federation_proposals`` y
``omega.federation_assimilation``) y permite que las pruebas verifiquen el flujo
completo de creación, firma y asimilación de propuestas.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any, Dict

# Importes internos de la infraestructura federada
# Se asume que estos módulos existen y están expuestos por el cargador lazy.
from omega.federation_proposal_manager import ProposalManager
from omega.federation_utils import verify_signature_ed25519

_logger = logging.getLogger(__name__)

# Un lock global para garantizar atomicidad en la actualización del estado de la propuesta.
_state_lock = threading.RLock()


class AssimilationError(RuntimeError):
    """Excepción genérica para errores durante la asimilación de una propuesta.

    Se utiliza para diferenciar fallos de lógica de negocio (p.ej. firma inválida,
    propuesta inexistente) de errores de infraestructura que pueden ser reintentados.
    """

    def __init__(self, message: str, *, proposal_id: str | None = None):
        self.proposal_id = proposal_id
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class AssimilationResult:
    """Resultado estructurado de una operación de asimilación.

    Attributes
    ----------
    proposal_id: str
        Identificador único de la propuesta asimilada.
    status: str
        Estado final después de la operación (p.ej. "assimilated").
    details: dict[str, Any]
        Información adicional para auditoría o depuración.
    """

    proposal_id: str
    status: str
    details: Dict[str, Any]


def _load_proposal(proposal_id: str) -> Dict[str, Any]:
    """Obtiene la representación en bruto de la propuesta desde ``ProposalManager``.

    Parameters
    ----------
    proposal_id: str
        ID de la propuesta solicitada.

    Returns
    -------
    dict
        Diccionario con los campos de la propuesta tal como fueron almacenados.

    Raises
    ------
    AssimilationError
        Si la propuesta no existe.
    """
    proposal = ProposalManager.get_proposal(proposal_id)
    if proposal is None:
        raise AssimilationError(
            f"Propuesta con ID '{proposal_id}' no encontrada.", proposal_id=proposal_id
        )
    return proposal


def _verify_proposal_signature(proposal: Dict[str, Any]) -> None:
    """Valida la firma Ed25519 de la propuesta.

    La propuesta se espera que contenga los campos ``payload`` (bytes o str) y
    ``signature`` (bytes) así como ``public_key`` (bytes) que corresponde a la
    clave pública del autor.

    Raises
    ------
    AssimilationError
        Si la firma no se verifica correctamente.
    """
    payload = proposal.get("payload")
    signature = proposal.get("signature")
    public_key = proposal.get("public_key")
    if payload is None or signature is None or public_key is None:
        raise AssimilationError(
            "Propuesta incompleta: faltan payload, signature o public_key.",
            proposal_id=proposal.get("id"),
        )

    # Normalizamos a bytes.
    if isinstance(payload, str):
        payload_bytes = payload.encode("utf-8")
    else:
        payload_bytes = bytes(payload)
    signature_bytes = bytes(signature)
    public_key_bytes = bytes(public_key)

    if not verify_signature_ed25519(public_key_bytes, payload_bytes, signature_bytes):
        raise AssimilationError(
            "Firma Ed25519 de la propuesta no válida.", proposal_id=proposal.get("id")
        )


def assimilate_proposal(proposal_id: str) -> AssimilationResult:
    """Proceso completo de asimilación para una propuesta federada.

    El flujo consiste en:
    1. Cargar la propuesta desde el almacén en memoria.
    2. Verificar su firma Ed25519.
    3. Marcarla como asimilada en ``ProposalManager`` (operación atómica).
    4. Registrar la acción.

    Parameters
    ----------
    proposal_id: str
        Identificador único de la propuesta a asimilar.

    Returns
    -------
    AssimilationResult
        Información estructurada del resultado.

    Raises
    ------
    AssimilationError
        En caso de cualquier fallo de validación o de actualización del estado.
    """
    _logger.debug("Iniciando asimilación de propuesta %s", proposal_id)
    with _state_lock:
        # Paso 1: cargar.
        proposal = _load_proposal(proposal_id)

        # Paso 2: validar firma.
        _verify_proposal_signature(proposal)

        # Paso 3: actualizar estado interno.
        try:
            ProposalManager.mark_assimilated(proposal_id)
        except Exception as exc:  # pragma: no cover – captura genérica para robustez.
            raise AssimilationError(
                f"Fallo al marcar la propuesta {proposal_id} como asimilada: {exc}",
                proposal_id=proposal_id,
            ) from exc

        # Paso 4: registro.
        _logger.info(
            "Propuesta %s asimilada exitosamente (autor: %s)",
            proposal_id,
            proposal.get("author", "desconocido"),
        )

        result = AssimilationResult(
            proposal_id=proposal_id,
            status="assimilated",
            details={
                "author": proposal.get("author"),
                "timestamp": proposal.get("timestamp"),
            },
        )
        return result


# Exportamos los símbolos principales para que el cargador lazy los descubra.
__all__ = [
    "AssimilationError",
    "AssimilationResult",
    "assimilate_proposal",
]
