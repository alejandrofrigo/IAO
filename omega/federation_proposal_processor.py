"""omega.federation_proposal_processor

Este módulo provee una capa de orquestación de alto nivel para el manejo de propuestas
federadas. Combina la validación estructural, la verificación de firmas Ed25519 y el
registro interno de propuestas aceptadas.

Uso típico:

    from omega.federation_proposal_processor import process_proposal

    proposal_id = process_proposal(proposal_dict, authority_public_key)

Si la propuesta es válida y la firma verifica, la función devuelve el identificador
único de la propuesta y la registra en un registro interno in‑memoria. En caso de
error se lanza ``ValueError`` descriptivo.
"""

from __future__ import annotations

import json
import threading
from typing import Any, Dict, List

# Importaciones de módulos existentes que proveen funcionalidades especializadas.
# Se asume que estos módulos existen y exportan las funciones indicadas.
from .federation_proposal_utils import (
    validate_structure as _validate_structure,
    compute_proposal_id as _compute_proposal_id,
)
from .federation_assimilation_verifier import verify_signature as _verify_signature

# ---------------------------------------------------------------------------
# Registro interno de propuestas aprobadas.
# ---------------------------------------------------------------------------
# Utilizamos un lock para garantizar la seguridad en entornos multihilo.
_registry_lock = threading.RLock()
_registry: Dict[str, Dict[str, Any]] = {}


def _register_proposal(proposal_id: str, proposal: Dict[str, Any]) -> None:
    """Añade la propuesta al registro interno.

    Esta operación es atómica y está protegida por ``_registry_lock``.
    Si ya existe una propuesta con el mismo identificador se sobrescribe, lo cual
    es aceptable porque el identificador es determinístico y depende del contenido
    de la propuesta; una colisión indica que el contenido es idéntico.
    """
    with _registry_lock:
        _registry[proposal_id] = proposal


def get_proposal(proposal_id: str) -> Dict[str, Any] | None:
    """Obtiene una propuesta previamente registrada.

    Returns
    -------
    dict | None
        El diccionario de la propuesta si está presente, de lo contrario ``None``.
    """
    with _registry_lock:
        return _registry.get(proposal_id)


def list_proposals() -> List[str]:
    """Devuelve la lista de identificadores de propuestas registradas."""
    with _registry_lock:
        return list(_registry.keys())


def process_proposal(proposal: Dict[str, Any], authority_public_key: bytes) -> str:
    """Valida, verifica y registra una propuesta federada.

    Parámetros
    ----------
    proposal: dict
        Representación JSON‑compatible de la propuesta. Debe contener al menos los
        campos ``payload`` (cualquier objeto serializable) y ``signature`` (bytes
        codificados en base64 o ``bytes`` directamente).
    authority_public_key: bytes
        Clave pública Ed25519 del ente de autoridad que firmó la propuesta.

    Returns
    -------
    str
        El identificador único (hash) de la propuesta.

    Levanta
    ------
    ValueError
        Si la propuesta no cumple con la estructura esperada o la firma es
        inválida.
    """
    # 1. Validación estructural básica.
    try:
        _validate_structure(proposal)
    except Exception as exc:
        raise ValueError(f"Estructura de propuesta inválida: {exc}") from exc

    # 2. Cálculo determinístico del identificador.
    try:
        proposal_id = _compute_proposal_id(proposal)
    except Exception as exc:
        raise ValueError(f"No se pudo calcular el identificador de la propuesta: {exc}") from exc

    # 3. Verificación criptográfica de la firma.
    signature = proposal.get("signature")
    payload = proposal.get("payload")
    if signature is None:
        raise ValueError("La propuesta carece del campo 'signature'.")
    if payload is None:
        raise ValueError("La propuesta carece del campo 'payload'.")

    # La función de verificación espera los bytes del payload y la firma.
    # Se asume que el payload es serializable a JSON.
    try:
        payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except Exception as exc:
        raise ValueError(f"No se pudo serializar el payload de la propuesta: {exc}") from exc

    if not _verify_signature(payload_bytes, signature, authority_public_key):
        raise ValueError("Firma Ed25519 de la propuesta no es válida.")

    # 4. Registro interno.
    _register_proposal(proposal_id, proposal)
    return proposal_id

# Exportamos los símbolos públicos esperados por el lazy loader.
__all__ = [
    "process_proposal",
    "get_proposal",
    "list_proposals",
]
