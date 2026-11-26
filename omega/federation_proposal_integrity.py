'''omega.federation_proposal_integrity

Módulo de soporte que provee una verificación combinada de integridad para
propuestas federadas. Se asegura de que:

1. La propuesta esté firmada correctamente con Ed25519 (usando el verificador
   existente en ``omega.federation_proposal_verifier``).
2. La propuesta no haya sido revocada previamente (consultando el almacén
   persistente en ``omega.federation_proposal_store``).

Esta función se puede invocar desde ``omega.federation_assimilation`` antes de
asumir una propuesta, garantizando que sólo propuestas válidas y activas sean
asimiladas.
''' 

from __future__ import annotations

import json
from typing import Any, Dict

# Importamos los componentes existentes de firma y almacenamiento.
# Estos módulos existen en el repositorio según el historial de PADGE.
from .federation_proposal_verifier import verify_signature
from .federation_proposal_store import ProposalStore

__all__ = ["verify_proposal_integrity"]


def _load_proposal_data(proposal: Dict[str, Any] | str) -> Dict[str, Any]:
    """Normaliza la propuesta a un diccionario.

    La propuesta puede recibirse como dict ya parseado o como cadena JSON.
    """
    if isinstance(proposal, dict):
        return proposal
    try:
        return json.loads(proposal)
    except json.JSONDecodeError as exc:
        raise ValueError("Propuesta no es un JSON válido") from exc


def verify_proposal_integrity(proposal: Dict[str, Any] | str) -> bool:
    """Verifica la integridad completa de una propuesta federada.

    Parámetros
    ----------
    proposal: dict o str
        Representación de la propuesta. Si es una cadena, se interpretará como
        JSON.

    Retorna
    -------
    bool
        ``True`` si la firma es válida y la propuesta no está revocada.
        Lanza ``ValueError`` si la estructura es inválida o la firma falla.
    """
    # Normalizamos la entrada.
    data = _load_proposal_data(proposal)

    # 1. Verificación criptográfica de la firma.
    # Se asume que ``verify_signature`` lanza excepción si la firma es inválida.
    verify_signature(data)

    # 2. Verificación de revocación.
    proposal_id = data.get("proposal_id")
    if not proposal_id:
        raise ValueError("La propuesta debe contener el campo 'proposal_id'.")

    store = ProposalStore()
    # El método ``get`` devuelve el registro completo o ``None``.
    record = store.get(proposal_id)
    if record is None:
        # Si no existe registro, consideramos que no está revocada.
        return True

    # Se espera un campo booleano ``revoked`` en el registro.
    if record.get("revoked", False):
        raise ValueError(f"La propuesta {proposal_id!s} ha sido revocada.")

    return True
