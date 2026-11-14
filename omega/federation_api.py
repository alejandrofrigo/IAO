"""Omega Federation High‑Level API

Este módulo expone una única función de entrada, ``process_proposal``, que
orquesta todo el ciclo de vida de una propuesta federada:

1. **Validación estructural** – Se comprueba que la propuesta sea un ``dict``
   y contenga los campos obligatorios ``id``, ``payload``, ``signature`` y
   ``public_key``.
2. **Verificación criptográfica** – La firma Ed25519 del ``payload`` se
   verifica frente a la clave pública provista. Se utiliza la implementación
   estándar de ``cryptography`` para evitar dependencias externas.
3. **Asimilación / Registro** – Si la propuesta es válida, se almacena en
   un registro interno en‑memoria que permite consultas, listados y revocación
   posterior.

El registro es un diccionario privado mantenido dentro de este módulo, lo que
garantiza que la información persista sólo mientras el proceso está activo y
no se expone fuera de los límites de la API pública.

Esta capa unifica la lógica dispersa en ``omega.federation``,
``omega.federation_proposals`` y ``omega.federation_assimilation`` sin modificar
esos módulos, facilitando pruebas automáticas y futuros enlaces con
implementaciones persistentes.
"""

from __future__ import annotations

import json
import base64
from typing import Dict, Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

# Registro interno de propuestas aceptadas.
# Clave: proposal.id  →  valor: la propuesta completa (dict).
_proposal_store: Dict[str, Dict[str, Any]] = {}

__all__ = ["process_proposal", "get_proposal", "list_proposals", "revoke_proposal"]


def _validate_structure(proposal: Dict[str, Any]) -> None:
    """Comprueba que la propuesta contenga los campos obligatorios.

    Lanza ``ValueError`` si falta alguno o si el tipo no es ``dict``.
    """
    required = {"id", "payload", "signature", "public_key"}
    if not isinstance(proposal, dict):
        raise ValueError("La propuesta debe ser un diccionario JSON‑serializable.")
    missing = required - proposal.keys()
    if missing:
        raise ValueError(f"Campos obligatorios ausentes en la propuesta: {missing}")

    # Tipos básicos de los campos.
    if not isinstance(proposal["id"], str):
        raise ValueError("El campo 'id' debe ser una cadena.")
    if not isinstance(proposal["payload"], dict):
        raise ValueError("El campo 'payload' debe ser un diccionario.")
    if not isinstance(proposal["signature"], str):
        raise ValueError("El campo 'signature' debe ser una cadena base64.")
    if not isinstance(proposal["public_key"], str):
        raise ValueError("El campo 'public_key' debe ser una cadena base64.")


def _verify_signature(proposal: Dict[str, Any]) -> None:
    """Verifica la firma Ed25519 del payload.

    La firma se espera codificada en base64 y el ``public_key`` también en
    base64. El mensaje firmado es la representación canónica JSON del payload
    (orden de claves garantizado mediante ``sort_keys=True``).
    """
    signature_b64 = proposal["signature"]
    public_key_b64 = proposal["public_key"]
    try:
        signature = base64.b64decode(signature_b64)
        public_key_bytes = base64.b64decode(public_key_b64)
    except Exception as exc:
        raise ValueError("Codificación base64 inválida en firma o clave pública") from exc

    # Serializamos el payload de forma determinista.
    payload_json = json.dumps(proposal["payload"], sort_keys=True, separators=(",", ":")).encode()

    try:
        pub_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        pub_key.verify(signature, payload_json)
    except InvalidSignature as exc:
        raise ValueError("Firma criptográfica inválida para la propuesta") from exc
    except Exception as exc:
        raise ValueError("Error al procesar la clave pública Ed25519") from exc


def _store_proposal(proposal: Dict[str, Any]) -> None:
    """Registra la propuesta en el almacén interno.

    Si ya existe una propuesta con el mismo ``id`` se sobrescribe, ya que la
    lógica de revocación debe gestionar explícitamente los conflictos.
    """
    _proposal_store[proposal["id"]] = proposal.copy()


def process_proposal(proposal: Dict[str, Any]) -> Dict[str, Any]:
    """Proceso completo de una propuesta federada.

    1. Validación estructural.
    2. Verificación de firma Ed25519.
    3. Registro interno.

    Devuelve la propuesta tal como se ha registrado (copia profunda).
    Lanza ``ValueError`` con mensaje descriptivo si cualquier paso falla.
    """
    _validate_structure(proposal)
    _verify_signature(proposal)
    _store_proposal(proposal)
    # Devolvemos una copia para evitar mutaciones externas.
    return _proposal_store[proposal["id"]].copy()


def get_proposal(proposal_id: str) -> Dict[str, Any] | None:
    """Obtiene una propuesta registrada por su identificador.

    Retorna ``None`` si no se encontró.
    """
    proposal = _proposal_store.get(proposal_id)
    return proposal.copy() if proposal is not None else None


def list_proposals() -> Dict[str, Dict[str, Any]]:
    """Devuelve un snapshot del registro completo de propuestas.

    El resultado es un diccionario ``id -> propuesta`` donde cada propuesta es
    una copia para preservar la inmutabilidad del almacén interno.
    """
    return {pid: prop.copy() for pid, prop in _proposal_store.items()}


def revoke_proposal(proposal_id: str) -> bool:
    """Revoca (elimina) una propuesta previamente registrada.

    Devuelve ``True`` si la propuesta existía y fue eliminada, ``False`` en caso
    contrario.
    """
    return _proposal_store.pop(proposal_id, None) is not None
