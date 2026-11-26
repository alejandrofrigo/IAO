# omega/federation_assimilation_api.py
"""API de alto nivel para la asimilación de propuestas federadas.

Esta API combina la verificación criptográfica (Ed25519) de una propuesta
con su registro interno.  Está diseñada para ser utilizada por los flujos de
orquestación federada sin requerir conocimiento interno de los módulos de
verificación ni de la capa de almacenamiento.

Requisitos:
- La propuesta debe ser un diccionario JSON‑serializable con los campos:
  * ``id`` (str): identificador único de la propuesta.
  * ``payload`` (dict): contenido de la propuesta.
  * ``signature`` (str): firma en base64 de ``payload``.
  * ``public_key`` (str): clave pública del firmante en base64 (Ed25519).
- La firma se verifica usando ``nacl.signing.VerifyKey``.
- Propuestas válidas se almacenan en un registro interno en memoria.

El registro es volátil y sirve para pruebas y para que otros componentes
puedan consultar el estado de la asimilación.  En producción podría
reemplazarse por una persistencia a través de ``omega.store``.
"""

from __future__ import annotations

import base64
import json
from typing import Dict, Optional

try:
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError
except ImportError as exc:
    raise ImportError(
        "PyNaCl es requerido para la verificación de firmas Ed25519. "
        "Instale la dependencia con 'pip install pynacl'."
    ) from exc

# Registro interno de propuestas asimiladas (en memoria).
# En un entorno real este diccionario podría delegarse a ``omega.store``.
_ASSIMILATED_PROPOSALS: Dict[str, Dict] = {}

__all__ = [
    "verify_proposal_signature",
    "assimilate_proposal",
    "get_assimilated_proposal",
    "list_assimilated_proposals",
]


def _b64decode(data: str) -> bytes:
    """Decodifica una cadena Base64 aceptando padding opcional."""
    try:
        return base64.b64decode(data + "=" * (-len(data) % 4))
    except Exception as exc:
        raise ValueError("Dato Base64 no válido") from exc


def verify_proposal_signature(proposal: Dict) -> bool:
    """Verifica la firma Ed25519 de una propuesta.

    Parámetros
    ----------
    proposal: dict
        Diccionario que contiene al menos los campos ``payload``, ``signature``
        y ``public_key``.

    Retorna
    -------
    bool
        ``True`` si la firma es válida, ``False`` en caso contrario.
    """
    required_fields = {"payload", "signature", "public_key"}
    if not required_fields.issubset(proposal):
        raise ValueError(f"La propuesta debe contener los campos: {required_fields}")

    # Serializamos el payload de forma determinista (sorted keys) para que la
    # verificación sea reproducible.
    payload_bytes = json.dumps(proposal["payload"], sort_keys=True, separators=(',', ':')).encode()
    signature = _b64decode(proposal["signature"])
    public_key = _b64decode(proposal["public_key"])

    try:
        verify_key = VerifyKey(public_key)
        verify_key.verify(payload_bytes, signature)
        return True
    except BadSignatureError:
        return False
    except Exception as exc:
        raise ValueError("Error al verificar la firma") from exc


def assimilate_proposal(proposal: Dict) -> bool:
    """Verifica y registra una propuesta federada.

    Si la firma es válida, la propuesta se almacena en ``_ASSIMILATED_PROPOSALS``
    bajo su identificador ``id``.  Si la propuesta ya estaba registrada, se
    sobrescribe.

    Parámetros
    ----------
    proposal: dict
        Estructura completa de la propuesta (debe incluir ``id``).

    Retorna
    -------
    bool
        ``True`` si la propuesta fue asimilada correctamente, ``False`` si la
        verificación de firma falló.
    """
    if "id" not in proposal:
        raise ValueError("La propuesta debe contener un campo 'id' único")

    if not verify_proposal_signature(proposal):
        return False

    # Registro interno (volátil).
    _ASSIMILATED_PROPOSALS[proposal["id"]] = proposal
    return True


def get_assimilated_proposal(proposal_id: str) -> Optional[Dict]:
    """Recupera una propuesta asimilada por su identificador.

    Parámetros
    ----------
    proposal_id: str
        Identificador de la propuesta.

    Retorna
    -------
    dict | None
        La propuesta completa si está registrada, de lo contrario ``None``.
    """
    return _ASSIMILATED_PROPOSALS.get(proposal_id)


def list_assimilated_proposals() -> Dict[str, Dict]:
    """Devuelve una copia del diccionario de propuestas asimiladas.
    """
    return dict(_ASSIMILATED_PROPOSALS)
