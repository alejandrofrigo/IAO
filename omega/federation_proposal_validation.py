"""Utilities for validating and verifying federation proposals.

Este módulo provee dos funciones principales:

1. ``validate_proposal_structure`` – garantiza que un diccionario de propuesta
   contenga los campos obligatorios y que sus tipos sean los esperados.
2. ``verify_proposal_signature`` – verifica la firma Ed25519 del creador
   utilizando la clave pública incluida en la propuesta.

Ambas funciones son utilizadas por los procesos de asimilación y gestión de
propuestas para asegurar que sólo se acepten propuestas bien formadas y
autenticadas.
"""

from __future__ import annotations

import json
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

# Campos obligatorios de una propuesta federada y sus tipos esperados.
_REQUIRED_FIELDS = {
    "id": str,
    "creator_pubkey": (bytes, str),  # Puede ser bytes o hex‑string.
    "timestamp": (int, float),
    "payload": Mapping,
    "signature": (bytes, str),  # Firma Ed25519 en bytes o hex‑string.
    # Opcionalmente, el mensaje que se firmó. Si no se provee, se construye a
    # partir de los campos obligatorios en un orden determinista.
    "signed_message": (bytes, str, type(None)),
}


def _to_bytes(value: Any) -> bytes:
    """Convierte ``value`` a ``bytes``.

    - ``bytes`` se devuelve tal cual.
    - ``str`` se interpreta como una cadena hexadecimal (sin prefijo ``0x``) y
      se decodifica.
    - Otros tipos generan ``TypeError``.
    """
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        # Asumir representación hexadecimal para claves y firmas.
        try:
            return bytes.fromhex(value)
        except ValueError as exc:
            raise TypeError("String value is not valid hex encoding") from exc
    raise TypeError(f"Unsupported type for bytes conversion: {type(value)!r}")


def validate_proposal_structure(proposal: Mapping[str, Any]) -> None:
    """Valida que ``proposal`` contenga los campos requeridos y tipos correctos.

    Lanza ``ValueError`` si la propuesta es inválida.
    """
    if not isinstance(proposal, Mapping):
        raise ValueError("Proposal must be a mapping/dict")

    missing = [f for f in _REQUIRED_FIELDS if f not in proposal]
    if missing:
        raise ValueError(f"Proposal is missing required fields: {missing}")

    for field, expected_type in _REQUIRED_FIELDS.items():
        value = proposal.get(field)
        if value is None and expected_type is type(None):
            continue
        if not isinstance(value, expected_type):
            # Permitir bytes o hex‑string para claves y firmas.
            if field in {"creator_pubkey", "signature", "signed_message"}:
                if not isinstance(value, (bytes, str)):
                    raise ValueError(
                        f"Field '{field}' must be bytes or hex string, got {type(value)!r}"
                    )
            else:
                raise ValueError(
                    f"Field '{field}' must be of type {expected_type}, got {type(value)!r}"
                )

    # Validación adicional de tipos internos.
    if not isinstance(proposal["payload"], Mapping):
        raise ValueError("Field 'payload' must be a mapping/dict")

    # Opcional: validar que el id tenga formato UUID‑like.
    # No se impone estrictamente para mantener flexibilidad.
    return None


def _canonical_message(proposal: Mapping[str, Any]) -> bytes:
    """Construye un mensaje canónico a partir de los campos de la propuesta.

    Si ``signed_message`` está presente y no es ``None``, se devuelve tal cual.
    De lo contrario, se serializa de forma determinista ``id``, ``timestamp`` y
    ``payload`` usando JSON con claves ordenadas y codificación UTF‑8.
    """
    signed_msg = proposal.get("signed_message")
    if signed_msg is not None:
        return _to_bytes(signed_msg)
    # Construir mensaje determinista.
    deterministic_dict = {
        "id": proposal["id"],
        "timestamp": proposal["timestamp"],
        "payload": proposal["payload"],
    }
    # ``separators`` elimina espacios para una representación estable.
    json_bytes = json.dumps(deterministic_dict, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return json_bytes


def verify_proposal_signature(proposal: Mapping[str, Any]) -> bool:
    """Verifica la firma Ed25519 incluida en la propuesta.

    La propuesta debe haber pasado ``validate_proposal_structure`` previamente.
    La función devuelve ``True`` si la firma es válida; de lo contrario ``False``.
    """
    try:
        # Convertir claves y firma a bytes.
        pubkey_bytes = _to_bytes(proposal["creator_pubkey"])
        signature_bytes = _to_bytes(proposal["signature"])
        message = _canonical_message(proposal)

        public_key = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
        public_key.verify(signature_bytes, message)
        return True
    except (InvalidSignature, TypeError, ValueError):
        return False

__all__ = [
    "validate_proposal_structure",
    "verify_proposal_signature",
]
