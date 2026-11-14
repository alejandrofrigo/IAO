"""Utilities for handling federation proposals.

Este módulo provee funciones auxiliares para generar identificadores
persistentes de propuestas y validar su estructura mínima antes de que
se proceda a firmarlas o assimilarlas. Se mantiene sin dependencias
externas salvo la biblioteca estándar para garantizar que pueda ser
usado en cualquier contexto del paquete ``omega``.
"""

from __future__ import annotations

import json
import hashlib
from typing import Mapping, Any

# Campos obligatorios que debe contener toda propuesta federada
_REQUIRED_FIELDS = {"origin", "payload", "timestamp", "signature"}


def generate_proposal_id(proposal: Mapping[str, Any]) -> str:
    """Genera un identificador determinístico para una propuesta.

    El ID se calcula como el hash SHA‑256 del JSON canónico del contenido
    de la propuesta (excluyendo el campo ``id`` si estuviera presente).
    Se asegura que la serialización sea reproducible mediante ``sort_keys``
    y la eliminación de espacios innecesarios.

    Args:
        proposal: Diccionario que representa la propuesta.

    Returns:
        Hexdigest de 64 caracteres que representa el ID único.
    """
    # Copiar sin mutar el argumento original y eliminar una clave id preexistente
    proposal_copy = {k: v for k, v in proposal.items() if k != "id"}
    # Serializar de forma canónica
    canonical_json = json.dumps(proposal_copy, sort_keys=True, separators=(",", ":"))
    sha256 = hashlib.sha256()
    sha256.update(canonical_json.encode("utf-8"))
    return sha256.hexdigest()


def validate_proposal_structure(proposal: Mapping[str, Any]) -> None:
    """Valida que una propuesta cumpla con los requisitos estructurales.

    La función no devuelve nada si la propuesta es válida; de lo contrario
    lanza ``ValueError`` indicando el motivo de la falla.

    Requisitos verificables:
    * El objeto debe ser un ``Mapping`` (por ejemplo, ``dict``).
    * Debe contener todos los campos obligatorios definidos en
      ``_REQUIRED_FIELDS``.
    * Cada campo debe ser de tipo ``str`` salvo ``payload`` que puede ser
      cualquier objeto JSON‑serializable.
    * El campo ``timestamp`` debe ser convertible a entero positivo.
    * El campo ``signature`` debe ser una cadena codificada en base64 o
      hexadecimal de longitud razonable (>= 64 caracteres).
    """
    if not isinstance(proposal, Mapping):
        raise ValueError("La propuesta debe ser un Mapping (p.ej., dict).")

    missing = _REQUIRED_FIELDS - proposal.keys()
    if missing:
        raise ValueError(f"Faltan campos obligatorios en la propuesta: {missing}")

    # Validación de tipos simples
    for field in ("origin", "timestamp", "signature"):
        if not isinstance(proposal[field], str):
            raise ValueError(f"El campo '{field}' debe ser una cadena.")

    # Timestamp debe ser entero positivo (se permite cadena que represente entero)
    try:
        ts_int = int(proposal["timestamp"])
        if ts_int <= 0:
            raise ValueError
    except Exception:
        raise ValueError("El campo 'timestamp' debe ser un entero positivo representado como cadena.")

    # Firma mínima longitud (hex SHA‑256 = 64 chars, base64 algo similar)
    sig = proposal["signature"]
    if len(sig) < 64:
        raise ValueError("El campo 'signature' parece demasiado corto para una firma Ed25519 válida.")

    # Payload debe ser serializable a JSON
    try:
        json.dumps(proposal["payload"])
    except (TypeError, ValueError) as exc:
        raise ValueError(f"El campo 'payload' no es JSON‑serializable: {exc}")

    # Si todo pasa, la propuesta es estructuralmente válida
    return None
