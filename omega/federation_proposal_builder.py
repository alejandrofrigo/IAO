"""omega.federation_proposal_builder
===================================

Este módulo provee una API de alto nivel para crear y firmar propuestas
federadas utilizando firmas Ed25519 determinísticas.  La firma se genera a
partir de una representación canónica del descriptor del candidato y del
marca de tiempo ISO‑8601 UTC.  El módulo no gestiona claves; estas deben ser
proporcionadas por el llamador (por ejemplo, mediante una carga segura desde
un almacén de secretos).  De esta forma se respeta la política de no crear ni
exponer claves estáticas dentro del código.

Funciones principales
----------------------
* ``build_signed_proposal`` – Construye un diccionario de propuesta que incluye
  el candidato, la marca de tiempo y la firma codificada en base64.
* ``verify_signed_proposal`` – Verifica la integridad y autenticidad de una
  propuesta firmada usando la clave pública correspondiente.

Ejemplo de uso
~~~~~~~~~~~~~~
>>> from cryptography.hazmat.primitives.asymmetric import ed25519
>>> priv = ed25519.Ed25519PrivateKey.generate()
>>> candidate = {"id": "node-42", "endpoint": "https://node-42.example.org"}
>>> proposal = build_signed_proposal(candidate, priv)
>>> verify_signed_proposal(proposal, priv.public_key())
True
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Any, Dict

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

__all__ = ["build_signed_proposal", "verify_signed_proposal"]


def _canonical_json(data: Any) -> bytes:
    """Serializa *data* a JSON canónico ordenado.

    La serialización canónica garantiza que dos estructuras equivalentes generen
    la misma secuencia de bytes, lo que es esencial para la firma determinística.
    """
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def build_signed_proposal(
    candidate_descriptor: Dict[str, Any],
    signing_key: Ed25519PrivateKey,
) -> Dict[str, Any]:
    """Construye y firma una propuesta federada.

    Parameters
    ----------
    candidate_descriptor:
        Diccionario que describe al candidato a incorporar.  No se impone una
        estructura rígida; la responsabilidad de validar los campos recae en
        los módulos de *capability validation* existentes.
    signing_key:
        Instancia ``Ed25519PrivateKey`` que será usada para firmar la propuesta.

    Returns
    -------
    dict
        Estructura de propuesta con los siguientes campos:
        ``candidate`` – copia del descriptor original.
        ``timestamp`` – marca de tiempo UTC en formato ISO‑8601 con sufijo ``Z``.
        ``signature`` – firma Ed25519 codificada en base64.
    """
    # Copiamos el descriptor para evitar mutaciones externas.
    candidate_copy = json.loads(json.dumps(candidate_descriptor))

    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    # Preparar el mensaje a firmar: combinación canónica del candidato y timestamp.
    message_structure = {
        "candidate": candidate_copy,
        "timestamp": timestamp,
    }
    message_bytes = _canonical_json(message_structure)
    signature = signing_key.sign(message_bytes)
    signature_b64 = base64.b64encode(signature).decode("ascii")

    return {
        "candidate": candidate_copy,
        "timestamp": timestamp,
        "signature": signature_b64,
    }


def verify_signed_proposal(
    proposal: Dict[str, Any], public_key: Ed25519PublicKey
) -> bool:
    """Verifica una propuesta firmada.

    Parameters
    ----------
    proposal:
        Propuesta generada por :func:`build_signed_proposal`.
    public_key:
        Clave pública Ed25519 correspondiente a la clave privada que firmó la
        propuesta.

    Returns
    -------
    bool
        ``True`` si la firma es válida y el contenido no ha sido alterado;
        ``False`` en caso contrario.
    """
    try:
        candidate = proposal["candidate"]
        timestamp = proposal["timestamp"]
        signature_b64 = proposal["signature"]
    except KeyError:
        return False

    try:
        signature = base64.b64decode(signature_b64)
    except (base64.binascii.Error, TypeError):
        return False

    message_structure = {"candidate": candidate, "timestamp": timestamp}
    message_bytes = _canonical_json(message_structure)
    try:
        public_key.verify(signature, message_bytes)
        return True
    except Exception:
        return False
