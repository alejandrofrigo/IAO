'''omega/federation_signature.py

Utilidades para la verificación de firmas Ed25519 en el contexto de la federación.

Esta capa permite validar que una propuesta o mensaje de federación provenga de un
participante autorizado que posea la clave privada correspondiente. La verificación
se basa en la representación canónica JSON del mensaje (ordenado por clave) y
utiliza la biblioteca ``cryptography`` que ya está incluida en las dependencias del
proyecto.

Funciones principales:
- ``load_public_key(pem: str)`` → ``ed25519.Ed25519PublicKey``
- ``canonical_json(data: Any)`` → ``bytes``
- ``verify_signature(message: Any, signature: bytes, public_key: ed25519.Ed25519PublicKey)`` → ``bool``
- ``verify_proposal(proposal: dict, signature_b64: str, public_key_pem: str)`` → ``bool``
''' 

from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

__all__ = [
    "load_public_key",
    "canonical_json",
    "verify_signature",
    "verify_proposal",
]


def load_public_key(pem: str) -> ed25519.Ed25519PublicKey:
    """Cargar una clave pública Ed25519 a partir de una cadena PEM.

    Args:
        pem: Representación PEM de la clave pública.
    Returns:
        Instancia ``Ed25519PublicKey`` lista para verificaciones.
    """
    pem_bytes = pem.encode("utf-8")
    return serialization.load_pem_public_key(pem_bytes)


def canonical_json(data: Any) -> bytes:
    """Serializar datos a JSON canónico (ordenado por claves) y codificar en UTF‑8.

    La canonicidad es requerida para que diferentes nodos produzcan exactamente el
    mismo mensaje binario antes de firmar o verificar.
    """
    # ``separators`` elimina espacios innecesarios y ``sort_keys`` garantiza orden.
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode("utf-8")


def verify_signature(message: Any, signature: bytes, public_key: ed25519.Ed25519PublicKey) -> bool:
    """Verificar que ``signature`` corresponda al ``message`` usando ``public_key``.

    Args:
        message: Objeto Python serializable a JSON que representa el contenido firmado.
        signature: Firma binaria (bytes) a validar.
        public_key: Clave pública Ed25519.
    Returns:
        ``True`` si la firma es válida, ``False`` en caso contrario.
    """
    try:
        data = canonical_json(message)
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False
    except Exception:
        # Cualquier otro error se considera una verificación fallida.
        return False


def verify_proposal(proposal: dict, signature_b64: str, public_key_pem: str) -> bool:
    """Conveniencia para validar una propuesta de federación firmada.

    La firma se espera en base64 estándar y la clave pública en formato PEM.

    Args:
        proposal: Diccionario que contiene la propuesta a validar.
        signature_b64: Firma codificada en base64.
        public_key_pem: Clave pública del autor en PEM.
    Returns:
        ``True`` si la firma corresponde a la propuesta, ``False`` en otro caso.
    """
    try:
        signature = base64.b64decode(signature_b64)
    except Exception:
        return False
    try:
        pub_key = load_public_key(public_key_pem)
    except Exception:
        return False
    return verify_signature(proposal, signature, pub_key)
