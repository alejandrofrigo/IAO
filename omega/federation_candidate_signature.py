'''omega/federation_candidate_signature.py

Utilidades para firmar y verificar descriptores de candidatos federados usando Ed25519.

Este módulo proporciona una API sencilla y determinista que permite a los operadores:
  * Generar una firma criptográfica del descriptor del candidato.
  * Adjuntar la firma al descriptor de manera estructurada.
  * Verificar la firma contra una clave pública conocida.

Todas las operaciones se basan en la librería estándar `cryptography` y utilizan una
serialización JSON canónica (ordenada y sin espacios) para garantizar que la
firma sea reproducible.
''' 

import os
import json
import base64
from typing import Any, Dict

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

# ---------------------------------------------------------------------------
# Configuración de claves
# ---------------------------------------------------------------------------

_PRIVATE_KEY_ENV = "IAO_FEDERATION_PRIVATE_KEY"  # hex‑encoded
_PUBLIC_KEY_ENV = "IAO_FEDERATION_PUBLIC_KEY"    # base64‑encoded (raw bytes)


def _load_private_key() -> ed25519.Ed25519PrivateKey:
    """Carga la clave privada Ed25519 desde la variable de entorno.

    La clave debe estar codificada en hexadecimal (sin prefijo ``0x``).
    Si la variable no está definida se lanza ``RuntimeError`` para evitar
    operaciones inseguras.
    """
    hex_key = os.getenv(_PRIVATE_KEY_ENV)
    if not hex_key:
        raise RuntimeError(
            f"Variable de entorno '{_PRIVATE_KEY_ENV}' no configurada. "
            "Se requiere una clave privada Ed25519 en formato hex para firmar."
        )
    try:
        raw = bytes.fromhex(hex_key)
        return ed25519.Ed25519PrivateKey.from_private_bytes(raw)
    except ValueError as exc:
        raise RuntimeError(
            f"Clave privada en '{_PRIVATE_KEY_ENV}' no es un hex válido: {exc}"
        ) from exc


def _load_public_key() -> ed25519.Ed25519PublicKey:
    """Carga la clave pública Ed25519 desde la variable de entorno.

    La clave pública debe estar codificada en Base64 (raw 32‑byte Ed25519 key).
    """
    b64_key = os.getenv(_PUBLIC_KEY_ENV)
    if not b64_key:
        raise RuntimeError(
            f"Variable de entorno '{_PUBLIC_KEY_ENV}' no configurada. "
            "Se requiere la clave pública Ed25519 para verificación."
        )
    try:
        raw = base64.b64decode(b64_key)
        return ed25519.Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, base64.binascii.Error) as exc:
        raise RuntimeError(
            f"Clave pública en '{_PUBLIC_KEY_ENV}' no es base64 válido: {exc}"
        ) from exc

# ---------------------------------------------------------------------------
# Serialización canónica del descriptor
# ---------------------------------------------------------------------------

def _canonical_json(data: Dict[str, Any]) -> bytes:
    """Serializa ``data`` a JSON canónico.

    - Las claves se ordenan alfabéticamente.
    - Se usan separadores compactos para evitar espacio extra.
    - ``ensure_ascii`` se desactiva para preservar UTF‑8.
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
    ).encode('utf-8')

# ---------------------------------------------------------------------------
# API pública
# ---------------------------------------------------------------------------

def sign_candidate(candidate: Dict[str, Any]) -> Dict[str, Any]:
    """Firma un descriptor de candidato y devuelve una nueva copia con la firma.

    La firma se añade bajo la clave ``"signature"`` codificada en Base64.
    El descriptor original no se modifica.
    """
    if not isinstance(candidate, dict):
        raise TypeError("candidate must be a dict")

    # Preparar una copia sin campo signature (en caso de que ya exista)
    clean_candidate = {k: v for k, v in candidate.items() if k != "signature"}
    payload = _canonical_json(clean_candidate)
    private_key = _load_private_key()
    signature = private_key.sign(payload)  # 64‑byte Ed25519 signature
    b64_sig = base64.b64encode(signature).decode('ascii')
    signed = dict(clean_candidate)  # shallow copy
    signed["signature"] = b64_sig
    return signed


def verify_candidate_signature(candidate: Dict[str, Any]) -> bool:
    """Verifica la firma incluida en ``candidate``.

    La función espera que el candidato contenga una clave ``"signature"`` con el
    valor codificado en Base64. Devuelve ``True`` si la firma es válida, de lo
    contrario ``False``.
    """
    if not isinstance(candidate, dict):
        raise TypeError("candidate must be a dict")
    signature_b64 = candidate.get("signature")
    if not signature_b64:
        return False
    try:
        signature = base64.b64decode(signature_b64)
    except (ValueError, base64.binascii.Error):
        return False
    # Excluir la firma del payload que será verificado
    payload_dict = {k: v for k, v in candidate.items() if k != "signature"}
    payload = _canonical_json(payload_dict)
    public_key = _load_public_key()
    try:
        public_key.verify(signature, payload)
        return True
    except InvalidSignature:
        return False

# ---------------------------------------------------------------------------
# Exportación del módulo
# ---------------------------------------------------------------------------

__all__ = [
    "sign_candidate",
    "verify_candidate_signature",
]
