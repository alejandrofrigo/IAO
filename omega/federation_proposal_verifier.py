'''omega.federation_proposal_verifier
===================================
Módulo de utilidad para validar la firma Ed25519 de una propuesta federada y, si la verificación es exitosa, delegar su asimilación al subsistema de asimilación.

Este módulo no realiza ninguna comunicación externa y funciona de manera totalmente offline,
utilizando únicamente criptografía estándar y la lógica interna de asimilación ya presente en
`omega.federation_assimilation`.

Se provee una única función pública:

* ``verify_and_assimilate(proposal_json: str, signer_pubkey_b64: str) -> bool``

La función devuelve ``True`` si la firma es válida y la propuesta se asimila correctamente,
``False`` en caso contrario.
''' 

import base64
import json
from typing import Any, Dict

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

# Importamos de forma perezosa el módulo de asimilación para evitar ciclos de importación.
from . import federation_assimilation as _assimilation

__all__ = ["verify_and_assimilate"]


def _load_proposal(proposal_json: str) -> Dict[str, Any]:
    """Parsea la cadena JSON de la propuesta y devuelve el diccionario.

    Se asume que el JSON contiene al menos los campos ``payload`` y ``signature``.
    ``payload`` es otro objeto JSON que representa la propuesta real.
    ``signature`` es una cadena Base64 de la firma Ed25519 sobre el
    *canonizado* bytes del ``payload``.
    """
    try:
        data = json.loads(proposal_json)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Propuesta no es un JSON válido: {exc}") from exc

    if not isinstance(data, dict) or "payload" not in data or "signature" not in data:
        raise ValueError("Formato de propuesta inesperado: se requieren 'payload' y 'signature'.")
    return data


def _canonical_bytes(payload: Any) -> bytes:
    """Serializa el payload de forma canónica para firmar/verificar.

    Utiliza ``json.dumps`` con ``sort_keys=True`` y codificación UTF‑8.
    """
    # ``ensure_ascii=False`` permite mantener caracteres Unicode sin escape.
    canon = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return canon.encode("utf-8")


def _verify_signature(data: bytes, signature_b64: str, pubkey_b64: str) -> bool:
    """Valida la firma Ed25519.

    Args:
        data: Bytes canonicalizados del payload.
        signature_b64: Firma codificada en Base64.
        pubkey_b64: Clave pública del firmante codificada en Base64.

    Returns:
        True si la firma es válida, False en caso contrario.
    """
    try:
        signature = base64.b64decode(signature_b64, validate=True)
        pubkey_bytes = base64.b64decode(pubkey_b64, validate=True)
        public_key = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
        public_key.verify(signature, data)
        return True
    except (ValueError, InvalidSignature, TypeError):
        return False


def verify_and_assimilate(proposal_json: str, signer_pubkey_b64: str) -> bool:
    """Verifica la firma de una propuesta y la asimila si es válida.

    La función realiza los siguientes pasos:
    1. Parsear ``proposal_json`` y extraer ``payload`` y ``signature``.
    2. Serializar el ``payload`` de forma canónica y obtener sus bytes.
    3. Verificar la firma Ed25519 usando la clave pública proporcionada.
    4. Si la firma es válida, delegar la asimilación del ``payload`` al módulo
       ``omega.federation_assimilation``.

    Parameters:
        proposal_json: Representación en cadena JSON de la propuesta completa.
        signer_pubkey_b64: Clave pública del firmante codificada en Base64.

    Returns:
        ``True`` si la firma es válida y la asimilación se realizó sin errores,
        ``False`` en cualquier otro caso.
    """
    try:
        proposal = _load_proposal(proposal_json)
        payload = proposal["payload"]
        signature_b64 = proposal["signature"]
        data_bytes = _canonical_bytes(payload)

        if not _verify_signature(data_bytes, signature_b64, signer_pubkey_b64):
            return False

        # Delegamos la lógica de asimilación al módulo existente.
        # Se asume que ``assimilation.assimilate`` acepta el diccionario de payload.
        _assimilation.assimilate(payload)
        return True
    except Exception:
        # Cualquier excepción (p.ej., formato inesperado, fallos internos) se interpreta
        # como una verificación/asimilación fallida para evitar efectos colaterales.
        return False
