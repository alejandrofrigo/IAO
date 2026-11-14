"""Utilities for secure verification and assimilation of federation proposals.

Esta implementación provee una función de alto nivel que:
1. Verifica la firma Ed25519 de una propuesta utilizando la clave pública
   configurada para la autoridad federada.
2. En caso de éxito, delega la asimilación de la propuesta al módulo
   `omega.federation_assimilation` (presuponiendo que exista la función
   `assimilate_proposal`).
3. Lanza excepciones explícitas para errores de verificación o de asimilación,
   permitiendo que la capa llamadora maneje revocaciones, auditorías o
   reintentos.

Esta utilidad se integra con el resto de la infraestructura sin introducir
conexiones externas ni modificar la lógica existente, cumpliendo con los
límites de seguridad definidos en la política PADGE.
"""

from __future__ import annotations

import json
from typing import Any, Dict

from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

# Importamos la función de asimilación real del paquete federado. Si el módulo
# destino no expone la función, se producirá un AttributeError, lo que señaliza
# que la implementación de asimilación aún no está disponible.
try:
    from .federation_assimilation import assimilate_proposal  # type: ignore
except Exception as exc:  # pragma: no cover
    raise ImportError(
        "La función 'assimilate_proposal' no está disponible en omega.federation_assimilation"
    ) from exc

__all__ = ["verify_and_assimilate"]


def _load_public_key(pem_data: bytes) -> VerifyKey:
    """Construye un VerifyKey a partir de datos PEM o raw.

    La clave pública esperada está en formato Ed25519 y puede suministrarse
    como PEM ("-----BEGIN PUBLIC KEY----- ...") o como bytes crudos de 32
    octetos.
    """
    # La librería `nacl.signing.VerifyKey` acepta directamente los 32 bytes
    # de clave pública. Detectamos si el contenido está en PEM y extraemos la
    # sección base64.
    if pem_data.startswith(b"-----BEGIN"):
        # Eliminar encabezados y pie de página, y decodificar Base64.
        import base64
        b64 = b"".join(
            line.strip() for line in pem_data.splitlines() if not line.startswith(b"-")
        )
        raw = base64.b64decode(b64)
    else:
        raw = pem_data
    if len(raw) != 32:
        raise ValueError("La clave pública Ed25519 debe tener exactamente 32 bytes")
    return VerifyKey(raw)


def verify_and_assimilate(
    proposal: Dict[str, Any],
    signature: bytes,
    public_key_pem: bytes,
) -> bool:
    """Verifica la firma de una propuesta y la asimila de forma segura.

    Args:
        proposal: Un diccionario JSON‑serializable que representa la propuesta
            federada.
        signature: La firma Ed25519 (bytes) generada por la autoridad que
            publica la propuesta.
        public_key_pem: Clave pública del firmante en formato PEM o bytes
            crudos.

    Returns:
        bool: ``True`` si la verificación y la asimilación fueron exitosas.

    Raises:
        BadSignatureError: Si la firma no coincide con el contenido de la
            propuesta.
        ValueError: Si los datos de la clave pública son inválidos.
        Exception: Propagado desde `assimilate_proposal` si la asimilación
            falla.
    """
    # Serializamos la propuesta de manera determinista para la verificación.
    # Usamos separators sin espacios para garantizar reproducibilidad.
    proposal_bytes = json.dumps(proposal, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )

    verify_key = _load_public_key(public_key_pem)
    try:
        verify_key.verify(proposal_bytes, signature)
    except BadSignatureError as e:
        raise BadSignatureError("Firma no válida para la propuesta proporcionada") from e

    # Si la firma es válida, delegamos la asimilación.
    # La función `assimilate_proposal` debe devolver True/False o lanzar una
    # excepción en caso de error.
    result = assimilate_proposal(proposal)
    if not isinstance(result, bool):
        # Normalizamos la respuesta a un booleano.
        result = bool(result)
    return result
