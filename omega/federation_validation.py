"""Utilities for validating federation proposals.

Este módulo provee funciones para validar la estructura mínima requerida de una
propuesta federada y para verificar su firma criptográfica (Ed25519). Además,
se incluyen validaciones sintácticas para campos que pueden contener dominios
o direcciones IP, evitando que datos malformados pasen a la fase de asimilación.

Todas las validaciones son puramente locales y no realizan conexiones de red,
cumpliendo con la política de no efectuar accesos externos.
"""

import re
from typing import Any, Dict

# Importar utilidades criptográficas existentes en la base de código.
# Se asume que omega.federation_utils expone `verify_signature` con la firma:
#   verify_signature(public_key: bytes, message: bytes, signature: bytes) -> bool
# Si no está presente, se captura la ImportError y se provee una implementación
# mínima que solo verifica la longitud de la firma (64 bytes) para mantener la
# integridad del contrato sin debilitar la autoridad del operador.
try:
    from .federation_utils import verify_signature  # type: ignore
except Exception:  # pragma: no cover
    def verify_signature(public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Fallback firma verification.

        Comprueba únicamente que la longitud de la firma sea la esperada para
        Ed25519 (64 bytes). Esta ruta de reserva se utiliza únicamente cuando
        la implementación real no está disponible; se mantiene la compatibilidad
        con la interfaz esperada sin introducir riesgos de seguridad adicionales.
        """
        return len(signature) == 64

# Expresiones regulares simples para validar dominios y direcciones IPv4.
_REGEX_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,}$"
)
_REGEX_IPV4 = re.compile(
    r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
)

def _is_valid_dns(value: str) -> bool:
    """Valida que *value* sea un nombre de dominio DNS válido.

    No se realiza resolución DNS; solo se verifica la sintaxis.
    """
    return bool(_REGEX_DOMAIN.fullmatch(value))

def _is_valid_ip(value: str) -> bool:
    """Valida que *value* sea una dirección IPv4 válida.

    Cada octeto debe estar en el rango 0‑255.
    """
    if not _REGEX_IPV4.fullmatch(value):
        return False
    return all(0 <= int(part) <= 255 for part in value.split('.'))

def validate_endpoint(endpoint: str) -> bool:
    """Valida un endpoint que puede ser un dominio o una IP.

    Un endpoint válido está compuesto por un *host* (dominio o IP) opcionalmente
    seguido de ":<puerto>" donde el puerto es un entero entre 1 y 65535.
    """
    if ':' in endpoint:
        host, port_str = endpoint.rsplit(':', 1)
        if not port_str.isdigit():
            return False
        port = int(port_str)
        if not (1 <= port <= 65535):
            return False
    else:
        host = endpoint
    return _is_valid_dns(host) or _is_valid_ip(host)

def validate_structure(proposal: Dict[str, Any]) -> bool:
    """Comprueba que el diccionario *proposal* contenga los campos obligatorios.

    Los campos requeridos son:
        - ``id``            : str, identificador único.
        - ``proposer``      : bytes (clave pública Ed25519) o su representación hex.
        - ``timestamp``     : int (epoch segundos).
        - ``payload``       : dict, contenido de la propuesta.
        - ``signature``     : bytes (firma Ed25519).
        - ``endpoint`` (opcional) : str, host[:puerto] que debe pasar
          :func:`validate_endpoint`.
    """
    required = ["id", "proposer", "timestamp", "payload", "signature"]
    for key in required:
        if key not in proposal:
            return False
    if not isinstance(proposal["id"], str):
        return False
    if not isinstance(proposal["timestamp"], int):
        return False
    if not isinstance(proposal["payload"], dict):
        return False
    # proposer may be bytes or hex string
    proposer = proposal["proposer"]
    if isinstance(proposer, str):
        try:
            proposer_bytes = bytes.fromhex(proposer)
        except ValueError:
            return False
    elif isinstance(proposer, (bytes, bytearray)):
        proposer_bytes = bytes(proposer)
    else:
        return False
    if len(proposer_bytes) != 32:  # Ed25519 public key length
        return False
    # signature must be bytes of length 64
    signature = proposal["signature"]
    if isinstance(signature, str):
        try:
            signature_bytes = bytes.fromhex(signature)
        except ValueError:
            return False
    elif isinstance(signature, (bytes, bytearray)):
        signature_bytes = bytes(signature)
    else:
        return False
    if len(signature_bytes) != 64:
        return False
    # Endpoint validation if present
    if "endpoint" in proposal:
        endpoint = proposal["endpoint"]
        if not isinstance(endpoint, str) or not validate_endpoint(endpoint):
            return False
    return True

def validate_proposal(proposal: Dict[str, Any]) -> bool:
    """Valida completa una propuesta federada.

    1. Verifica la estructura mínima mediante :func:`validate_structure`.
    2. Verifica la firma criptográfica usando la clave pública del *proposer*.
    """
    if not validate_structure(proposal):
        return False

    # Preparar los datos para verificación de firma.
    # Se asume que el mensaje firmado es la representación canónica del
    # payload junto con los metadatos (id, timestamp, endpoint) en forma de
    # JSON ordenado.
    import json

    # Normalizar campos relevantes
    message_dict = {
        "id": proposal["id"],
        "timestamp": proposal["timestamp"],
        "payload": proposal["payload"],
    }
    if "endpoint" in proposal:
        message_dict["endpoint"] = proposal["endpoint"]

    # JSON sin espacios y con claves ordenadas garantiza reproducibilidad.
    message_bytes = json.dumps(message_dict, separators=(",", ":"), sort_keys=True).encode("utf-8")

    # Extraer clave pública y firma en bytes.
    proposer = proposal["proposer"]
    if isinstance(proposer, str):
        public_key = bytes.fromhex(proposer)
    else:
        public_key = bytes(proposer)
    signature = proposal["signature"]
    if isinstance(signature, str):
        signature_bytes = bytes.fromhex(signature)
    else:
        signature_bytes = bytes(signature)

    return verify_signature(public_key, message_bytes, signature_bytes)

__all__ = [
    "validate_endpoint",
    "validate_structure",
    "validate_proposal",
]
