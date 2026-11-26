"""Utilities for handling federation proposal signatures.

Este módulo centraliza la generación y verificación de firmas Ed25519 para
propuestas federadas. Proporciona funciones de alto nivel que pueden ser
utilizadas por ``omega.federation``, ``omega.federation_proposals`` y
``omega.federation_assimilation`` así como por los tests.

La firma se realiza sobre una representación canónica JSON del diccionario
de la propuesta (ordenado por claves) codificada en UTF‑8. Se emplea la
implementación estándar de Ed25519 de la biblioteca ``cryptography`` que ya
está presente en el entorno del proyecto.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

# ---------------------------------------------------------------------------
# Datos de propuesta firmada
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class SignedProposal:
    """Representación inmutable de una propuesta federada firmada.

    Attributes
    ----------
    proposal_id: str
        Identificador único de la propuesta.
    payload: Dict[str, Any]
        Contenido arbitrario de la propuesta.
    signature: bytes
        Firma Ed25519 sobre la representación canónica del payload.
    """

    proposal_id: str
    payload: Dict[str, Any]
    signature: bytes

    def as_dict(self) -> Dict[str, Any]:
        """Devuelve la propuesta como diccionario serializable JSON.

        La clave ``signature`` se codifica en hexadecimal para conservar la
        compatibilidad con los tests que esperan texto legible.
        """
        return {
            "id": self.proposal_id,
            "payload": self.payload,
            "signature": self.signature.hex(),
        }

# ---------------------------------------------------------------------------
# Funciones de bajo nivel
# ---------------------------------------------------------------------------

def _canonical_json(data: Any) -> bytes:
    """Serializa *data* a JSON canónico (ordenado por claves) y lo codifica a UTF‑8.

    Esta representación garantiza que dos estructuras idénticas produzcan la
    misma secuencia de bytes, requisito necesario para firmas determinísticas.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

# ---------------------------------------------------------------------------
# API pública
# ---------------------------------------------------------------------------

def generate_keypair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Genera un par de claves Ed25519.

    Devuelve una tupla ``(private_key, public_key)`` que puede ser utilizada
    por ``sign_proposal`` y ``verify_proposal_signature``.
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def sign_proposal(proposal_id: str, payload: Dict[str, Any], private_key: ed25519.Ed25519PrivateKey) -> SignedProposal:
    """Firma una propuesta federada.

    Parameters
    ----------
    proposal_id: str
        Identificador único de la propuesta.
    payload: Dict[str, Any]
        Contenido que se desea proteger.
    private_key: ed25519.Ed25519PrivateKey
        Clave privada usada para generar la firma.

    Returns
    -------
    SignedProposal
        Objeto inmutable que contiene la propuesta y su firma.
    """
    # Normalizamos el payload antes de firmar para evitar variaciones de formato.
    canonical = _canonical_json(payload)
    signature = private_key.sign(canonical)
    return SignedProposal(proposal_id=proposal_id, payload=payload, signature=signature)


def verify_proposal_signature(signed: SignedProposal, public_key: ed25519.Ed25519PublicKey) -> bool:
    """Verifica la firma de una ``SignedProposal``.

    Returns ``True`` si la firma es válida, ``False`` en caso contrario.
    """
    try:
        canonical = _canonical_json(signed.payload)
        public_key.verify(signed.signature, canonical)
        return True
    except InvalidSignature:
        return False


def load_signed_proposal(raw: Dict[str, Any]) -> SignedProposal:
    """Construye un ``SignedProposal`` a partir de un diccionario crudo.

    Se asume que el diccionario contiene las claves ``id``, ``payload`` y
    ``signature`` (hexadecimal). Si falta alguna clave o la firma no es
    hexadecimal, se lanza ``ValueError``.
    """
    try:
        proposal_id = raw["id"]
        payload = raw["payload"]
        signature_hex = raw["signature"]
        signature = bytes.fromhex(signature_hex)
    except (KeyError, TypeError) as exc:
        raise ValueError("Signed proposal dict malformed") from exc
    return SignedProposal(proposal_id=proposal_id, payload=payload, signature=signature)

# ---------------------------------------------------------------------------
# Compatibilidad con los módulos de alta‑nivel existentes
# ---------------------------------------------------------------------------

def create_and_register(proposal_id: str, payload: Dict[str, Any], private_key: ed25519.Ed25519PrivateKey, store: Any) -> SignedProposal:
    """Crea una propuesta firmada y la registra en ``store``.

    ``store`` debe exponer un método ``add(proposal: SignedProposal)`` compatible
    con la interfaz de los almacenes en‑memoria introducidos en
    ``federation_proposal_store.py``. La función devuelve el objeto firmado para
    que el llamador pueda inspeccionarlo o almacenarlo adicionalmente.
    """
    signed = sign_proposal(proposal_id, payload, private_key)
    # Registramos la propuesta; si el store no tiene el método esperado se
    # propagará una excepción clara, lo que ayuda a detectar integraciones
    # incorrectas durante las pruebas.
    if not hasattr(store, "add"):
        raise AttributeError("Provided store object does not implement 'add' method")
    store.add(signed)
    return signed

"""Fin del módulo federation_utils.py"""
