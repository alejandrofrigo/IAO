"""Omega Federation Proposal Service

Este módulo ofrece una capa de orquestación de alto nivel que combina la
creación y firma de propuestas federadas, su verificación criptográfica y su
asimilación en el sistema. Utiliza los bloques funcionales ya presentes en
``omega.federation_proposal_signing`` y ``omega.federation_assimilation_verifier``
para garantizar que las propuestas sean auténticas antes de ser procesadas.

La API pública consiste en dos funciones principales:

* ``create_signed_proposal`` – construye una propuesta a partir de la información
  del candidato y la firma con la llave privada Ed25519 proporcionada.
* ``verify_and_assimilate`` – verifica la firma de una propuesta ya firmada y,
  si la verificación es satisfactoria, delega su asimilación al módulo de
  ``omega.federation_assimilation``.

Todas las operaciones se realizan en memoria y no realizan I/O externo, lo
que permite su uso seguro dentro del entorno controlado de PADGE.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# Importación de los bloques funcionales existentes
from .federation_proposal_signing import sign_proposal
from .federation_assimilation_verifier import verify_proposal_signature

# La asimilación puede estar implementada bajo diferentes nombres; intentamos
# importar la función estándar. Si no existe, se lanza un error claro.
try:
    from . import federation_assimilation as _assimilation_module
except Exception as exc:  # pragma: no cover
    raise ImportError("Unable to import federation_assimilation module") from exc

# Intentamos obtener la función de asimilación esperada.
if hasattr(_assimilation_module, "assimilate_proposal"):
    _assimilate = getattr(_assimilation_module, "assimilate_proposal")
elif hasattr(_assimilation_module, "assimilate"):
    _assimilate = getattr(_assimilation_module, "assimilate")
else:  # pragma: no cover
    raise AttributeError(
        "Module 'omega.federation_assimilation' does not expose an assimilation function"
    )


@dataclass(frozen=True)
class SignedProposal:
    """Representación inmutable de una propuesta federada firmada.

    Attributes
    ----------
    candidate_id: str
        Identificador único del candidato al que se refiere la propuesta.
    payload: Dict[str, Any]
        Contenido arbitrario de la propuesta (por ejemplo, metadatos de
        configuración, políticas, etc.).
    signature: str
        Firma hexadecimal del JSON canónico de ``{candidate_id, payload}``.
    """

    candidate_id: str
    payload: Dict[str, Any]
    signature: str

    def to_dict(self) -> Dict[str, Any]:
        """Convierte la propuesta firmada a un ``dict`` JSON‑serializable."""
        return {
            "candidate_id": self.candidate_id,
            "payload": self.payload,
            "signature": self.signature,
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "SignedProposal":
        """Construye una instancia a partir de un ``dict`` previamente creado.

        Se asume que el diccionario contiene las claves ``candidate_id``,
        ``payload`` y ``signature``.
        """
        return SignedProposal(
            candidate_id=data["candidate_id"],
            payload=data["payload"],
            signature=data["signature"],
        )


def create_signed_proposal(
    candidate_id: str,
    payload: Dict[str, Any],
    signing_key: Ed25519PrivateKey,
) -> SignedProposal:
    """Crea una propuesta federada y la firma con la clave privada Ed25519.

    Parámetros
    ----------
    candidate_id: str
        Identificador único del candidato.
    payload: Dict[str, Any]
        Información que acompañará a la propuesta.
    signing_key: Ed25519PrivateKey
        Clave privada utilizada para generar la firma.

    Retorna
    -------
    SignedProposal
        Objeto inmutable que contiene la propuesta y su firma en hexadecimal.
    """
    # La función ``sign_proposal`` existente espera un ``dict`` con los campos
    # ``candidate_id`` y ``payload`` y devuelve una copia firma‑incluida.
    base_proposal = {"candidate_id": candidate_id, "payload": payload}
    signed_dict = sign_proposal(base_proposal, signing_key)
    # ``sign_proposal`` garantiza la presencia de la clave ``signature``.
    return SignedProposal.from_dict(signed_dict)


def verify_and_assimilate(
    signed_proposal: SignedProposal,
    verification_key: Ed25519PublicKey,
) -> bool:
    """Verifica la firma de una propuesta y, si es válida, la asimila.

    Parámetros
    ----------
    signed_proposal: SignedProposal
        Propuesta previamente firmada.
    verification_key: Ed25519PublicKey
        Clave pública correspondiente a la clave privada que firmó la propuesta.

    Retorna
    -------
    bool
        ``True`` si la verificación y la asimilación fueron exitosas; ``False``
        en caso contrario.
    """
    # Convertir a dict para reutilizar la lógica de verificación existente.
    proposal_dict = signed_proposal.to_dict()
    is_valid = verify_proposal_signature(proposal_dict, verification_key)
    if not is_valid:
        return False
    # Delegar la asimilación al módulo de asimilación. Se asume que la función
    # devuelve ``True``/``False`` indicando éxito.
    try:
        result = _assimilate(proposal_dict)
    except Exception:  # pragma: no cover
        # En caso de error inesperado, consideramos la asimilación fallida.
        return False
    return bool(result)
