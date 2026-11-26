"""Utilities for secure assimilation of signed federation proposals.

Este módulo provee una función de alto nivel que verifica la firma
Ed25519 de una propuesta antes de delegar la lógica de asimilación al
módulo existente ``omega.federation_assimilation``.

Se asume que el proyecto ya cuenta con ``omega.federation_proposal_signature``
que expone ``verify_signature(proposal_bytes: bytes, signature: bytes, public_key: bytes)``
para la validación criptográfica de firmas. La función aquí definida
encapsula esa verificación y lanza una excepción clara en caso de falla.

El uso típico es:

```python
from omega.federation_assimilation_utils import assimilate_signed_proposal

assimilate_signed_proposal(proposal, signature, authority_pubkey)
```

Esto protege la cadena de asimilación sin modificar la lógica actual
ni los flujos de pruebas existentes.
"""

from __future__ import annotations

import json
from typing import Any, Dict

# Importamos la función de verificación de firmas que ya está presente en el proyecto.
# Si la firma o la clave pública no son válidas, se propagará la excepción específica
# de ese módulo.
from .federation_proposal_signature import verify_signature

# Importamos la lógica de asimilación original. Se mantiene sin cambios.
from . import federation_assimilation


class InvalidProposalSignatureError(ValueError):
    """Excepción lanzada cuando la firma de una propuesta no es válida."""


def _serialize_proposal(proposal: Dict[str, Any]) -> bytes:
    """Serializa una propuesta a bytes de forma determinista.

    La serialización debe ser idéntica a la utilizada al firmar la propuesta.
    Se emplea JSON sin espacios y con clave ordenada.
    """
    # ``ensure_ascii=False`` preserva caracteres Unicode; ``separators`` elimina
    # espacios innecesarios. ``sort_keys`` garantiza orden estable.
    return json.dumps(proposal, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def assimilate_signed_proposal(
    proposal: Dict[str, Any],
    signature: bytes,
    authority_public_key: bytes,
) -> None:
    """Verifica la firma de *proposal* y, si es válida, ejecuta la asimilación.

    Parameters
    ----------
    proposal: dict
        La propuesta estructurada que se desea asimilar.
    signature: bytes
        Firma Ed25519 sobre la representación serializada de ``proposal``.
    authority_public_key: bytes
        Clave pública Ed25519 de la autoridad que firmó la propuesta.

    Raises
    ------
    InvalidProposalSignatureError
        Si la firma no coincide con la clave pública provista.
    Exception
        Cualquier excepción proveniente de ``federation_assimilation`` se
        propaga tal cual, pues la verificación de firma ya se completó con
        éxito.
    """
    # Serializamos la propuesta exactamente como se firmó.
    proposal_bytes = _serialize_proposal(proposal)

    # Verificamos la firma usando la utilidad centralizada.
    try:
        verify_signature(proposal_bytes, signature, authority_public_key)
    except Exception as exc:
        # Normalizamos cualquier error de firma a nuestra excepción pública.
        raise InvalidProposalSignatureError("Firma de propuesta no válida") from exc

    # Si la firma es válida, delegamos al módulo de asimilación existente.
    # Se asume que ``federation_assimilation`` expone una función ``assimilate``
    # que acepta la propuesta en su forma dict.
    if hasattr(federation_assimilation, "assimilate"):
        federation_assimilation.assimilate(proposal)
    else:
        # Resguardamos el caso de que la función no exista todavía; la ausencia
        # indica que la implementación está pendiente y no debe romper el flujo.
        raise NotImplementedError(
            "La función 'assimilate' no está disponible en omega.federation_assimilation"
        )
