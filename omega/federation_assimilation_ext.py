"""Extensiones de asimilación federada con verificación de firma.

Este módulo provee una API de alto nivel que garantiza que una propuesta
federada esté firmada correctamente con una clave Ed25519 antes de ser
asimilada en el sistema. Utiliza las utilidades definidas en
`omega.federation_assimilation_utils` para la verificación y delega el
procesamiento real a `omega.federation_assimilation.assimilate_proposal`.

El objetivo es ofrecer una única función segura que pueda ser usada por
tests y componentes externos sin replicar la lógica de verificación en
cada lugar.
"""

from __future__ import annotations

from typing import Any

# Importar la función de verificación de firma existente.
from .federation_assimilation_utils import verify_proposal_signature

# Importar la lógica de asimilación original.
# Se asume que `assimilate_proposal` consume la propuesta ya verificada y
# devuelve un objeto que representa el estado de asimilación (por ejemplo,
# un dict o una instancia de modelo interno).
from .federation_assimilation import assimilate_proposal


def assimilate_verified_proposal(
    proposal: bytes,
    signature: bytes,
    public_key: bytes,
    *args: Any,
    **kwargs: Any,
) -> Any:
    """Asimila una propuesta federada después de verificar su firma.

    Parameters
    ----------
    proposal: bytes
        La propuesta serializada que se quiere asimilar.
    signature: bytes
        Firma Ed25519 generada con la clave privada correspondiente al
        `public_key` proporcionado.
    public_key: bytes
        Clave pública Ed25519 del emisor de la propuesta.
    *args, **kwargs: Any
        Parámetros adicionales que serán reenviados a
        `omega.federation_assimilation.assimilate_proposal` para permitir
        extensibilidad sin romper la interfaz existente.

    Returns
    -------
    Any
        El resultado devuelto por `assimilate_proposal`.

    Raises
    ------
    ValueError
        Si la verificación de la firma falla.
    """
    if not verify_proposal_signature(proposal, signature, public_key):
        raise ValueError("Invalid proposal signature; assimilation aborted.")
    # La firma es válida; delegar al proceso de asimilación original.
    return assimilate_proposal(proposal, *args, **kwargs)


__all__ = ["assimilate_verified_proposal"]
