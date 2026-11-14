"""omega.federation_manager

Módulo de alto nivel que orquesta todo el ciclo de vida de una propuesta
federada: validación estructural, firma criptográfica Ed25519, verificación y
registro en el almacén en‑memoria. Se basa en los utilitarios ya presentes en
`omega.federation_utils` y el almacén `omega.federation_proposal_store`.

Este módulo está pensado para ser usado por las pruebas y por los
operadores que necesiten una API única sin replicar lógica en varios lugares.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict, Optional

# Utilidades criptográficas existentes (firma y verificación Ed25519)
from . import federation_utils as fu

# Almacén en‑memoria de propuestas federadas
from .federation_proposal_store import FederationProposalStore


class FederationProposalError(Exception):
    """Excepción genérica para errores en el manejo de propuestas federadas."""


class FederationProposalManager:
    """Gestor de alto nivel para propuestas federadas.

    Provee métodos para crear, registrar, consultar, verificar y revocar
    propuestas, garantizando que todos los pasos críticos se ejecuten en el
    orden correcto.
    """

    # Campos obligatorios mínimos para considerar una propuesta válida.
    _required_fields = {"id", "payload", "timestamp"}

    def __init__(self) -> None:
        self._store = FederationProposalStore()

    # ---------------------------------------------------------------------
    # Validación estructural
    # ---------------------------------------------------------------------
    def _validate_structure(self, proposal: Dict[str, Any]) -> None:
        """Comprueba que la propuesta contiene los campos mínimos obligatorios.

        Lanza ``FederationProposalError`` si falta alguno.
        """
        missing = self._required_fields - proposal.keys()
        if missing:
            raise FederationProposalError(
                f"Propuesta incompleta: faltan campos {sorted(missing)}"
            )
        # Se pueden añadir validaciones adicionales (tipos, rangos, etc.) en el futuro.

    # ---------------------------------------------------------------------
    # Firma y verificación
    # ---------------------------------------------------------------------
    def _sign_proposal(self, proposal: Dict[str, Any], private_key: bytes) -> str:
        """Firma la propuesta y devuelve la firma codificada en Base64.

        La firma se calcula sobre la representación JSON canónica (ordenadas
        las claves) codificada en UTF‑8.
        """
        canonical_bytes = json.dumps(proposal, sort_keys=True, separators=(",", ":")).encode()
        signature = fu.sign(canonical_bytes, private_key)
        return base64.b64encode(signature).decode("ascii")

    def verify_proposal_signature(self, proposal: Dict[str, Any], public_key: bytes) -> bool:
        """Verifica la firma incluida en la propuesta.

        La propuesta debe contener el campo ``_signature`` con la firma en Base64.
        """
        sig_b64 = proposal.get("_signature")
        if not sig_b64:
            return False
        signature = base64.b64decode(sig_b64.encode())
        # Se elimina la firma del dict antes de recomputar el hash JSON.
        proposal_copy = dict(proposal)
        proposal_copy.pop("_signature", None)
        canonical_bytes = json.dumps(proposal_copy, sort_keys=True, separators=(",", ":")).encode()
        return fu.verify(canonical_bytes, signature, public_key)

    # ---------------------------------------------------------------------
    # Gestión del ciclo de vida
    # ---------------------------------------------------------------------
    def submit_proposal(self, proposal: Dict[str, Any], private_key: bytes) -> str:
        """Registra una nueva propuesta federada.

        1. Valida la estructura mínima.
        2. Firma la propuesta y añade el campo ``_signature``.
        3. Almacena la propuesta en el ``FederationProposalStore``.

        Devuelve el identificador de la propuesta (campo ``id``).
        """
        self._validate_structure(proposal)
        # La firma se agrega al objeto antes de almacenarlo.
        proposal["_signature"] = self._sign_proposal(proposal, private_key)
        proposal_id = proposal["id"]
        self._store.add(proposal_id, proposal)
        return proposal_id

    def get_proposal(self, proposal_id: str) -> Optional[Dict[str, Any]]:
        """Recupera una propuesta del almacén, o ``None`` si no existe."""
        return self._store.get(proposal_id)

    def revoke_proposal(self, proposal_id: str, reason: Optional[str] = None) -> None:
        """Revoca una propuesta previamente almacenada.

        Si la propuesta no está presente se lanza ``FederationProposalError``.
        """
        if not self._store.revoke(proposal_id, reason):
            raise FederationProposalError(f"No se pudo revocar la propuesta {proposal_id!r}; no existe.")

    def list_active_proposals(self) -> Dict[str, Dict[str, Any]]:
        """Devuelve un diccionario con todas las propuestas activas (no revocadas)."""
        return self._store.list_active()

    # ---------------------------------------------------------------------
    # API de conveniencia (instancia singleton)
    # ---------------------------------------------------------------------
    # La instancia ``proposal_manager`` permite importar directamente
    # ``from omega.federation_manager import proposal_manager`` y usar sus
    # métodos sin crear objetos explícitos.


# Instancia única reutilizable por todo el paquete.
proposal_manager = FederationProposalManager()
