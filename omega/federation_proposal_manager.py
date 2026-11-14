"""omega.federation_proposal_manager
===================================

Este módulo implementa una capa de alto nivel para la gestión completa del
ciclo de vida de propuestas federadas.

Características principales
---------------------------
* **Creación y firma** de propuestas a partir de un payload arbitrario y una clave
  privada Ed25519.
* **Validación estructural** mediante las utilidades existentes en
  ``omega.federation_utils``.
* **Verificación criptográfica** de la firma antes de aceptar una propuesta.
* **Almacenamiento en memoria** thread‑safe que permite registrar, consultar y
  revocar propuestas de forma fiable.
* **API sencilla** basada en una clase ``FederationProposalManager`` y una
  instancia singleton ``proposal_manager`` para uso inmediato por otros
  componentes (por ejemplo, ``omega.federation.py`` o los tests).

El gestor se apoya en los módulos ya promocionados:

* ``omega.federation_utils`` – funciones ``sign_proposal``,
  ``verify_proposal_signature`` y ``validate_proposal_structure``.
* ``omega.federation_proposal_store`` – store en‑memoria que mantiene el estado
  interno de las propuestas.

Al centralizar estas operaciones garantizamos consistencia, evitamos código
duplicado y proporcionamos una interfaz verificable para los flujos de trabajo
federados.
"""

from __future__ import annotations

import uuid
import threading
from typing import Dict, List, Optional, Any

# Utilidades criptográficas y de validación provisionales.  Estas funciones
# deben estar definidas en ``omega.federation_utils``; si alguna falta se
# propagará la excepción para que el fallo sea evidente en tiempo de prueba.
from .federation_utils import (
    sign_proposal,
    verify_proposal_signature,
    validate_proposal_structure,
)

# Store interno en memoria.  El módulo ``federation_proposal_store`` ya expone
# una clase con la misma semántica; sin embargo, para evitar dependencia
# circular lo reutilizamos de forma directa.
from .federation_proposal_store import InMemoryProposalStore

__all__ = ["FederationProposalManager", "proposal_manager"]


class FederationProposalManager:
    """Gestor de propuestas federadas.

    La clase encapsula un ``InMemoryProposalStore`` y proporciona métodos de
    alto nivel que aplican la cadena completa de procesamiento:

    1. **Crear** una propuesta a partir de datos de negocio.
    2. **Firmar** la propuesta con una clave privada Ed25519.
    3. **Validar** su estructura y firma antes de almacenarla.
    4. **Registrar**, **consultar** y **revocar** propuestas de forma
       thread‑safe.
    """

    def __init__(self) -> None:
        self._store = InMemoryProposalStore()
        self._lock = threading.RLock()

    # ---------------------------------------------------------------------
    # Creación y firma
    # ---------------------------------------------------------------------
    def create_and_sign(self, payload: Dict[str, Any], private_key: bytes) -> Dict[str, Any]:
        """Crea una propuesta a partir de ``payload`` y la firma.

        Parameters
        ----------
        payload: dict
            Contenido de negocio que será incluido en la propuesta.
        private_key: bytes
            Clave privada Ed25519 (32 bytes) utilizada para generar la firma.

        Returns
        -------
        dict
            Propuesta completa con campos ``id``, ``payload`` y ``signature``.
        """
        proposal_id = str(uuid.uuid4())
        proposal: Dict[str, Any] = {
            "id": proposal_id,
            "payload": payload,
        }
        # La utilidad de firma recibe el dict completo (sin firma) y devuelve
        # la firma codificada en base64.
        signature = sign_proposal(proposal, private_key)
        proposal["signature"] = signature
        return proposal

    # ---------------------------------------------------------------------
    # Registro interno
    # ---------------------------------------------------------------------
    def add_proposal(self, proposal: Dict[str, Any]) -> None:
        """Valida y almacena una propuesta firmada.

        La función ejecuta, en este orden:

        1. Validación estructural (campos obligatorios, tipos, etc.).
        2. Verificación de la firma criptográfica.
        3. Registro en el store interno.
        """
        # Validación estructural preliminar.
        validate_proposal_structure(proposal)
        # Verificación criptográfica.
        if not verify_proposal_signature(proposal):
            raise ValueError("Firma de propuesta inválida")
        # Registro seguro.
        with self._lock:
            self._store.store(proposal["id"], proposal)

    # ---------------------------------------------------------------------
    # Consulta
    # ---------------------------------------------------------------------
    def get_proposal(self, proposal_id: str) -> Optional[Dict[str, Any]]:
        """Devuelve la propuesta con el identificador indicado o ``None``.
        """
        with self._lock:
            return self._store.retrieve(proposal_id)

    def list_active(self) -> List[Dict[str, Any]]:
        """Lista todas las propuestas actualmente registradas.
        """
        with self._lock:
            return list(self._store.all())

    # ---------------------------------------------------------------------
    # Revocación
    # ---------------------------------------------------------------------
    def revoke_proposal(self, proposal_id: str) -> bool:
        """Revoca (elimina) la propuesta indicada.

        Returns
        -------
        bool
            ``True`` si la propuesta existía y fue removida, ``False`` en caso
            contrario.
        """
        with self._lock:
            return self._store.remove(proposal_id)


# Instancia singleton para uso inmediato por la aplicación y los tests.
proposal_manager = FederationProposalManager()
