'''omega/federation_proposal_store.py

Almacén en memoria para propuestas federadas.

- Inmutabilidad: una vez almacenada una propuesta con un identificador
  único no puede ser sobrescrita.
- Revocación: permite marcar una propuesta como revocada sin eliminarla,
  manteniendo el registro histórico.
- Auditoría: cada operación (add, revoke, get) se registra mediante el
  módulo estándar de logging; se incluye el identificador de propuesta y
  la acción realizada.
- Validación de firma: al añadir una propuesta se verifica la firma
  Ed25519 usando ``omega.federation_utils.verify_signature``.

Este almacén sirve como base para los gestores de propuestas de alto nivel
(y para los tests) garantizando integridad y trazabilidad.
''' 

import threading
import logging
from typing import Dict, Any, Optional, List

# Configuración básica de logging para auditoría interna del almacén.
logger = logging.getLogger(__name__)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# Importamos la utilidad de verificación de firma. Si no está disponible, se
# producirá un ImportError que indicará que la dependencia crítica falta.
try:
    from .federation_utils import verify_signature, get_public_key
except Exception as exc:  # pragma: no cover
    raise ImportError('federation_utils must provide verify_signature and get_public_key') from exc

class ProposalRecord:
    """Representa una propuesta almacenada.

    Attributes
    ----------
    proposal_id: str
        Identificador único de la propuesta.
    data: dict
        Contenido completo de la propuesta (incluye campos firmados).
    revoked: bool
        Marca que indica si la propuesta ha sido revocada.
    """

    __slots__ = ("proposal_id", "data", "revoked")

    def __init__(self, proposal_id: str, data: Dict[str, Any]):
        self.proposal_id = proposal_id
        self.data = data
        self.revoked = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "data": self.data,
            "revoked": self.revoked,
        }

class FederationProposalStore:
    """Almacén thread‑safe para propuestas federadas.

    Provee operaciones de inserción, consulta, listado y revocación con
    auditoría y validación de firma.
    """

    def __init__(self):
        self._store: Dict[str, ProposalRecord] = {}
        self._lock = threading.RLock()

    def add_proposal(self, proposal_id: str, proposal: Dict[str, Any]) -> None:
        """Agrega una propuesta al almacén.

        Parameters
        ----------
        proposal_id: str
            Identificador único de la propuesta.
        proposal: dict
            Representación de la propuesta, que debe contener al menos los
            campos ``"signature"`` y ``"signed_data"`` (el mensaje pre‑hash).

        Raises
        ------
        ValueError
            Si la propuesta ya existe, si la firma es inválida o si los
            campos requeridos faltan.
        """
        with self._lock:
            if proposal_id in self._store:
                logger.warning("Attempt to overwrite existing proposal %s", proposal_id)
                raise ValueError(f"Proposal '{proposal_id}' already exists and cannot be overwritten.")

            # Validamos la presencia de los campos críticos.
            if "signature" not in proposal or "signed_data" not in proposal:
                raise ValueError("Proposal must contain 'signature' and 'signed_data' fields.")

            # Verificamos la firma usando la clave pública configurada.
            public_key = get_public_key()
            if not verify_signature(public_key, proposal["signed_data"], proposal["signature"]):
                logger.warning("Invalid signature for proposal %s", proposal_id)
                raise ValueError("Proposal signature verification failed.")

            # Almacenamos la propuesta como registro inmutable.
            record = ProposalRecord(proposal_id, proposal)
            self._store[proposal_id] = record
            logger.info("Proposal %s added successfully.", proposal_id)

    def get_proposal(self, proposal_id: str) -> Optional[Dict[str, Any]]:
        """Devuelve la propuesta completa o ``None`` si no existe.
        """
        with self._lock:
            record = self._store.get(proposal_id)
            if record is None:
                logger.debug("Proposal %s not found.", proposal_id)
                return None
            logger.debug("Proposal %s retrieved (revoked=%s).", proposal_id, record.revoked)
            return record.to_dict()

    def list_active(self) -> List[Dict[str, Any]]:
        """Lista todas las propuestas que no están revocadas.
        """
        with self._lock:
            active = [rec.to_dict() for rec in self._store.values() if not rec.revoked]
            logger.debug("Listing %d active proposals.", len(active))
            return active

    def revoke_proposal(self, proposal_id: str) -> None:
        """Marca una propuesta como revocada.

        La revocación es idempotente; si la propuesta ya está revocada no se
        produce error.
        """
        with self._lock:
            record = self._store.get(proposal_id)
            if record is None:
                logger.warning("Attempt to revoke non‑existent proposal %s", proposal_id)
                raise ValueError(f"Proposal '{proposal_id}' does not exist.")
            if not record.revoked:
                record.revoked = True
                logger.info("Proposal %s revoked.", proposal_id)
            else:
                logger.debug("Proposal %s was already revoked.", proposal_id)

    def clear(self) -> None:
        """Vacía completamente el almacén (uso exclusivo para pruebas)."""
        with self._lock:
            self._store.clear()
            logger.info("Federation proposal store cleared.")

# Instancia singleton que puede ser importada por otros módulos.
proposal_store = FederationProposalStore()
