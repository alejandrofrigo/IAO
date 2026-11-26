"""Omega Federation Lifecycle
================================
Este módulo provee una API de alto nivel que unifica las capacidades
existentes de la infraestructura federada para gestionar el ciclo de vida
completo de un candidato participante:

1. **Registro y validación** del candidato mediante ``FederationCandidateService``.
2. **Generación y firma** de propuestas federadas usando ``FederationProposalProcessor``.
3. **Asimilación** segura de propuestas mediante ``FederationAssimilationAPI``.
4. **Revocación** de candidatos autorizados con auditoría de la firma del
   operador.

Al proporcionar una única clase ``FederationLifecycle`` los operadores y
las pruebas pueden ejecutar flujos completos con una sola llamada, mejorando
la cohesión del código y la verificabilidad de la red federada.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional

# Importar los componentes existentes de la infraestructura federada.
# Estos módulos ya fueron introducidos en cambios previos y están
# disponibles en el paquete ``omega`` gracias al cargador lazy.
from .federation_candidate_service import FederationCandidateService
from .federation_proposal_processor import FederationProposalProcessor
from .federation_assimilation_api import FederationAssimilationAPI
from .federation_candidate_revocation_service import (
    FederationCandidateRevocationService,
)

_logger = logging.getLogger(__name__)


@dataclass
class CandidateInfo:
    """Representación mínima de los datos de un candidato.

    Los campos son los que los servicios de validación esperan. Se utiliza
    ``dataclass`` para facilitar la (de)serialización y la documentación
    automática.
    """

    identifier: str
    endpoint: str  # URL HTTPS del nodo candidato
    public_key: str  # Clave pública Ed25519 codificada en base64
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serializa el candidato a un diccionario listo para JSON."""
        data: Dict[str, Any] = {
            "identifier": self.identifier,
            "endpoint": self.endpoint,
            "public_key": self.public_key,
        }
        if self.metadata:
            data["metadata"] = self.metadata
        return data


class FederationLifecycle:
    """Orquestador de ciclo de vida federado.

    Esta clase combina los servicios de bajo nivel en operaciones de dominio
    que son fáciles de usar y están cubiertas por auditoría y registro.
    """

    def __init__(
        self,
        candidate_service: Optional[FederationCandidateService] = None,
        proposal_processor: Optional[FederationProposalProcessor] = None,
        assimilation_api: Optional[FederationAssimilationAPI] = None,
        revocation_service: Optional[FederationCandidateRevocationService] = None,
    ) -> None:
        self.candidate_service = candidate_service or FederationCandidateService()
        self.proposal_processor = proposal_processor or FederationProposalProcessor()
        self.assimilation_api = assimilation_api or FederationAssimilationAPI()
        self.revocation_service = revocation_service or FederationCandidateRevocationService()
        _logger.debug("FederationLifecycle inicializado con servicios predeterminados")

    # ---------------------------------------------------------------------
    # Registro y validación de candidatos
    # ---------------------------------------------------------------------
    def register_candidate(self, info: CandidateInfo) -> str:
        """Registra un nuevo candidato después de validar su estructura.

        Args:
            info: Información del candidato a registrar.

        Returns:
            Un identificador interno único asignado al candidato.
        """
        _logger.info("Registrando candidato %s", info.identifier)
        # El servicio de candidato ya implementa validación estructural y de
        # conectividad. Se delega directamente.
        candidate_id = self.candidate_service.register_candidate(info.to_dict())
        _logger.debug("Candidato registrado con id %s", candidate_id)
        return candidate_id

    # ---------------------------------------------------------------------
    # Generación y firma de propuestas federadas
    # ---------------------------------------------------------------------
    def create_signed_proposal(
        self, candidate_id: str, operator_private_key: bytes
    ) -> Dict[str, Any]:
        """Genera una propuesta federada para el candidato especificado y la firma.

        La firma utiliza Ed25519 (el algoritmo pre‑configurado en la
        infraestructura). Se delega la creación del cuerpo de la propuesta al
        ``FederationProposalProcessor`` y la firma a dicho procesador.
        """
        _logger.info("Creando propuesta firmada para candidato %s", candidate_id)
        candidate_data = self.candidate_service.get_candidate(candidate_id)
        if not candidate_data:
            raise ValueError(f"Candidato con id {candidate_id} no encontrado")

        # Construir la propuesta base.
        proposal_body = {
            "candidate_id": candidate_id,
            "candidate": candidate_data,
            "timestamp": self.proposal_processor.current_timestamp(),
        }

        # "process" produce la propuesta con firma incluida.
        signed_proposal = self.proposal_processor.process(proposal_body, operator_private_key)
        _logger.debug("Propuesta firmada creada: %s", json.dumps(signed_proposal)[:200])
        return signed_proposal

    # ---------------------------------------------------------------------
    # Asimilación de propuestas
    # ---------------------------------------------------------------------
    def assimilate_proposal(self, signed_proposal: Dict[str, Any]) -> bool:
        """Asimila una propuesta previamente firmada.

        La asimilación incluye verificación de firma y registro interno.
        Devuelve ``True`` si la asimilación fue exitosa.
        """
        _logger.info("Asimilando propuesta para candidato %s", signed_proposal.get("candidate_id"))
        result = self.assimilation_api.assimilate(signed_proposal)
        _logger.debug("Asimilación resultó en %s", result)
        return result

    # ---------------------------------------------------------------------
    # Revocación de candidatos
    # ---------------------------------------------------------------------
    def revoke_candidate(self, candidate_id: str, operator_signature: bytes) -> bool:
        """Revoca un candidato autorizado.

        Se requiere la firma del operador (Ed25519) sobre el identificador del
        candidato para evitar revocaciones no autorizadas.
        """
        _logger.warning("Revocando candidato %s", candidate_id)
        success = self.revocation_service.revoke(candidate_id, operator_signature)
        _logger.debug("Revocación completada con éxito=%s", success)
        return success

    # ---------------------------------------------------------------------
    # Helper utilities
    # ---------------------------------------------------------------------
    @staticmethod
    def load_private_key(pem_path: str) -> bytes:
        """Carga una clave privada Ed25519 desde un archivo PEM.

        Esta utilidad está pensada para pruebas y operaciones de operador
        controlado; no se incluye gestión de almacenes seguros.
        """
        with open(pem_path, "rb") as fh:
            return fh.read()

    @staticmethod
    def load_public_key(pem_path: str) -> bytes:
        """Carga una clave pública Ed25519 desde un archivo PEM."""
        with open(pem_path, "rb") as fh:
            return fh.read()

# Exportar la clase principal como parte de la API pública del paquete.
__all__ = ["FederationLifecycle", "CandidateInfo"]
