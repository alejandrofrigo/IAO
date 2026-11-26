'''omega/federation_coordinator.py

Coordinador de alto nivel para la infraestructura federada.

Este módulo reúne los componentes ya presentes en el paquete ``omega``:

* :pymod:`omega.federation_candidate_service` – Servicio que permite descubrir
  candidatos de forma controlada y registrar métricas internas.
* :pymod:`omega.federation_proposal_manager` – Lógica para crear, firmar y
  validar propuestas federadas.
* :pymod:`omega.federation_proposal_store` – Almacén en‑memoria que persiste
  propuestas y permite consultas, revocaciones y listados.
* :pymod:`omega.federation_assimilation` – Procesador que asimila una propuesta
  aceptada, verifica su firma y actualiza el estado interno.

El objetivo es ofrecer una única función ``run_federation_cycle`` que ejecuta
el flujo completo de descubrimiento → propuesta → firma → almacenamiento →
asimilación.  La función está diseñada para ser utilizada por los tests y por
el operador sin necesidad de conocer los detalles internos de cada sub‑módulo.

Todas las operaciones están encapsuladas en bloques ``try/except`` con
excepciones específicas para que el llamador pueda diagnosticar fallos sin
exponer información sensible.
'''  

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Importes perezosos para evitar ciclos de dependencia y respetar el
# cargador lazy que ya está implementado en ``omega.__init__``.
try:
    from .federation_candidate_service import FederationCandidateService
except Exception as exc:  # pragma: no cover
    FederationCandidateService = None  # type: ignore
    logger.debug("FederationCandidateService no está disponible: %s", exc)

try:
    from .federation_proposal_manager import FederationProposalManager
except Exception as exc:  # pragma: no cover
    FederationProposalManager = None  # type: ignore
    logger.debug("FederationProposalManager no está disponible: %s", exc)

try:
    from .federation_proposal_store import ProposalStore
except Exception as exc:  # pragma: no cover
    ProposalStore = None  # type: ignore
    logger.debug("ProposalStore no está disponible: %s", exc)

try:
    from .federation_assimilation import assimilate_proposal
except Exception as exc:  # pragma: no cover
    assimilate_proposal = None  # type: ignore
    logger.debug("assimilate_proposal no está disponible: %s", exc)


class FederationCoordinator:
    """Coordinador de alto nivel para la interacción federada.

    El coordinador mantiene una instancia de cada componente necesario y expone
    métodos que realizan acciones atomísticas y combinadas.
    """

    def __init__(self, candidate_limit: Optional[int] = None):
        if FederationCandidateService is None:
            raise RuntimeError("FederationCandidateService no está disponible en el entorno actual.")
        if FederationProposalManager is None:
            raise RuntimeError("FederationProposalManager no está disponible en el entorno actual.")
        if ProposalStore is None:
            raise RuntimeError("ProposalStore no está disponible en el entorno actual.")
        if assimilate_proposal is None:
            raise RuntimeError("assimilate_proposal no está disponible en el entorno actual.")

        self.candidate_service = FederationCandidateService()
        self.proposal_manager = FederationProposalManager()
        self.store = ProposalStore()
        self._candidate_limit = candidate_limit

    # ---------------------------------------------------------------------
    # Descubrimiento de candidatos
    # ---------------------------------------------------------------------
    def discover_candidates(self) -> List[Dict[str, Any]]:
        """Descubre candidatos controlados por ``candidate_limit``.

        Returns
        -------
        list[dict]
            Cada diccionario representa un candidato con al menos la clave
            ``id``.  Otros campos son opcionales y dependen del servicio.
        """
        limit = self._candidate_limit
        try:
            candidates = self.candidate_service.discover(limit=limit)
            logger.debug("Descubiertos %d candidatos (límite=%s)", len(candidates), limit)
            return candidates
        except Exception as exc:
            logger.error("Error durante el descubrimiento de candidatos: %s", exc)
            raise

    # ---------------------------------------------------------------------
    # Creación y firma de propuesta
    # ---------------------------------------------------------------------
    def create_and_sign_proposal(self, candidate: Dict[str, Any], payload: Any) -> Any:
        """Crea una propuesta a partir de un candidato y la firma.

        Parameters
        ----------
        candidate: dict
            Información del candidato que se incluirá en la propuesta.
        payload: Any
            Datos de negocio que la propuesta debe transportar.

        Returns
        -------
        Any
            Objeto de propuesta ya firmado y validado.
        """
        try:
            proposal = self.proposal_manager.create_proposal(candidate, payload)
            signed = self.proposal_manager.sign_proposal(proposal)
            logger.debug("Propuesta creada y firmada para candidato %s", candidate.get('id'))
            return signed
        except Exception as exc:
            logger.error("Fallo al crear/firma la propuesta para candidato %s: %s", candidate.get('id'), exc)
            raise

    # ---------------------------------------------------------------------
    # Persistencia de la propuesta
    # ---------------------------------------------------------------------
    def store_proposal(self, proposal: Any) -> None:
        """Almacena la propuesta en el ``ProposalStore`` interno.
        """
        try:
            self.store.add(proposal)
            logger.debug("Propuesta almacenada con id %s", getattr(proposal, 'id', '<sin-id>'))
        except Exception as exc:
            logger.error("Error al almacenar la propuesta: %s", exc)
            raise

    # ---------------------------------------------------------------------
    # Asimilación de la propuesta
    # ---------------------------------------------------------------------
    def assimilate(self, proposal_id: str) -> Any:
        """Asimila una propuesta previamente almacenada.

        Parameters
        ----------
        proposal_id: str
            Identificador único de la propuesta a asimilar.
        """
        try:
            proposal = self.store.get(proposal_id)
            if proposal is None:
                raise KeyError(f"Propuesta con id {proposal_id} no encontrada en el almacén.")
            result = assimilate_proposal(proposal)
            logger.debug("Propuesta %s asimilada exitosamente", proposal_id)
            return result
        except Exception as exc:
            logger.error("Fallo al asimilar la propuesta %s: %s", proposal_id, exc)
            raise

    # ---------------------------------------------------------------------
    # Ciclo completo de federación para un conjunto limitado de candidatos
    # ---------------------------------------------------------------------
    def run_cycle(self, payload_factory: Optional[callable] = None) -> Dict[str, Any]:
        """Ejecuta el flujo completo de federación.

        Opcionalmente se puede pasar una ``payload_factory`` que recibe el
        diccionario del candidato y devuelve el payload a incluir en la
        propuesta.  Si no se provee, se usará un payload vacío.

        Returns
        -------
        dict
            Resumen del ciclo con claves ``candidates``, ``proposals`` y
            ``assimilation_results``.
        """
        summary: Dict[str, Any] = {
            "candidates": [],
            "proposals": [],
            "assimilation_results": [],
        }

        candidates = self.discover_candidates()
        summary["candidates"] = candidates

        for cand in candidates:
            try:
                payload = payload_factory(cand) if payload_factory else {}
                proposal = self.create_and_sign_proposal(cand, payload)
                self.store_proposal(proposal)
                summary["proposals"].append(proposal)
                # Asimilamos inmediatamente para mantener el ciclo compacto.
                result = self.assimilate(getattr(proposal, "id"))
                summary["assimilation_results"].append({"id": getattr(proposal, "id"), "result": result})
            except Exception as exc:
                logger.warning("Ciclo de federación parcial falló para candidato %s: %s", cand.get('id'), exc)
                continue
        return summary


def run_federation_cycle(candidate_limit: Optional[int] = None, payload_factory: Optional[callable] = None) -> Dict[str, Any]:
    """Conveniencia de una única llamada para ejecutar el ciclo completo.

    Esta función de nivel de módulo permite a los tests y a los operadores
    iniciar la orquestación sin necesidad de instanciar explícitamente la clase.
    """
    coordinator = FederationCoordinator(candidate_limit=candidate_limit)
    return coordinator.run_cycle(payload_factory=payload_factory)
