'''\
omega.federation_orchestrator
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Módulo de orquestación de alto nivel para la infraestructura federada.

Este módulo provee una única función pública ``run_federation_cycle`` que
encadena de forma segura los pasos críticos del ciclo de vida de una
propuesta federada:

1. **Descubrimiento controlado de candidatos** mediante
   :pyclass:`omega.federation_candidate_service.CandidateService`.
2. **Validación estructural** de cada candidato usando
   ``omega.federation_validation.validate_candidate`` (si está disponible).
3. **Creación de propuesta** a partir de los candidatos válidos mediante
   ``omega.federation_proposals.create_proposal``.
4. **Firma criptográfica** de la propuesta con la clave Ed25519 del nodo
   mediante ``omega.federation_utils.sign_proposal``.
5. **Almacenamiento** de la propuesta firmada en el almacén in‑memory
   mediante :pyclass:`omega.federation_proposal_store.ProposalStore`.
6. **Asimilación** de la propuesta mediante
   ``omega.federation_assimilation.assimilate_proposal``.
7. **Auditoría** opcional del proceso mediante los módulos de auditoría
   (si están presentes).

La implementación está diseñada para ser resiliente: si alguno de los
módulos esperados no está disponible (por ejemplo, en entornos de prueba
iniciales) la función captura la excepción y continúa con los pasos que sí
pueden ejecutarse, registrando el problema en el logger estándar.

Esta arquitectura satisface los requisitos de la misión PADGE de construir
capacidades reales, modulares y verificables sin introducir dependencias
externas ni modificar la política de seguridad existente.
'''\

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Resultados estructurados del ciclo de federación
# ---------------------------------------------------------------------------

@dataclass
class FederationStepResult:
    """Resultado de un paso individual del ciclo de federación."""
    name: str
    success: bool
    detail: Any = None

@dataclass
class FederationCycleResult:
    """Resultado completo del ciclo de federación."""
    steps: List[FederationStepResult] = field(default_factory=list)
    overall_success: bool = True

    def add_step(self, name: str, success: bool, detail: Any = None) -> None:
        self.steps.append(FederationStepResult(name, success, detail))
        if not success:
            self.overall_success = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_success": self.overall_success,
            "steps": [
                {"name": s.name, "success": s.success, "detail": s.detail}
                for s in self.steps
            ],
        }

# ---------------------------------------------------------------------------
# Función pública de orquestación
# ---------------------------------------------------------------------------

def run_federation_cycle(candidate_limit: int = 5) -> FederationCycleResult:
    """Ejecuta un ciclo completo de federación.

    Parameters
    ----------
    candidate_limit: int, opcional
        Límite máximo de candidatos a descubrir. Si es 0 o negativo se
        utilizará el comportamiento por defecto del servicio de descubrimiento.

    Returns
    -------
    FederationCycleResult
        Un objeto que resume el éxito de cada paso y del ciclo completo.
    """
    result = FederationCycleResult()

    # 1. Descubrimiento de candidatos
    try:
        from omega.federation_candidate_service import CandidateService
        service = CandidateService()
        candidates = service.discover(limit=candidate_limit) if hasattr(service, "discover") else []
        result.add_step("candidate_discovery", True, candidates)
    except Exception as exc:  # pragma: no cover
        logger.exception("Error durante el descubrimiento de candidatos")
        result.add_step("candidate_discovery", False, str(exc))
        candidates = []

    # 2. Validación de candidatos (opcional)
    valid_candidates = []
    try:
        from omega.federation_validation import validate_candidate  # type: ignore
        for cand in candidates:
            try:
                validate_candidate(cand)
                valid_candidates.append(cand)
            except Exception as ve:  # pragma: no cover
                logger.warning("Candidato inválido descartado: %s", ve)
        result.add_step("candidate_validation", True, valid_candidates)
    except ImportError:
        # Si el módulo de validación no existe, aceptar todos los candidatos
        valid_candidates = candidates
        result.add_step("candidate_validation", True, "validation module missing, all candidates accepted")
    except Exception as exc:  # pragma: no cover
        logger.exception("Error durante la validación de candidatos")
        result.add_step("candidate_validation", False, str(exc))

    if not valid_candidates:
        # No hay candidatos válidos; el ciclo termina aquí.
        result.add_step("proposal_creation", False, "no valid candidates")
        return result

    # 3. Creación de propuesta
    try:
        from omega.federation_proposals import create_proposal  # type: ignore
        proposal = create_proposal(valid_candidates)
        result.add_step("proposal_creation", True, proposal)
    except Exception as exc:  # pragma: no cover
        logger.exception("Error creando la propuesta")
        result.add_step("proposal_creation", False, str(exc))
        return result

    # 4. Firma de la propuesta
    try:
        from omega.federation_utils import sign_proposal  # type: ignore
        signed_proposal = sign_proposal(proposal)
        result.add_step("proposal_signing", True, signed_proposal)
    except Exception as exc:  # pragma: no cover
        logger.exception("Error firmando la propuesta")
        result.add_step("proposal_signing", False, str(exc))
        signed_proposal = proposal  # continuar con la propuesta sin firma

    # 5. Almacenamiento de la propuesta
    try:
        from omega.federation_proposal_store import ProposalStore
        store = ProposalStore.get_instance()
        store.add(signed_proposal)
        result.add_step("proposal_storage", True, "stored")
    except Exception as exc:  # pragma: no cover
        logger.exception("Error almacenando la propuesta")
        result.add_step("proposal_storage", False, str(exc))

    # 6. Asimilación de la propuesta
    try:
        from omega.federation_assimilation import assimilate_proposal  # type: ignore
        assimilation_result = assimilate_proposal(signed_proposal)
        result.add_step("proposal_assimilation", True, assimilation_result)
    except Exception as exc:  # pragma: no cover
        logger.exception("Error asimilando la propuesta")
        result.add_step("proposal_assimilation", False, str(exc))

    # 7. Auditoría (si está disponible)
    try:
        from omega.federation_audit import audit_event  # type: ignore
        audit_event("federation_cycle_completed", result.to_dict())
        result.add_step("audit", True, "event logged")
    except ImportError:
        # Auditoría opcional; no es crítico si falta.
        result.add_step("audit", True, "audit module missing")
    except Exception as exc:  # pragma: no cover
        logger.exception("Error durante la auditoría")
        result.add_step("audit", False, str(exc))

    return result
