"""omega.federation_integration
=================================

Este módulo provee una API de alto nivel para ejecutar el flujo completo de
federación sobre un *candidato* único.  Las etapas son:

1. **Validación** de capacidades y conectividad del candidato.
2. **Actualización** del estado del candidato en el rastreador.
3. **Construcción** y firma de una propuesta federada.
4. **Asimilación** de la propuesta firmada.
5. **Actualización** final del estado del candidato.

La función está diseñada para ser utilizada por pruebas automatizadas y por
componentes externos que necesiten un punto de entrada único sin tener que
re‑implementar la lógica de orquestación.
"""

from __future__ import annotations

from typing import Any, Dict

# Importes perezosos para evitar costos de importación innecesarios cuando el
# módulo no se use directamente.

def _lazy_import(module_name: str):
    import importlib

    return importlib.import_module(module_name)


def run_federation_pipeline(candidate: Any) -> Dict[str, Any]:
    """Ejecuta el flujo completo de federación para *candidate*.

    Parámetros
    ----------
    candidate: Any
        Objeto que representa al candidato federado.  Se espera que tenga al
        menos los atributos ``id`` y ``metadata`` utilizados por los módulos
        de validación y rastreo.

    Retorna
    -------
    dict
        Un diccionario con la siguiente estructura::

            {
                "success": bool,                 # Indicador global
                "details": str,                  # Mensaje descriptivo
                "proposal": Optional[Any]        # Propuesta firmada (si tuvo éxito)
            }

    La función captura cualquier excepción inesperada, actualiza el estado del
    candidato a ``FAILED`` y devuelve ``success=False`` con la información del
    error.
    """

    # Importes perezosos para mantener el módulo ligero y evitar dependencias
    # cíclicas en tiempo de carga.
    federation_validation = _lazy_import("omega.federation_validation")
    federation_tracker = _lazy_import("omega.federation_tracker")
    federation_proposal_builder = _lazy_import("omega.federation_proposal_builder")
    federation_assimilation_api = _lazy_import("omega.federation_assimilation_api")

    try:
        # -----------------------------------------------------------------
        # 1. Validación del candidato
        # -----------------------------------------------------------------
        validation_result = federation_validation.validate_candidate(candidate)
        if not getattr(validation_result, "is_valid", False):
            # Marcar como inválido y terminar.
            federation_tracker.update_candidate_state(
                candidate.id,
                federation_tracker.CandidateState.INVALID,
                reason=getattr(validation_result, "reason", "validation failed"),
            )
            return {
                "success": False,
                "details": f"Validación fallida: {getattr(validation_result, 'reason', 'desconocido')}",
                "proposal": None,
            }

        # Estado VALIDATED
        federation_tracker.update_candidate_state(
            candidate.id, federation_tracker.CandidateState.VALIDATED
        )

        # -----------------------------------------------------------------
        # 2. Construcción y firma de la propuesta
        # -----------------------------------------------------------------
        proposal = federation_proposal_builder.build_signed_proposal(candidate)

        # -----------------------------------------------------------------
        # 3. Asimilación de la propuesta firmada
        # -----------------------------------------------------------------
        federation_assimilation_api.assimilate_signed_proposal(proposal)

        # Estado ASSIMILATED
        federation_tracker.update_candidate_state(
            candidate.id, federation_tracker.CandidateState.ASSIMILATED
        )

        return {
            "success": True,
            "details": "Candidato procesado exitosamente",
            "proposal": proposal,
        }

    except Exception as exc:  # pragma: no cover – captura genérica para robustez
        # Intentar registrar el fallo antes de re‑elevar la excepción.
        try:
            federation_tracker.update_candidate_state(
                getattr(candidate, "id", "unknown"),
                federation_tracker.CandidateState.FAILED,
                reason=str(exc),
            )
        finally:
            return {
                "success": False,
                "details": f"Excepción durante el flujo: {exc}",
                "proposal": None,
            }


__all__ = ["run_federation_pipeline"]
