"""Omega Federation Flow

Este módulo expone una función de alto nivel `execute_federation_flow` que coordina
el descubrimiento de candidatos, su validación, la creación y firma de propuestas,
la asimilación y el registro de estado mediante los componentes ya presentes en
el paquete `omega`.

La función está diseñada para ser segura, reutilizable y fácil de testear:
- No realiza conexiones externas por sí misma; delega a los módulos de
  descubrimiento y validación que ya implementan los controles necesarios.
- Captura y registra excepciones de cada etapa, devolviendo un diccionario de
  resultados que indica el éxito o el motivo de fallo por candidato.
- Utiliza `FederationManager` como punto de entrada único al ciclo de vida del
  candidato, garantizando que el seguimiento de estado se mantenga coherente.
"""

from __future__ import annotations

from typing import Dict, List

# Importar los componentes ya existentes en la base de código.
from .federation_candidate import FederationCandidate
from .federation_discovery_controller import FederationDiscoveryController
from .federation_manager import FederationManager
from .federation_tracker import FederationTracker

__all__ = ["execute_federation_flow"]


def _load_candidates(source_path: str) -> List[FederationCandidate]:
    """Utilidad interna para cargar candidatos desde un archivo.

    Se delega a :class:`FederationDiscoveryController`, que ya implementa la
    lógica de lectura segura, validación de formato y control de errores.
    """
    controller = FederationDiscoveryController(source_path)
    return controller.discover()


def execute_federation_flow(source_path: str) -> Dict[str, str]:
    """Ejecuta el flujo completo de federación para todos los candidatos
    descubiertos en ``source_path``.

    Parameters
    ----------
    source_path: str
        Ruta al archivo (JSON, YAML o CSV) que contiene la lista de candidatos
        federados a procesar.

    Returns
    -------
    Dict[str, str]
        Mapeo ``candidate_id -> resultado`` donde el valor es ``"success"`` o
        una cadena descriptiva de error.

    Notas de seguridad
    -------------------
    * No se registra ni se persiste información sensible.
    * Cada etapa usa los módulos con sus propias auditorías y controles de
      revocación.
    * En caso de error crítico se captura la excepción y se continua con el
      siguiente candidato, garantizando que la ejecución de otros candidatos
      no se vea interrumpida.
    """
    results: Dict[str, str] = {}
    tracker = FederationTracker()
    manager = FederationManager(tracker=tracker)

    try:
        candidates = _load_candidates(source_path)
    except Exception as exc:
        # Si el descubrimiento falla, devolvemos un error global.
        raise RuntimeError(f"Error al descubrir candidatos desde '{source_path}': {exc}")

    for candidate in candidates:
        candidate_id = getattr(candidate, "id", str(candidate))
        try:
            # El manager se encarga de validar, firmar la propuesta y asimilar.
            manager.process_candidate(candidate)
            results[candidate_id] = "success"
        except Exception as exc:
            # Registrar el fallo en el tracker y devolver información al llamador.
            tracker.record_failure(candidate_id, str(exc))
            results[candidate_id] = f"failed: {exc}"

    return results
