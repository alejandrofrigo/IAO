'''Controlador de descubrimiento de candidatos federados con límite y métricas.

Este módulo provee una API de alto nivel que envuelve la funcionalidad de
`omega.federation_candidate_discovery` (presumiblemente existente) y agrega:

1. **Límite opcional** – permite al operador solicitar un número máximo de
   candidatos en una sola invocación sin modificar la lógica interna del
   descubridor.
2. **Métricas en memoria** – contabiliza total de descubrimientos, número
   de candidatos devueltos y tiempos de ejecución para facilitar auditoría y
   monitoreo.
3. **Exposición de métricas** – método `get_metrics` que devuelve un dict
   serializable con los contadores actuales.

La implementación es deliberadamente ligera y sin dependencias externas para
mantener la seguridad y la capacidad de rollback. Utiliza la función
`discover_all_candidates` que debe estar definida en
`omega.federation_candidate_discovery`. Si el módulo subyacente no está
presente, se genera una excepción clara para que el operador pueda
proveer la implementación adecuada.
'''  # noqa: D400

import time
from typing import Any, Dict, List, Optional

# Importación segura del descubridor subyacente.
try:
    from .federation_candidate_discovery import discover_all_candidates  # tipo: ignore
except ImportError as exc:
    raise ImportError(
        "El módulo 'omega.federation_candidate_discovery' debe exponer la función "
        "'discover_all_candidates' para que el controlador pueda operar."
    ) from exc


class CandidateDiscoveryController:
    """Controlador que limita y monitorea la detección de candidatos.

    La clase mantiene contadores simples en memoria que pueden resetearse con
    `reset_metrics`. Cada llamada a :meth:`discover` actualiza los contadores
    y devuelve una lista de candidatos (cualquiera sea su representación).
    """

    def __init__(self) -> None:
        self._total_calls: int = 0
        self._total_candidates: int = 0
        self._cumulative_time_ms: float = 0.0

    def discover(self, limit: Optional[int] = None) -> List[Any]:
        """Descubre candidatos respetando un límite opcional.

        Parameters
        ----------
        limit: int | None
            Número máximo de candidatos a devolver. Si ``None`` o ``<= 0``
            se devuelven todos los candidatos descubiertos.

        Returns
        -------
        list
            Lista de candidatos (cualquier objeto devuelto por
            ``discover_all_candidates``) truncada al límite especificado.
        """
        start = time.perf_counter()
        all_candidates = discover_all_candidates()
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        # Aplicar límite de forma segura.
        if limit is not None and limit > 0:
            result = all_candidates[:limit]
        else:
            result = list(all_candidates)  # garantiza una lista nueva.

        # Actualizar métricas.
        self._total_calls += 1
        self._total_candidates += len(result)
        self._cumulative_time_ms += elapsed_ms
        return result

    def get_metrics(self) -> Dict[str, Any]:
        """Devuelve un snapshot de las métricas de descubrimiento.

        Returns
        -------
        dict
            Contiene ``calls``, ``candidates_returned`` y ``average_latency_ms``.
        """
        avg_latency = (
            self._cumulative_time_ms / self._total_calls
            if self._total_calls > 0
            else 0.0
        )
        return {
            "calls": self._total_calls,
            "candidates_returned": self._total_candidates,
            "average_latency_ms": round(avg_latency, 3),
        }

    def reset_metrics(self) -> None:
        """Reinicia todos los contadores a cero."""
        self._total_calls = 0
        self._total_candidates = 0
        self._cumulative_time_ms = 0.0

    # Representación útil para depuración.
    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<CandidateDiscoveryController calls={self._total_calls} "
            f"candidates={self._total_candidates} avg_latency={self.get_metrics()['average_latency_ms']}ms>"
        )
