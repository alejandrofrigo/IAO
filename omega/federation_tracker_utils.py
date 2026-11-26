"""Utilities for querying the FederationTracker.

Este módulo complementa :pymod:`omega.federation_tracker` ofreciendo funciones
de alto nivel para inspeccionar el estado de los candidatos federados.
No introduce persistencia adicional ni modifica el comportamiento del
tracker; simplemente consume su API pública.

Funciones principales:

* ``list_candidates_by_state(tracker, state)`` – Devuelve una lista de IDs
  de candidatos cuyo estado coincide con ``state``.
* ``summarize_tracker(tracker)`` – Genera un dict con el recuento de
  candidatos por cada estado registrado.

El código está escrito para ser seguro en entornos multihilo mediante el
uso de bloqueos internos del propio ``FederationTracker`` (se asume que el
tracker expone métodos ``get_all()`` y ``get_state(id)`` que son thread‑safe).
"""

from __future__ import annotations

from collections import Counter
from typing import Dict, List, Mapping

# Importamos la clase base del tracker. Se asume que está disponible en el
# paquete ``omega`` y que sigue la interfaz mínima descrita en la docstring.
from .federation_tracker import FederationTracker, CandidateState


def list_candidates_by_state(tracker: FederationTracker, state: CandidateState) -> List[str]:
    """Return a list of candidate identifiers that are currently in *state*.

    Parameters
    ----------
    tracker: FederationTracker
        Instancia del rastreador que contiene los candidatos.
    state: CandidateState
        Estado que se desea filtrar.

    Returns
    -------
    List[str]
        Identificadores (IDs) de los candidatos cuyo estado coincide.
    """
    # ``tracker.get_all()`` se espera que devuelva un mapping id -> candidate
    # donde cada candidato posee un atributo ``state`` o un método ``get_state``.
    # Para mantener compatibilidad con distintas implementaciones usamos
    # ``getattr`` con fallback.
    result: List[str] = []
    for cand_id, candidate in tracker.get_all().items():
        cand_state = getattr(candidate, "state", None)
        if cand_state is None:
            # Compatibilidad con versiones que exponen ``get_state``
            cand_state = getattr(candidate, "get_state", lambda: None)()
        if cand_state == state:
            result.append(cand_id)
    return result


def summarize_tracker(tracker: FederationTracker) -> Dict[CandidateState, int]:
    """Generate a summary count of candidates per ``CandidateState``.

    The function iterates over todos los candidatos almacenados en *tracker*
    y contabiliza cuántos se encuentran en cada estado posible.  El retorno es
    un ``dict`` cuya clave es el enum ``CandidateState`` y cuyo valor es el
    número de candidatos en ese estado.
    """
    counter: Counter = Counter()
    for candidate in tracker.get_all().values():
        cand_state = getattr(candidate, "state", None)
        if cand_state is None:
            cand_state = getattr(candidate, "get_state", lambda: None)()
        if cand_state is not None:
            counter[cand_state] += 1
    # Convertir Counter a dict con tipos exactos para mayor claridad.
    return dict(counter)


__all__ = ["list_candidates_by_state", "summarize_tracker"]
