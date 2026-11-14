import time
from typing import List

# Importaciones opcionales que pueden no estar presentes en todas las versiones.
# Se usan dentro de bloques try/except para mantener compatibilidad.
try:
    from .federation_candidate_io import load_all_candidates
except Exception:  # pragma: no cover
    load_all_candidates = None  # type: ignore

try:
    from .federation_tracker import remove_candidate
except Exception:  # pragma: no cover
    remove_candidate = None  # type: ignore


def prune_stale_candidates(max_age_seconds: int) -> List[str]:
    """Eliminar candidatos federados que no se hayan actualizado en *max_age_seconds*.

    Esta función inspecciona todos los candidatos almacenados mediante
    ``load_all_candidates`` (si está disponible) y, para aquellos cuyo
    campo ``last_updated`` sea más antiguo que el umbral, intenta retirarlos
    del rastreador mediante ``remove_candidate`` (si está disponible).

    Parameters
    ----------
    max_age_seconds: int
        Edad máxima permitida, en segundos, desde la última actualización.

    Returns
    -------
    List[str]
        Identificadores de los candidatos que fueron removidos. Si la
        infraestructura de carga o eliminación no está disponible, la lista
        estará vacía.
    """
    if max_age_seconds <= 0:
        raise ValueError("max_age_seconds must be a positive integer")

    if load_all_candidates is None:
        # No hay mecanismo de carga, nada que purgar.
        return []

    now = time.time()
    removed_ids: List[str] = []

    try:
        candidates = load_all_candidates()
    except Exception:  # pragma: no cover
        # Si ocurre cualquier error al cargar, consideramos que no hay candidatos
        # que procesar.
        return []

    for cand in candidates:
        # Se acepta tanto objetos con atributos como diccionarios.
        cand_id = getattr(cand, "candidate_id", None) or cand.get("candidate_id") if isinstance(cand, dict) else None
        if cand_id is None:
            # Compatibilidad con posibles nombres alternativos.
            cand_id = getattr(cand, "id", None) or (cand.get("id") if isinstance(cand, dict) else None)
        if cand_id is None:
            continue

        last_updated = getattr(cand, "last_updated", None) or (cand.get("last_updated") if isinstance(cand, dict) else None)
        if last_updated is None:
            continue
        try:
            age = now - float(last_updated)
        except Exception:  # pragma: no cover
            continue
        if age > max_age_seconds:
            # Intentar eliminar del rastreador si la función está disponible.
            if callable(remove_candidate):
                try:
                    remove_candidate(cand_id)
                except Exception:  # pragma: no cover
                    # No detener el proceso si la eliminación falla.
                    pass
            removed_ids.append(str(cand_id))

    return removed_ids
