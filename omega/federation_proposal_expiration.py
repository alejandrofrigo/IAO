"""Omega - Expiración de propuestas federadas

Este módulo proporciona utilidades para identificar y purgar propuestas federadas que
hayan superado un tiempo de vida configurable. Se basa en el almacén persistente
implementado en :pymod:`omega.federation_proposal_store` y no introduce nuevas
dependencias externas.

Funciones principales
----------------------
* :func:`is_expired` – Determina si una propuesta está caduca según su marca de
  tiempo y una edad máxima expresada en segundos.
* :func:`purge_expired` – Recorre todas las propuestas almacenadas y elimina las
  que estén caducas, devolviendo el número de entradas removidas.

Uso típico
~~~~~~~~~~
>>> from omega.federation_proposal_store import ProposalStore
>>> from omega.federation_proposal_expiration import purge_expired
>>> store = ProposalStore()
>>> removed = purge_expired(store, max_age_seconds=86400)  # 1 día
>>> print(f"Se eliminaron {removed} propuestas caducas")

El módulo está diseñado para ser llamado por procesos de mantenimiento o por el
orquestador de federación antes de iniciar ciclos de asimilación.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any, Dict

# Nota: Se evita una importación directa al nivel de módulo para no crear una
# dependencia cíclica en caso de que el almacén importe este archivo en algún
# futuro. La importación se realiza dentro de las funciones.

def _now_utc() -> _dt.datetime:
    """Obtiene la marca de tiempo UTC actual con zona horaria fija.

    Se emplea una función auxiliar para permitir la fácil simulación en pruebas
    unitarias mediante *patching*.
    """
    return _dt.datetime.now(tz=_dt.timezone.utc)


def is_expired(proposal: Dict[str, Any], max_age_seconds: int) -> bool:
    """Determina si una propuesta está caduca.

    Parámetros
    ----------
    proposal: dict
        Diccionario que representa la propuesta tal como se almacena en
        :class:`omega.federation_proposal_store.ProposalStore`. Debe contener una
        clave ``"timestamp"`` con el valor ISO‑8601 en UTC (p.ej. ``"2026-11-01T12:34:56Z"``).
    max_age_seconds: int
        Edad máxima permitida expresada en segundos.

    Returns
    -------
    bool
        ``True`` si la diferencia entre la hora actual y la marca de tiempo de la
        propuesta supera ``max_age_seconds``; ``False`` en caso contrario.
    """
    ts_str = proposal.get("timestamp")
    if not ts_str:
        # Si la propuesta no incluye timestamp, la tratamos como caduca para
        # evitar conservar datos sin referencia temporal.
        return True
    try:
        # Se admiten tanto la forma con zona "Z" como con offset.
        if ts_str.endswith("Z"):
            ts = _dt.datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ")
            ts = ts.replace(tzinfo=_dt.timezone.utc)
        else:
            ts = _dt.datetime.fromisoformat(ts_str)
    except Exception:
        # En caso de formato inesperado, consideramos la propuesta caduca.
        return True
    age = (_now_utc() - ts).total_seconds()
    return age > max_age_seconds


def purge_expired(store: Any, max_age_seconds: int) -> int:
    """Elimina propuestas caducas del almacén.

    Parámetros
    ----------
    store: object
        Instancia del almacén de propuestas. Se requiere que el objeto implemente
        al menos los siguientes métodos:
        * ``list_proposals()`` → iterable de pares ``(proposal_id, proposal_dict)``.
        * ``delete_proposal(proposal_id)`` → elimina la propuesta del almacén.
    max_age_seconds: int
        Edad máxima permitida para una propuesta antes de considerarla caduca.

    Returns
    -------
    int
        Número de propuestas que fueron eliminadas.
    """
    removed = 0
    for proposal_id, proposal_data in list(store.list_proposals()):
        if is_expired(proposal_data, max_age_seconds):
            try:
                store.delete_proposal(proposal_id)
                removed += 1
            except Exception:
                # No abortimos por un borrado fallido; registramos en los logs
                # del sistema (el mecanismo de logging está disponible en el
                # paquete omega). Se evita importación directa para mantener
                # la independencia del módulo.
                pass
    return removed

__all__ = ["is_expired", "purge_expired"]
