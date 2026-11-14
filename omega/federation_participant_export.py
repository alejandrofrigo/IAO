# -*- coding: utf-8 -*-
"""Exportación de participantes federados registrados.

Esta utilidad permite obtener una lista serializable en JSON que describe cada
participante actualmente registrado en la red federada. Es útil para auditoría,
monitoreo y pruebas sin alterar el comportamiento del registro interno.
"""

from __future__ import annotations

from typing import Any, Dict, List

__all__ = ["export_registered_participants"]


def _load_registry() -> Dict[str, Dict[str, Any]]:
    """Carga de forma segura el registro interno de participantes.

    Se intenta importar el módulo que mantiene el registro. Si el módulo o el
    símbolo esperado no están disponibles (por ejemplo, en entornos de pruebas
    aislados), se devuelve un diccionario vacío para que la función sea
    determinista y no genere excepciones inesperadas.
    """
    try:
        # El registro se define típicamente en `omega.federation_participant_registry`
        # bajo un nombre como ``PARTICIPANT_REGISTRY`` o a través de una función
        # ``get_registry``. Probamos ambas posibilidades.
        from .federation_participant_registry import PARTICIPANT_REGISTRY
        return dict(PARTICIPANT_REGISTRY)  # Copia para evitar mutaciones externas
    except Exception:
        try:
            from .federation_participant_registry import get_registry
            return dict(get_registry())
        except Exception:
            # Registro inexistente o inaccesible; devolvemos vacío.
            return {}


def export_registered_participants() -> List[Dict[str, Any]]:
    """Devuelve una lista de diccionarios con la información de cada participante.

    Cada entrada contiene al menos los campos ``participant_id`` y ``endpoint``.
    Opcionalmente se incluyen los metadatos adicionales que el registro almacene
    bajo la clave ``metadata``.
    """
    registry = _load_registry()
    exported: List[Dict[str, Any]] = []
    for participant_id, info in registry.items():
        exported.append(
            {
                "participant_id": participant_id,
                "endpoint": info.get("endpoint"),
                "metadata": info.get("metadata", {}),
            }
        )
    return exported
