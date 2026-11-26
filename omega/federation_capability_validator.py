"""Omega federation capability validator

Este módulo provee funciones para validar que los descriptores de candidatos
federados cumplan con el esquema esperado antes de proceder con la generación
de propuestas y su asimilación.

Requisitos principales para un descriptor válido:
- Debe ser un ``dict``.
- Contener la clave ``'id'`` con un valor tipo ``str`` no vacío.
- Contener la clave ``'endpoint'`` con una URL válida (esquema *https*).
- Contener la clave ``'capabilities'`` como una lista no vacía de strings.
- Opcionalmente puede incluir ``'metadata'`` que debe ser un ``dict``.

Las funciones lanzan ``ValueError`` describiendo el problema encontrado,
permitiendo a los llamadores decidir si abortar o registrar la incidencia.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

__all__: List[str] = [
    "validate_candidate_descriptor",
]

# Expresión regular sencilla para validar URLs HTTPS
_HTTPS_URL_RE = re.compile(r"^https://[A-Za-z0-9.-]+(:\d+)?(/[A-Za-z0-9._~%!$&'()*+,;=\-]*)*$")


def _ensure_type(name: str, value: Any, expected_type: type) -> None:
    """Lanza ValueError si *value* no es una instancia de *expected_type*.

    Args:
        name: Nombre del campo que se está validando (para mensajes).
        value: Valor a validar.
        expected_type: Tipo esperado.
    """
    if not isinstance(value, expected_type):
        raise ValueError(f"Campo '{name}' debe ser de tipo {expected_type.__name__}, se recibió {type(value).__name__}.")


def _validate_https_url(url: str) -> None:
    """Valida que *url* sea una URL HTTPS válida según la expresión regular.

    La validación es deliberadamente conservadora; se asegura de que el esquema
    sea ``https`` y que la cadena tenga al menos un host.
    """
    if not isinstance(url, str) or not _HTTPS_URL_RE.match(url):
        raise ValueError(f"El endpoint '{url}' no es una URL HTTPS válida.")


def validate_candidate_descriptor(descriptor: Dict[str, Any]) -> None:
    """Valida la estructura y contenido de un descriptor de candidato federado.

    La función **no** devuelve un valor; si el descriptor es válido, la ejecución
    continúa sin excepción. De lo contrario, levanta ``ValueError`` con una
    descripción del problema detectado.

    Args:
        descriptor: Diccionario que representa al candidato.
    """
    if not isinstance(descriptor, dict):
        raise ValueError("El descriptor debe ser un dict.")

    # Campo 'id'
    if "id" not in descriptor:
        raise ValueError("Falta el campo obligatorio 'id' en el descriptor.")
    _ensure_type("id", descriptor["id"], str)
    if not descriptor["id"].strip():
        raise ValueError("El campo 'id' no debe estar vacío.")

    # Campo 'endpoint'
    if "endpoint" not in descriptor:
        raise ValueError("Falta el campo obligatorio 'endpoint' en el descriptor.")
    _ensure_type("endpoint", descriptor["endpoint"], str)
    _validate_https_url(descriptor["endpoint"])

    # Campo 'capabilities'
    if "capabilities" not in descriptor:
        raise ValueError("Falta el campo obligatorio 'capabilities' en el descriptor.")
    _ensure_type("capabilities", descriptor["capabilities"], list)
    if not descriptor["capabilities"]:
        raise ValueError("La lista 'capabilities' no debe estar vacía.")
    for idx, cap in enumerate(descriptor["capabilities"]):
        if not isinstance(cap, str) or not cap.strip():
            raise ValueError(f"Elemento de 'capabilities' en posición {idx} debe ser una cadena no vacía.")

    # Campo opcional 'metadata'
    if "metadata" in descriptor:
        _ensure_type("metadata", descriptor["metadata"], dict)

    # Si se llega aquí, el descriptor es considerado válido.
    return None
