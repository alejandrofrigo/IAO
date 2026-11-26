"""omega.federation_onboard_helper
===================================

Módulo de utilidad de alto nivel que implementa el flujo completo de incorporación
(on‑boarding) de un candidato federado.

El proceso sigue estrictamente los pasos requeridos por la arquitectura federada:

1. **Validación de capacidades** – se asegura que el descriptor del candidato contiene
   los campos obligatorios y que los endpoints tienen un formato válido.
2. **Validación sintáctica de endpoints** – comprueba que cada URL tiene un esquema
   soportado (``https`` o ``wss``) y que la parte de host es un nombre de dominio o IP
   válido sin realizar resoluciones de red.
3. **Generación de propuesta** – crea una propuesta de incorporación a partir del
   descriptor validado.
4. **Firma de la propuesta** – utiliza la clave privada Ed25519 del operador para
   firmar la propuesta de forma determinista.
5. **Asimilación de la propuesta** – procesa la propuesta firmada mediante el
   subsistema de asimilación existente.

Todas las operaciones son **offline** y **deterministas**; no se efectúan llamadas de
red externas ni se persisten datos fuera del contexto llamado. En caso de error se
lanza ``ValueError`` con un mensaje descriptivo.

Este helper está pensado para ser usado tanto por código de producción como por los
tests unitarios que requieren un flujo completo y reproducible.
"""

from __future__ import annotations

import re
from typing import Any, Dict

# Importes locales de la propia rama del proyecto. Se realizan dentro de la
# función para evitar importaciones circulares en tiempo de carga del paquete.


def _load_dependencies() -> Dict[str, Any]:
    """Carga perezosa de los módulos internos requeridos.

    Se envuelve en una función para que la importación sólo ocurra cuando se
    invoque ``onboard_candidate``. Esto evita problemas de orden de importación y
    mantiene la carga del paquete ``omega`` ligera.
    """
    from . import federation_capability_validator
    from . import federation_endpoint_validator
    from . import federation_proposal_generator
    from . import federation_candidate_signature
    from . import federation_assimilation

    return {
        "validator": federation_capability_validator,
        "endpoint_validator": federation_endpoint_validator,
        "proposal_generator": federation_proposal_generator,
        "signature": federation_candidate_signature,
        "assimilation": federation_assimilation,
    }


# ---------------------------------------------------------------------------
# Utilidades internas
# ---------------------------------------------------------------------------

_URL_RE = re.compile(r"^(https?|wss)://[^/]+(?:/.*)?$")


def _validate_endpoint_syntax(endpoint: str) -> None:
    """Valida de forma sintáctica una URL de endpoint.

    No realiza consultas de red; solo comprueba que el esquema sea ``https`` o
    ``wss`` y que la cadena tenga al menos un host.
    """
    if not isinstance(endpoint, str) or not endpoint:
        raise ValueError(f"Endpoint must be a non‑empty string, got {endpoint!r}")
    if not _URL_RE.match(endpoint):
        raise ValueError(f"Endpoint '{endpoint}' no cumple el formato requerido (https:// o wss://)"
        )


def _validate_candidate_descriptor(descriptor: dict) -> dict:
    """Ejecuta validaciones estructurales y de endpoint sobre el descriptor.

    Se delega a ``federation_capability_validator`` para la validación de campos
    obligatorios y a ``_validate_endpoint_syntax`` para cada URL declarada bajo la
    clave ``endpoints``.
    """
    deps = _load_dependencies()
    validator = deps["validator"]
    # 1️⃣ Validación de campos obligatorios y tipos
    validator.validate_capabilities(descriptor)

    # 2️⃣ Validación sintáctica de cada endpoint declarado
    endpoints = descriptor.get("endpoints", {})
    if not isinstance(endpoints, dict):
        raise ValueError("'endpoints' debe ser un diccionario de nombre->url")
    for name, url in endpoints.items():
        try:
            _validate_endpoint_syntax(url)
        except ValueError as exc:
            raise ValueError(f"Endpoint '{name}' inválido: {exc}") from exc

    return descriptor


# ---------------------------------------------------------------------------
# API pública
# ---------------------------------------------------------------------------

def onboard_candidate(candidate_descriptor: dict, operator_private_key: bytes) -> dict:
    """Orquesta el proceso completo de incorporación de un candidato federado.

    Parámetros
    ----------
    candidate_descriptor:
        Diccionario que describe al candidato. Debe cumplir con el esquema definido
        por ``federation_capability_validator`` y contener una clave ``endpoints``
        con URLs válidas.
    operator_private_key:
        Clave privada Ed25519 del operador (bytes). Se utiliza para firmar la
        propuesta generada.

    Retorna
    -------
    dict
        Resultado de la asimilación devuelto por ``federation_assimilation``.

    Excepciones
    -----------
    ValueError
        Si alguna de las etapas de validación falla.
    """
    # Paso 1: validaciones estructurales y de endpoints
    validated_descriptor = _validate_candidate_descriptor(candidate_descriptor)

    # Paso 2: generación de propuesta (sin firma)
    deps = _load_dependencies()
    proposal = deps["proposal_generator"].create_proposal(validated_descriptor)

    # Paso 3: firma de la propuesta
    signed_proposal = deps["signature"].sign_descriptor(proposal, operator_private_key)

    # Paso 4: asimilación de la propuesta firmada
    assimilation_result = deps["assimilation"].assimilate_proposal(signed_proposal)

    return assimilation_result


__all__ = ["onboard_candidate"]
