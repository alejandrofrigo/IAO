"""omega.federation_candidate_pipeline
===================================

Módulo de alto nivel que combina las capacidades existentes de la infraestructura
federada para procesar un candidato desde su descubrimiento hasta su registro.

El pipeline ejecuta, en orden:

1. **Descubrimiento** – transforma una referencia abstracta (URL, ID, etc.) en
   una representación estructurada del candidato.
2. **Validación estructural** – comprueba que el candidato cumple con el
   esquema esperado (identificador, claves públicas, URL HTTPS, etc.).
3. **Verificación de conectividad** – asegura que el nodo es alcanzable vía TCP
   y HTTPS antes de admitir su incorporación.
4. **Registro** – almacena el candidato en el registro central y devuelve un
   identificador permanente.

Si alguna fase falla el pipeline finaliza temprano y marca al candidato como
rechazado, manteniendo trazabilidad del motivo.

Este módulo está pensado para ser importado por componentes de orquestación
(o por pruebas) sin introducir dependencias circulares; los imports se realizan
perezosamente y se capturan excepciones para que la ausencia de una pieza no
rompa todo el proceso.
"""

from __future__ import annotations

from typing import Any, Dict

__all__ = ["process_candidate"]


def _discover(candidate_source: Any) -> Dict[str, Any]:
    """Intenta descubrir un candidato a partir de un descriptor.

    Si el proyecto incluye ``omega.federation_candidate_discovery`` se delega a
    su función ``discover_candidate``; de lo contrario se asume que *candidate_source*
    ya es un diccionario con los campos requeridos.
    """
    try:
        from .federation_candidate_discovery import discover_candidate  # type: ignore
    except Exception:
        # Módulo no disponible – devolver directamente si es un dict
        return candidate_source if isinstance(candidate_source, dict) else {}
    else:
        return discover_candidate(candidate_source)


def _validate(candidate: Dict[str, Any]) -> bool:
    """Valida la estructura del candidato usando el validador existente.

    Devuelve ``True`` si el candidato pasa todas las comprobaciones; ``False``
    en caso contrario o si el validador no está presente.
    """
    try:
        from .federation_candidate_validator import validate_candidate  # type: ignore
    except Exception:
        return False
    else:
        return validate_candidate(candidate)


def _check_connectivity(candidate: Dict[str, Any]) -> bool:
    """Comprueba la conectividad TCP/HTTPS del candidato.

    Se espera que el candidato tenga una clave ``url`` con la dirección del
    nodo. Si el módulo de conectividad no está disponible, la función devuelve
    ``False`` para evitar aceptar candidatos sin verificación explícita.
    """
    url = candidate.get("url")
    if not isinstance(url, str):
        return False
    try:
        from .federation_connectivity import check_connectivity  # type: ignore
    except Exception:
        return False
    else:
        return check_connectivity(url)


def _register(candidate: Dict[str, Any]) -> str:
    """Registra el candidato en el registro central y devuelve su ID.

    Si el registro no está disponible, se genera un UUID aleatorio como
    identificador transitorio, garantizando que la función siempre devuelve una
    cadena válida.
    """
    try:
        from .federation_candidate_registry import register_candidate  # type: ignore
    except Exception:
        import uuid
        return str(uuid.uuid4())
    else:
        return register_candidate(candidate)


def process_candidate(candidate_source: Any) -> Dict[str, Any]:
    """Ejecuta el pipeline completo de incorporación de un candidato.

    Parámetros
    ----------
    candidate_source: Any
        Puede ser una URL, un ID, o directamente un diccionario con la
        representación estructurada del candidato.

    Retorna
    -------
    dict
        Informe con los resultados de cada fase y el estado final:
        ``candidate_id`` (str | None), ``validated`` (bool), ``connectivity``
        (bool), ``registered`` (bool) y ``status`` ("accepted" o "rejected").
    """
    # 1. Descubrimiento
    candidate = _discover(candidate_source)

    # 2. Validación estructural
    validated = _validate(candidate)

    # 3. Verificación de conectividad (solo si la validación fue exitosa)
    connectivity = _check_connectivity(candidate) if validated else False

    # 4. Registro (solo si ambas fases anteriores fueron exitosas)
    candidate_id = _register(candidate) if validated and connectivity else None

    status = "accepted" if candidate_id else "rejected"

    return {
        "candidate_id": candidate_id,
        "validated": validated,
        "connectivity": connectivity,
        "registered": bool(candidate_id),
        "status": status,
        "details": candidate,
    }
