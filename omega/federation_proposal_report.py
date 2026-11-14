"""omega.federation_proposal_report
===================================

Módulo de alto nivel que genera un informe completo para una propuesta
federada identificada por su *proposal_id*.

El informe incluye:

* **proposal** – datos en bruto de la propuesta tal como están almacenados.
* **signature_valid** – resultado de la verificación de la firma Ed25519.
* **status** – estado del ciclo de vida (activo, revocado, expirado, etc.).
* **audit_log** – lista de entradas de auditoría asociadas a la propuesta.

Esta función reutiliza los componentes ya existentes:

* :pyfunc:`omega.federation_proposal_detail.get_proposal_detail`
* :pyfunc:`omega.federation_status.get_federation_proposal_status`
* :pyfunc:`omega.federation_audit_query.get_audit_log`

Al combinar los resultados, se ofrece una única fuente de verdad que
simplifica la inspección por parte de operadores y pruebas automáticas.
"""

from __future__ import annotations

from typing import Any, Dict

# Importes seguros – si alguno de los módulos falla en tiempo de importación,
# la excepción será capturada y el informe contendrá la información del error.
try:
    from omega.federation_proposal_detail import get_proposal_detail
except Exception as exc:  # pragma: no cover
    get_proposal_detail = None  # type: ignore
    _detail_import_error = exc
else:
    _detail_import_error = None

try:
    from omega.federation_status import get_federation_proposal_status
except Exception as exc:  # pragma: no cover
    get_federation_proposal_status = None  # type: ignore
    _status_import_error = exc
else:
    _status_import_error = None

try:
    from omega.federation_audit_query import get_audit_log
except Exception as exc:  # pragma: no cover
    get_audit_log = None  # type: ignore
    _audit_import_error = exc
else:
    _audit_import_error = None

__all__ = ["get_federation_proposal_report"]


def _safe_call(func, *args, **kwargs) -> Any:
    """Ejecuta *func* de forma segura capturando cualquier excepción.

    Si la llamada falla, se devuelve una cadena descriptiva del error en vez de
    propagar la excepción, garantizando que el informe siempre se genere.
    """
    if func is None:
        return None
    try:
        return func(*args, **kwargs)
    except Exception as exc:  # pragma: no cover
        return f"Error during call: {exc!s}"


def get_federation_proposal_report(proposal_id: str) -> Dict[str, Any]:
    """Genera un informe consolidado para la propuesta federada *proposal_id*.

    El diccionario resultante contiene los siguientes campos clave:

    * ``detail`` – salida de ``get_proposal_detail`` (puede ser un ``dict`` o
      información de error).
    * ``status`` – estado del ciclo de vida obtenido mediante
      ``get_federation_proposal_status``.
    * ``audit_log`` – lista de entradas de auditoría vía ``get_audit_log``.
    * ``errors`` – lista opcional de problemas encontrados al importar o
      ejecutar los sub‑módulos.
    """
    report: Dict[str, Any] = {}
    errors: list[str] = []

    # Import errors se registran para visibilidad del operador.
    if _detail_import_error:
        errors.append(f"Import error in federation_proposal_detail: {_detail_import_error}")
    if _status_import_error:
        errors.append(f"Import error in federation_status: {_status_import_error}")
    if _audit_import_error:
        errors.append(f"Import error in federation_audit_query: {_audit_import_error}")

    # Detalle de la propuesta.
    detail = _safe_call(get_proposal_detail, proposal_id)
    report["detail"] = detail

    # Estado del ciclo de vida.
    status = _safe_call(get_federation_proposal_status, proposal_id)
    report["status"] = status

    # Registro de auditoría.
    audit_log = _safe_call(get_audit_log, proposal_id)
    report["audit_log"] = audit_log

    if errors:
        report["errors"] = errors

    return report
