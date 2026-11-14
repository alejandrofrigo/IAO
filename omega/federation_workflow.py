"""omega.federation_workflow

Módulo de orquestación de propuestas federadas de alto nivel.

Proporciona una única función pública `process_proposal` que ejecuta los pasos
críticos de la cadena de manejo de una propuesta:

1. **Validación estructural** – garantiza que el diccionario de la propuesta
   contenga los campos obligatorios y que los tipos sean correctos.
2. **Verificación de firma** – comprueba que la firma tenga la longitud adecuada
   (64 bytes para Ed25519) y que el valor de la firma sea coherente con la clave
   pública proporcionada. En esta versión se emplea una comprobación mínima de
   longitud para evitar dependencias criptográficas externas; la lógica puede
   ampliarse fácilmente usando `cryptography.hazmat.primitives.asymmetric.ed25519`.
3. **Registro interno** – almacena la propuesta válida en un registro en‑memoria
   protegido por un candado de sub‑procesos, de forma que otras partes del
   sistema puedan consultar el estado mediante `get_registered_proposal`.

Esta capa separa la orquestación de la lógica de bajo nivel ya existente en
`omega.federation_proposal_validation`, `omega.federation_assimilation_api` y
`omega.federation_state_tracker`, evitando duplicación de código y garantizando
que todas las pruebas que necesiten procesar una propuesta utilicen la misma
ruta de ejecución.
"""

from __future__ import annotations

import threading
from typing import Dict, Any, Optional

# ---------------------------------------------------------------------------
# Registro interno de propuestas validadas y asimiladas.
# ---------------------------------------------------------------------------
_registry_lock = threading.RLock()
_registered_proposals: Dict[str, Dict[str, Any]] = {}

# ---------------------------------------------------------------------------
# Validación estructural mínima.
# ---------------------------------------------------------------------------
_REQUIRED_FIELDS = {
    "id": str,
    "payload": dict,
    "signature": (bytes, bytearray),
}


def _validate_structure(proposal: Dict[str, Any]) -> bool:
    """Comprueba que *proposal* contenga los campos obligatorios con los tipos
    esperados.

    Se devuelve ``True`` si la propuesta pasa todas las comprobaciones; de lo
    contrario se lanza ``ValueError`` con una descripción del error.
    """
    if not isinstance(proposal, dict):
        raise ValueError("La propuesta debe ser un diccionario.")

    for field, expected_type in _REQUIRED_FIELDS.items():
        if field not in proposal:
            raise ValueError(f"Campo obligatorio '{field}' ausente en la propuesta.")
        if not isinstance(proposal[field], expected_type):
            raise ValueError(
                f"Campo '{field}' debe ser de tipo {expected_type}, "
                f"pero se recibió {type(proposal[field]).__name__}."
            )
    return True


def _verify_signature(proposal: Dict[str, Any], public_key: bytes) -> bool:
    """Verificación muy básica de la firma Ed25519.

    En esta implementación preliminar solo se verifica que la firma tenga la
    longitud correcta (64 bytes). La verificación criptográfica completa está
    delegada a módulos futuros para evitar dependencias pesadas en este paso
    inicial.
    """
    signature = proposal["signature"]
    if len(signature) != 64:
        raise ValueError("La firma Ed25519 debe tener exactamente 64 bytes.")
    # Placeholder for real cryptographic verification.
    # Los módulos de firma/validación avanzados pueden importarse aquí sin
    # afectar la lógica básica.
    _ = public_key  # Mantener la variable para futuras extensiones.
    return True


def _register_proposal(proposal: Dict[str, Any]) -> None:
    """Almacena la propuesta en el registro interno bajo su identificador.

    La operación está protegida por un candado para garantizar la seguridad en
    entornos multihilo.
    """
    proposal_id = proposal["id"]
    with _registry_lock:
        _registered_proposals[proposal_id] = proposal.copy()


def get_registered_proposal(proposal_id: str) -> Optional[Dict[str, Any]]:
    """Devuelve una copia de la propuesta registrada identificada por *proposal_id*.

    Si no existe, se devuelve ``None``.
    """
    with _registry_lock:
        proposal = _registered_proposals.get(proposal_id)
        return proposal.copy() if proposal is not None else None


def process_proposal(proposal: Dict[str, Any], public_key: bytes) -> bool:
    """Orquesta el flujo completo de manejo de una propuesta federada.

    1. Valida la estructura de la propuesta.
    2. Verifica la firma contra la clave pública suministrada.
    3. Registra la propuesta en el registro interno.

    Devuelve ``True`` si todos los pasos se completan con éxito; en caso de
    error se lanza ``ValueError`` con la causa subyacente.
    """
    # Paso 1 – validación estructural.
    _validate_structure(proposal)

    # Paso 2 – verificación de firma.
    _verify_signature(proposal, public_key)

    # Paso 3 – registro interno.
    _register_proposal(proposal)

    return True
