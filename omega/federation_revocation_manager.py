'''omega/federation_revocation_manager.py

Módulo de alto nivel que permite revocar propuestas federadas de forma segura,
actualizando el almacén en memoria y registrando el evento en el auditoría.
Esto cierra la brecha existente entre el almacén de propuestas thread‑safe y los
módulos de auditoría que ya existen en la infraestructura.
'''

from __future__ import annotations

import datetime
from typing import Any, Dict

# Importar los componentes ya presentes en la base de código.
# Se asume que ``federation_proposal_store_threadsafe`` expone una instancia
# llamada ``proposal_store`` con los métodos ``get`` y ``update`` que son
# thread‑safe.
from .federation_proposal_store_threadsafe import proposal_store

# El registro de auditoría está centralizado en ``federation_audit_log``.
# Se espera que este módulo provea un método ``record`` que acepte pares
# clave‑valor describiendo el evento.
from .federation_audit_log import AuditLog


def _validate_non_empty_str(value: Any, name: str) -> str:
    """Valida que *value* sea una cadena no vacía.

    Raises:
        ValueError: Si la validación falla.
    """
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} debe ser una cadena no vacía")
    return value


def revoke_proposal(proposal_id: str, reason: str, revoked_by: str) -> bool:
    """Revoca una propuesta federada.

    Args:
        proposal_id: Identificador único de la propuesta a revocar.
        reason: Motivo de la revocación, útil para auditoría.
        revoked_by: Identidad (e.g., Ed25519 key ID) del actor que revoca.

    Returns:
        bool: ``True`` si la revocación se realizó con éxito, ``False`` si la
        propuesta no existe o ya estaba revocada.

    El proceso consiste en:
    1. Validar los parámetros de entrada.
    2. Recuperar la propuesta del almacén thread‑safe.
    3. Marcarla como revocada y añadir metadatos de revocación.
    4. Persistir la actualización en el almacén.
    5. Emitir un registro de auditoría.
    """
    # 1. Validaciones básicas de los argumentos.
    _validate_non_empty_str(proposal_id, "proposal_id")
    _validate_non_empty_str(reason, "reason")
    _validate_non_empty_str(revoked_by, "revoked_by")

    # 2. Obtener la propuesta actual.
    proposal: Dict[str, Any] | None = proposal_store.get(proposal_id)
    if proposal is None:
        # No existe la propuesta; nada que revocar.
        return False

    # 3. Verificar que no esté ya revocada.
    if proposal.get("revoked", False):
        return False

    # 4. Construir el bloque de revocación.
    revocation_record = {
        "reason": reason,
        "revoked_by": revoked_by,
        "timestamp": datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }
    proposal["revoked"] = True
    proposal["revocation"] = revocation_record

    # 5. Persistir la actualización de forma thread‑safe.
    proposal_store.update(proposal_id, proposal)

    # 6. Registrar el evento en el auditoría.
    AuditLog.record(
        event="proposal_revoked",
        proposal_id=proposal_id,
        reason=reason,
        revoked_by=revoked_by,
        timestamp=revocation_record["timestamp"],
    )

    return True
