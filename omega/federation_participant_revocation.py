# -*- coding: utf-8 -*-
"""Revocación de participantes federados.

Esta utilidad proporciona una función de alto nivel que elimina de forma
controlada a un participante del registro de la federación y registra la
operación en el auditoría del subsistema, sin alterar otros componentes.
"""

from __future__ import annotations

import datetime
from typing import Optional

# Importamos el registro de participantes de forma segura. Si el módulo no
# está disponible (por ejemplo, por una dependencia opcional) la importación
# devolverá ``None`` y la función fallará de forma controlada.
try:
    from . import federation_participant_registry as _registry
except Exception:  # pragma: no cover
    _registry = None


def _record_audit(action: str, participant_id: str, reason: Optional[str] = None) -> None:
    """Intentar registrar la acción en el log de auditoría del registro.

    Si el registro dispone de una función ``record_audit`` se llama con los
    parámetros suministrados; de lo contrario la llamada se ignora silenciosa‑
    mente.
    """
    if _registry is None:
        return
    audit_fn = getattr(_registry, "record_audit", None)
    if callable(audit_fn):
        try:
            audit_fn(action, participant_id, reason)
        except Exception:  # pragma: no cover
            pass


def revoke_participant(participant_id: str, reason: Optional[str] = None) -> bool:
    """Revoca (elimina) un participante federado.

    Args:
        participant_id: Identificador único del participante dentro del
            registro de la federación.
        reason: Motivo opcional de la revocación que se anotará en la auditoría.

    Returns:
        ``True`` si el participante existía y fue eliminado; ``False`` si no
        se encontró o la operación no pudo completarse.

    La operación respeta los siguientes pasos:
    1. Validar el tipo del identificador.
    2. Intentar usar una API explícita de revocación del registro
       (``revoke_participant`` o ``unregister_participant``).
    3. Si no existe una API, acceder directamente a la estructura interna
       ``_participants`` (si está presente) y eliminar la entrada.
    4. Registrar la revocación en el log de auditoría cuando sea posible.
    """
    if not isinstance(participant_id, str):
        raise TypeError("participant_id must be a string")

    if _registry is None:
        # Sin registro disponible no podemos revocar de forma segura.
        return False

    # 1) API explícita de revocación, si está implementada.
    for api_name in ("revoke_participant", "unregister_participant"):
        api = getattr(_registry, api_name, None)
        if callable(api):
            try:
                result = api(participant_id, reason=reason) if api_name == "revoke_participant" else api(participant_id)
                _record_audit("revoke_participant", participant_id, reason)
                return bool(result) if result is not None else True
            except Exception:  # pragma: no cover
                continue

    # 2) Acceso directo a la estructura interna.
    participants = getattr(_registry, "_participants", None)
    if isinstance(participants, dict) and participant_id in participants:
        try:
            del participants[participant_id]
            _record_audit("revoke_participant", participant_id, reason)
            return True
        except Exception:  # pragma: no cover
            return False

    # No se encontró al participante.
    return False
