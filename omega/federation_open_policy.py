"""
Política de federación abierta y autorización progresiva de IAO.

Este módulo evalúa permisos. La identidad y el desafío deben ser
verificados criptográficamente por el componente de transporte/autenticación.
Nunca se deben aceptar estos indicadores desde declaraciones del propio peer.
"""

from __future__ import annotations

from typing import Iterable

POLICY_VERSION = "1.0"

# Permisos federados de bajo riesgo que pueden concederse automáticamente.
AUTO_CAPABILITIES = frozenset({
    "knowledge.search",
    "knowledge.read",
    "capabilities.exchange",
    "task.submit",
    "artifact.propose",
    "artifact.test",
})

# No conceder a participantes externos, ni siquiera verificados.
NEVER_AUTO_GRANT = frozenset({
    "admin",
    "root",
    "device.admin",
    "host.shell",
    "host.execute",
    "filesystem.write",
    "filesystem.read_private",
    "credentials.read",
    "secrets.read",
    "keys.export",
    "audit.disable",
    "policy.disable",
    "security.disable",
    "network.unrestricted",
    "deployment.production",
    "code.execute.host",
    "code.modify.core",
})

def evaluate_peer(
    *,
    transport_secure: bool,
    audit_available: bool,
    identity_verified: bool,
    challenge_verified: bool,
    requested_capabilities: Iterable[str] = (),
) -> dict:
    """
    Devuelve una decisión explícita y auditable.

    Nivel 0: descubrimiento, sin permisos.
    Nivel 1: contacto provisional por transporte seguro.
    Nivel 2: colaboración pública limitada.
    Nivel 3: identidad y desafío verificados automáticamente.
    Nivel 4: permisos federados permitidos concedidos automáticamente.

    identity_verified y challenge_verified solo pueden proceder de
    verificaciones criptográficas reales, nunca de datos declarados por el peer.
    """
    requested = sorted({
        str(x).strip().lower()
        for x in requested_capabilities
        if str(x).strip()
    })

    granted = []
    denied = []

    result = {
        "policy_version": POLICY_VERSION,
        "level": 0,
        "status": "DISCOVERED",
        "verification": "NOT_VERIFIED",
        "authorization": "NONE",
        "granted_capabilities": granted,
        "denied_capabilities": denied,
        "manual_approval_required": False,
        "reasons": [],
    }

    if not transport_secure:
        denied.extend(requested)
        result["reasons"].append("SECURE_TRANSPORT_REQUIRED")
        result["status"] = "DISCOVERED_ONLY"
        return result

    result["level"] = 1
    result["status"] = "PROVISIONAL_CONTACT"
    result["reasons"].append("SECURE_TRANSPORT_ESTABLISHED")

    if not audit_available:
        denied.extend(requested)
        result["reasons"].append("AUDIT_UNAVAILABLE")
        result["status"] = "CONTACT_ONLY"
        return result

    result["level"] = 2
    result["status"] = "LIMITED_COLLABORATION"

    if not (identity_verified and challenge_verified):
        denied.extend(requested)
        result["reasons"].append("IDENTITY_OR_CHALLENGE_NOT_VERIFIED")
        return result

    result["level"] = 3
    result["status"] = "FEDERATED_PEER"
    result["verification"] = "CRYPTOGRAPHICALLY_VERIFIED"
    result["reasons"].append("AUTOMATIC_VERIFICATION_SUCCEEDED")

    for capability in requested:
        if capability in NEVER_AUTO_GRANT:
            denied.append(capability)
        elif capability in AUTO_CAPABILITIES:
            granted.append(capability)
        else:
            denied.append(capability)

    result["level"] = 4 if granted else 3
    result["authorization"] = (
        "AUTOMATIC_SCOPED_GRANT" if granted else "NO_CAPABILITIES_GRANTED"
    )
    result["status"] = (
        "FEDERATED_WITH_SCOPED_PERMISSIONS" if granted
        else "VERIFIED_WITHOUT_GRANTED_CAPABILITIES"
    )
    result["reasons"].append("AUTOMATIC_POLICY_EVALUATION")

    if denied:
        result["reasons"].append("UNSUPPORTED_OR_PRIVILEGED_CAPABILITIES_DENIED")

    return result
