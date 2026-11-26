
import base64
import json
import sys
from datetime import datetime, timezone
from urllib.parse import urlsplit

from tools.iao_federation_agent import load_nodes, verify_node, request_json


def field(obj, *names):
    if not isinstance(obj, dict):
        return None
    for name in names:
        value = obj.get(name)
        if value is not None:
            return value
    return None


def origin_of(node):
    raw = field(node, "url", "origin", "endpoint", "base_url")
    if not isinstance(raw, str):
        raise ValueError("El nodo no contiene una URL configurada")
    parsed = urlsplit(raw)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.port not in (None, 443)
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("URL externa no válida")
    return f"https://{parsed.netloc}"


def verified_id_from(result):
    if not isinstance(result, dict):
        return None
    status = field(result, "status", "identity_status", "result")
    if status not in ("IDENTITY_VERIFIED", "VERIFIED"):
        return None
    return field(
        result, "node_id", "verified_node_id", "peer_id"
    )


def check_contract(node):
    origin = origin_of(node)

    # Reutiliza la comprobación Ed25519 del agente existente.
    verification = verify_node(node)
    verified_id = verified_id_from(verification)
    if not verified_id:
        return {
            "status": "IDENTITY_NOT_VERIFIED",
            "configured_node": field(node, "node_id", "id"),
            "enrollment": "NOT_PERFORMED",
        }

    identity = request_json(origin + "/fed/v1/identity")
    contract = request_json(origin + "/fed/v1/contract")

    if not isinstance(identity, dict) or not isinstance(contract, dict):
        raise ValueError("Identidad o contrato no devuelven un objeto JSON")

    identity_id = identity.get("node_id")
    identity_key = identity.get("public_key")
    contract_id = contract.get("peer_id")
    contract_key = contract.get("pubkey")
    capabilities = contract.get("capabilities")
    lease = contract.get("lease_expires_at")

    if identity_id != verified_id or contract_id != verified_id:
        raise ValueError("La identidad verificada no coincide con el contrato")

    if not isinstance(identity_key, str) or not isinstance(contract_key, str):
        raise ValueError("Falta la clave pública del nodo")

    key_hex = bytes.fromhex(identity_key)
    key_b64 = base64.b64decode(contract_key, validate=True)

    if len(key_hex) != 32 or key_b64 != key_hex:
        raise ValueError("La clave pública del contrato no coincide")

    if (
        not isinstance(capabilities, list)
        or not capabilities
        or any(not isinstance(c, str) or not c for c in capabilities)
        or len(set(capabilities)) != len(capabilities)
    ):
        raise ValueError("Lista de capacidades inválida")

    if not isinstance(lease, (int, float)):
        raise ValueError("Vencimiento del contrato inválido")

    now = datetime.now(timezone.utc).timestamp()
    if lease <= now:
        raise ValueError("El contrato del nodo está vencido")

    return {
        "status": "CONTRACT_VERIFIED",
        "node_id": verified_id,
        "capabilities": sorted(capabilities),
        "lease_expires_at": lease,
        "enrollment": "NOT_PERFORMED",
        "task_exchange": "NOT_PERFORMED",
    }


def main():
    nodes = load_nodes()
    if not nodes:
        print("No hay nodos externos autorizados configurados.")
        return 0

    reports = []
    for node in nodes:
        try:
            reports.append(check_contract(node))
        except Exception as exc:
            reports.append({
                "status": "CONTRACT_CHECK_FAILED",
                "configured_node": field(node, "node_id", "id"),
                "reason": str(exc)[:240],
                "enrollment": "NOT_PERFORMED",
            })

    print(json.dumps({
        "component": "IAO_FEDERATION_CONTRACT_WORKER",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "reports": reports,
    }, indent=2, ensure_ascii=False))

    return 0 if all(
        item["status"] == "CONTRACT_VERIFIED" for item in reports
    ) else 2


if __name__ == "__main__":
    sys.exit(main())
