#!/usr/bin/env python3
import hashlib
import json
import os
import sys
import time

from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".state/iao-node-network"

AGENT = ROOT / "tools/iao_external_node_agent.py"
POLICY = STATE / "federation-policy.json"
REGISTRY = STATE / "nodes.json"
PEERS = STATE / "authorized-peers.json"
INBOX = STATE / "federation-inbox"
AUDIT = STATE / "federation-audit/events.jsonl"
CONTROL = ROOT / "tools/iao_control_plane.py"
PADGE = ROOT / "omega/padge.py"

def utc():
    return datetime.now(timezone.utc).isoformat()

def load(path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))

def save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8"
    )
    os.replace(tmp, path)

def audit(event, **fields):
    AUDIT.parent.mkdir(parents=True, exist_ok=True)
    record = {"timestamp": utc(), "event": event, **fields}
    with AUDIT.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(json.dumps(record, ensure_ascii=False), flush=True)

def discover():
    if not AGENT.is_file():
        raise RuntimeError("Agente de expansión inexistente")

    import subprocess
    result = subprocess.run(
        [sys.executable, str(AGENT), "--once"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=180
    )

    if result.returncode != 0:
        audit(
            "discovery_failed",
            exit_code=result.returncode,
            output=result.stderr[-1000:]
        )
        raise RuntimeError("Falló el ciclo de descubrimiento")

    audit("discovery_completed")

def verify_node(node, policy):
    node_id = node.get("node_id", "")
    if len(node_id) not in (16, 64):
        return False, "INVALID_NODE_ID"

    if node.get("status") != "ACTIVE":
        return False, "NODE_NOT_ACTIVE"

    if node.get("transport") != "mTLS":
        return False, "MTLS_NOT_CONFIRMED"

    tls = node.get("tls", {})
    if tls.get("tls_version") not in ("TLSv1.2", "TLSv1.3"):
        return False, "TLS_VERSION_NOT_ALLOWED"

    if not tls.get("cipher"):
        return False, "TLS_CIPHER_MISSING"

    try:
        verified = datetime.fromisoformat(
            node["last_verified"].replace("Z", "+00:00")
        )
        age = (datetime.now(timezone.utc) - verified).total_seconds()
    except Exception:
        return False, "INVALID_VERIFICATION_TIMESTAMP"

    if age < 0 or age > policy["maximum_node_age_seconds"]:
        return False, "VERIFICATION_EXPIRED"

    endpoint = node.get("endpoint", "")
    protocol = node.get("protocol", "iao-federation")
    if protocol == "nostr":
        # Peer federado via bridge Nostr: transporte = relay Nostr, no FedServer HTTPS
        if not endpoint.startswith("nostr://"):
            return False, "INVALID_ENDPOINT"
    else:
        if not endpoint.startswith("https://"):
            return False, "INVALID_ENDPOINT"

    return True, "VERIFIED"

def stage_padge_candidate(node, capabilities):
    # La propuesta es información, no código ejecutable.
    # PADGE debe aplicar sus propias pruebas y política.
    proposal = {
        "schema": 1,
        "proposal_id": hashlib.sha256(
            (node["node_id"] + utc()).encode()
        ).hexdigest(),
        "source": "IAO_FEDERATED_NODE",
        "node_id": node["node_id"],
        "node_name": node.get("name", "unnamed"),
        "capabilities": capabilities,
        "requested_action": "CAPABILITY_CATALOG_UPDATE",
        "execution_authority": "NONE",
        "status": "STAGED_FOR_PADGE_REVIEW",
        "created_at": utc()
    }

    destination = INBOX / (proposal["proposal_id"] + ".json")
    save(destination, proposal)

    audit(
        "padge_proposal_staged",
        node_id=node["node_id"],
        proposal_id=proposal["proposal_id"]
    )

def integrate():
    policy = load(POLICY, {})
    registry = load(REGISTRY, {"schema": 1, "nodes": {}})
    peers = load(PEERS, {"schema": 1, "authorized_peers": []})

    if not policy.get("enabled"):
        raise RuntimeError("Expansión federada deshabilitada")

    if not policy.get("require_trusted_directory_signature"):
        raise RuntimeError("La firma del directorio es obligatoria")

    if not policy.get("require_mutual_tls"):
        raise RuntimeError("mTLS es obligatorio")

    peer_ids = {
        p.get("node_id")
        for p in peers.get("authorized_peers", [])
        if p.get("status") == "AUTHORIZED"
    }

    nodes = registry.get("nodes", {})
    admitted = 0
    rejected = 0

    for node_id, node in list(nodes.items()):
        valid, reason = verify_node(node, policy)

        if not valid:
            rejected += 1
            audit(
                "node_rejected_by_control_plane",
                node_id=node_id,
                reason=reason
            )
            continue

        # La identidad debe pertenecer al registro de nodos
        # autorizados por el proceso de admisión criptográfica.
        if node_id not in peer_ids:
            rejected += 1
            audit(
                "node_waiting_for_enrollment",
                node_id=node_id
            )
            continue

        capabilities = sorted(
            set(node.get("capabilities", []))
            & set(policy["allowed_capabilities"])
        )

        if not capabilities:
            rejected += 1
            audit(
                "node_has_no_allowed_capabilities",
                node_id=node_id
            )
            continue

        if node.get("control_plane_admission") != "AUTO_ADMITTED":
            node["control_plane_admission"] = "AUTO_ADMITTED"
            node["admitted_at"] = utc()
            admitted += 1

            audit(
                "node_auto_admitted",
                node_id=node_id,
                capabilities=capabilities
            )

        node["capabilities"] = capabilities
        node["authority"] = "LIMITED_FEDERATED_NODE"

        if policy.get("automatic_candidate_staging"):
            stage_padge_candidate(node, capabilities)

    # Evitar exceder el máximo configurado.
    active = [
        n for n in nodes.values()
        if n.get("control_plane_admission") == "AUTO_ADMITTED"
    ]

    if len(active) > policy["maximum_nodes"]:
        raise RuntimeError("Límite de nodos superado; revisión necesaria")

    save(REGISTRY, registry)

    audit(
        "federation_control_cycle",
        admitted=admitted,
        rejected=rejected,
        registered=len(nodes),
        padge="POLICY_GATED"
    )

def status():
    policy = load(POLICY, {})
    registry = load(REGISTRY, {"nodes": {}})
    nodes = registry.get("nodes", {})

    print("FEDERATION_ENABLED=", policy.get("enabled"))
    print("AUTO_ADMISSION=", policy.get("automatic_admission"))
    print("REGISTERED_NODES=", len(nodes))
    print(
        "AUTO_ADMITTED_NODES=",
        sum(
            n.get("control_plane_admission") == "AUTO_ADMITTED"
            for n in nodes.values()
        )
    )
    print("PADGE_MODE=", policy.get("padge_mode"))
    print("REMOTE_CODE_EXECUTION=", policy.get("remote_code_execution"))
    print("CONTROL_PLANE_FILE=", CONTROL.exists())
    print("PADGE_FILE=", PADGE.exists())
    print("PROPOSAL_QUEUE=", len(list(INBOX.glob("*.json"))))

def watch():
    policy = load(POLICY, {})
    interval = max(60, min(
        int(load(
            ROOT / ".state/iao-node-network/agent-config.json",
            {"poll_seconds": 300}
        ).get("poll_seconds", 300)),
        3600
    ))

    audit("federation_supervisor_started", interval=interval)

    while True:
        try:
            discover()
            integrate()
        except Exception as exc:
            audit(
                "federation_supervisor_error",
                error=type(exc).__name__,
                detail=str(exc)[:300]
            )
        time.sleep(interval)

def main():
    action = sys.argv[1] if len(sys.argv) > 1 else "once"

    if action == "once":
        discover()
        integrate()
    elif action == "watch":
        watch()
    elif action == "status":
        status()
    else:
        raise SystemExit("Uso: once | watch | status")

if __name__ == "__main__":
    main()
