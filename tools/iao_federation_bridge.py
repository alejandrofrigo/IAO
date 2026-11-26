#!/usr/bin/env python3
"""Puente fail-closed entre candidatos verificados y Node de IAO."""
import argparse
import json
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

from omega.federation import Node
from omega.federation_assimilation import CandidateRegistry

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / ".state/federation-candidates.json"
IDENTITY = ROOT / ".state/federation/identity"
PEERS = ROOT / ".state/federation/identity/peers.json"
AUDIT = ROOT / ".state/federation-external/bridge.jsonl"

def emit(event, **data):
    AUDIT.parent.mkdir(parents=True, exist_ok=True)
    row = {"ts": time.time(), "event": event, **data}
    with AUDIT.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, sort_keys=True) + "\n")
    print(json.dumps(row, ensure_ascii=False))

def load_node():
    return Node.from_persistent_identity(
        identity_dir=IDENTITY,
        peer_store_path=PEERS,
    )

def endpoint_ok(value):
    if not isinstance(value, str) or len(value) > 2048:
        return False
    try:
        u = urlsplit(value)
        return (
            u.scheme == "https" and bool(u.hostname)
            and not u.username and not u.password
            and (u.port is None or u.port == 443)
            and u.path == "/fed/v1/message"
            and not u.query and not u.fragment
        )
    except ValueError:
        return False

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidate-id", required=True)
    ap.add_argument("--capability", default="knowledge.search")
    ap.add_argument("--body", default='{"query":"IAO federation connectivity test"}')
    ap.add_argument("--timeout", type=float, default=8.0)
    args = ap.parse_args()

    registry = CandidateRegistry(REGISTRY)
    item = registry.get(args.candidate_id)
    if not item:
        emit("REJECTED", reason="CANDIDATE_NOT_FOUND")
        return 2

    if item.get("status") != "AUTHORIZATION_PENDING" or item.get("authorized") is not True:
        emit("REJECTED", reason="VERIFIED_AND_AUTHORIZED_CANDIDATE_REQUIRED",
             candidate_status=item.get("status"),
             authorized=item.get("authorized"))
        return 3

    evidence = item.get("verification_evidence") or {}
    identity = evidence.get("identity") or {}
    transport = evidence.get("transport") or {}
    node_id = item.get("node_id")
    if (identity.get("node_id") != node_id
            or transport.get("https_verified") is not True
            or transport.get("redirected") is not False):
        emit("REJECTED", reason="VERIFICATION_EVIDENCE_INVALID")
        return 4

    endpoint = item.get("endpoint")
    if not endpoint_ok(endpoint):
        emit("REJECTED", reason="VALID_HTTPS_MESSAGE_ENDPOINT_REQUIRED")
        return 5

    body = json.loads(args.body)
    if not isinstance(body, dict):
        emit("REJECTED", reason="BODY_MUST_BE_JSON_OBJECT")
        return 6

    node = load_node()
    caps = identity.get("capabilities")
    if not isinstance(caps, list) or args.capability not in caps:
        emit("REJECTED", reason="REMOTE_CAPABILITY_NOT_ADVERTISED")
        return 7
    if args.capability not in node.served:
        emit("REJECTED", reason="LOCAL_CAPABILITY_NOT_SERVED")
        return 8

    contract = {
        "peer_id": node_id,
        "pubkey": __import__("base64").b64encode(
            bytes.fromhex(identity["public_key"])
        ).decode("ascii"),
        "capabilities": caps,
        "lease_expires_at": float(identity["lease_expires_at"]),
        "rate_limit_per_min": int(identity.get("rate_limit_per_min", 30)),
        "endpoint": endpoint,
    }

    # Autorización explícita: nunca se otorgan grants entrantes por defecto.
    node.enroll(contract, granted_capabilities=[])
    emit("PEER_ENROLLED", peer_id=node_id, inbound_grants=[])

    result = node.send(
        node_id, endpoint, args.capability, body,
        timeout=max(1.0, min(args.timeout, 30.0)),
    )
    ok = isinstance(result, dict) and result.get("ok") is True
    emit("EXCHANGE_RESULT", peer_id=node_id, capability=args.capability,
         ok=ok, result=result)
    return 0 if ok else 9

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        emit("BRIDGE_ERROR", error=type(exc).__name__, detail=str(exc)[:200])
        sys.exit(10)
