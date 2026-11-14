#!/usr/bin/env python3
import os, sys, json, ssl, time, uuid, hashlib, socket
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import urllib.request
import tools.iao_federation_autonomous as auto

STATE = ROOT / ".state" / "iao-node-network"
AUDIT = STATE / "federation-audit" / "events.jsonl"
REPORT = ROOT / ".state" / "iao-federated-read-execution.json"

def stamp():
    return datetime.now(timezone.utc).isoformat()

def audit(event, **fields):
    AUDIT.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": stamp(), "event": event, **fields}) + "\n")

def report(data):
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(json.dumps(data, indent=2))

def main():
    policy = json.loads((STATE / "federation-policy.json").read_text())
    if not policy.get("enabled"):
        report({"status": "BLOCKED", "reason": "FEDERATION_POLICY_DISABLED"})
        return 2

    # No se rebaja require_mutual_tls. Se exige certificado cliente real.
    if policy.get("require_mutual_tls"):
        cert = os.environ.get("IAO_FEDERATION_MTLS_CERT")
        key = os.environ.get("IAO_FEDERATION_MTLS_KEY")
        ca = os.environ.get("IAO_FEDERATION_MTLS_CA")
        if not cert or not key or not Path(cert).is_file() or not Path(key).is_file():
            report({
                "status": "BLOCKED",
                "reason": "MTLS_CLIENT_CERTIFICATE_NOT_CONFIGURED",
                "required_environment": [
                    "IAO_FEDERATION_MTLS_CERT",
                    "IAO_FEDERATION_MTLS_KEY",
                    "IAO_FEDERATION_MTLS_CA"
                ],
                "administrative_authority_granted": False
            })
            return 3

        ctx = ssl.create_default_context(cafile=ca if ca and Path(ca).is_file() else None)
        ctx.load_cert_chain(certfile=cert, keyfile=key)
        original_urlopen = urllib.request.urlopen

        def mtls_urlopen(url, *args, **kwargs):
            if isinstance(url, urllib.request.Request):
                scheme = url.full_url.split(":", 1)[0].lower()
            else:
                scheme = str(url).split(":", 1)[0].lower()
            if scheme == "https":
                kwargs["context"] = ctx
            return original_urlopen(url, *args, **kwargs)

        urllib.request.urlopen = mtls_urlopen

    # Actualiza descubrimiento desde las fuentes ya configuradas.
    try:
        cycle = auto.run_cycle(dry_run=False, discover=True)
        audit("external_discovery_cycle", result=str(cycle)[:1500])
    except Exception as e:
        audit("external_discovery_error", error=type(e).__name__ + ":" + str(e)[:300])

    node = auto.make_node(policy)
    allowed = set(policy.get("allowed_capabilities", []))
    results = []

    for peer_id, peer in list(node.peers.items()):
        endpoint = peer.get("endpoint")
        caps = set(peer.get("capabilities", []))
        grants = set(peer.get("granted_capabilities", []))
        lease = float(peer.get("lease_expires_at", 0) or 0)
        item = {"peer_id": peer_id, "endpoint": endpoint}

        if peer.get("revoked"):
            item["status"] = "REVOKED"
        elif lease <= time.time():
            item["status"] = "LEASE_EXPIRED"
        elif "knowledge.search" not in allowed or "knowledge.search" not in caps or "knowledge.search" not in grants:
            item["status"] = "CAPABILITY_NOT_AUTHORIZED"
        elif not endpoint or urlparse(endpoint).scheme != "https":
            item["status"] = "INVALID_HTTPS_ENDPOINT"
        else:
            host = urlparse(endpoint).hostname
            try:
                socket.getaddrinfo(host, urlparse(endpoint).port or 443)
                rid = uuid.uuid4().hex
                audit("federated_read_request_started", request_id=rid,
                      peer_id=peer_id, capability="knowledge.search",
                      administrative_authority=False)
                response = node.send(
                    peer_id=peer_id,
                    url=endpoint,
                    capability="knowledge.search",
                    body={"query": "IAO federated read-only verification"},
                    timeout=20
                )
                verified = isinstance(response, dict) and response.get("ok") is True
                digest = hashlib.sha256(
                    json.dumps(response, sort_keys=True, default=str).encode()
                ).hexdigest()
                item.update(status="RESPONSE_VERIFIED" if verified else "REMOTE_OR_VERIFICATION_FAILURE",
                            response_ok=verified, response_digest=digest)
                audit("federated_read_response", request_id=rid,
                      peer_id=peer_id, response_verified=verified,
                      response_digest=digest, administrative_authority=False)
            except Exception as e:
                item["status"] = "CONNECTION_OR_TASK_FAILED"
                item["error"] = type(e).__name__ + ":" + str(e)[:300]
                audit("federated_read_failed", peer_id=peer_id, error=item["error"])
        results.append(item)

    report({
        "timestamp": stamp(),
        "status": "COMPLETED_WITH_EVIDENCE",
        "discovered_peer_records": len(results),
        "results": results,
        "administrative_authority_granted": False,
        "signature_validation": "delegated_to_Node.send_response_verification"
    })
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
