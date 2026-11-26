#!/usr/bin/env python3
import os, json, time, ssl, socket, subprocess, hashlib
import urllib.request
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime, timezone

ROOT = Path.cwd()
STATE = ROOT / ".state" / "iao-node-network"
PEERS_FILE = STATE / "peers.json"
POLICY_FILE = STATE / "federation-policy.json"
AUDIT_FILE = STATE / "federation-audit" / "events.jsonl"
EXEC_REPORT = ROOT / ".state" / "iao-federated-read-execution.json"
OLD_REPORT = ROOT / ".state" / "iao-federation-autonomous-report.json"
MTLS = Path.home() / ".config/iao/federation-mtls"

def load(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default

def emit(name, value):
    print(f"{name}={value}")

def get_processes():
    try:
        p = subprocess.run(
            ["ps", "-A", "-o", "PID,ARGS"],
            capture_output=True, text=True, timeout=5
        )
        lines = p.stdout.splitlines()
        return [x.strip() for x in lines if any(
            token in x for token in (
                "iao_federation_autonomous.py --watch",
                "iao_fedserver_public.py",
                "cloudflared tunnel"
            )
        )]
    except Exception:
        return []

def endpoint_check(url, expected_id=None, expected_key=None):
    result = {"endpoint": url}
    parsed = urlparse(url or "")
    if parsed.scheme != "https" or not parsed.hostname:
        result["status"] = "INVALID_ENDPOINT"
        return result

    try:
        socket.getaddrinfo(parsed.hostname, parsed.port or 443)
        result["dns"] = "OK"
    except Exception as e:
        result["dns"] = "ERROR: " + str(e)[:180]
        result["status"] = "DNS_UNAVAILABLE"
        return result

    ctx = ssl.create_default_context()
    cert = os.environ.get("IAO_FEDERATION_MTLS_CERT")
    key = os.environ.get("IAO_FEDERATION_MTLS_KEY")
    ca = os.environ.get("IAO_FEDERATION_MTLS_CA")

    cert = cert or str(MTLS / "client.crt")
    key = key or str(MTLS / "client.key")
    ca = ca or str(MTLS / "ca.crt")

    if Path(cert).is_file() and Path(key).is_file():
        try:
            ctx.load_cert_chain(cert, key)
            result["client_certificate"] = "LOADED"
        except Exception as e:
            result["client_certificate"] = "INVALID: " + str(e)[:120]
    else:
        result["client_certificate"] = "NOT_CONFIGURED"

    if Path(ca).is_file():
        try:
            ctx.load_verify_locations(cafile=ca)
            result["ca_file"] = "LOADED"
        except Exception as e:
            result["ca_file"] = "INVALID: " + str(e)[:120]
    else:
        result["ca_file"] = "NOT_CONFIGURED"

    identity_url = f"{parsed.scheme}://{parsed.netloc}/fed/v1/identity"
    try:
        req = urllib.request.Request(
            identity_url, headers={"Accept": "application/json"}
        )
        with urllib.request.urlopen(req, context=ctx, timeout=8) as response:
            result["identity_http"] = response.status
            doc = json.loads(response.read(65536).decode("utf-8"))
        result["remote_node_id"] = doc.get("node_id")
        result["remote_protocol"] = doc.get("protocol")
        remote_key = doc.get("public_key")
        result["identity_key_present"] = bool(remote_key)

        id_ok = expected_id is None or doc.get("node_id") == expected_id
        key_ok = True
        if expected_key and remote_key:
            try:
                import base64
                expected = expected_key
                if isinstance(expected, bytes):
                    expected = expected.hex()
                elif isinstance(expected, str):
                    try:
                        expected = base64.b64decode(expected).hex()
                    except Exception:
                        pass
                key_ok = str(expected).lower() == str(remote_key).lower()
            except Exception:
                key_ok = False

        result["peer_id_match"] = id_ok
        result["public_key_match"] = key_ok
        result["status"] = (
            "IDENTITY_MATCH" if id_ok and key_ok
            else "IDENTITY_MISMATCH"
        )
    except Exception as e:
        result["status"] = "IDENTITY_UNAVAILABLE"
        result["error"] = type(e).__name__ + ": " + str(e)[:180]
    return result

def main():
    print("========== IAO FEDERATION STATUS ==========")
    emit("TIME_UTC", datetime.now(timezone.utc).isoformat())

    policy = load(POLICY_FILE, {})
    emit("POLICY_ENABLED", policy.get("enabled", "UNKNOWN"))
    emit("MTLS_REQUIRED", policy.get("require_mutual_tls", "UNKNOWN"))
    emit("LOCAL_ALLOWED_CAPABILITIES",
         ",".join(policy.get("allowed_capabilities", [])))

    processes = get_processes()
    emit("FEDERATION_PROCESSES", len(processes))
    for p in processes:
        print("PROCESS:", p)

    raw = load(PEERS_FILE, [])
    if isinstance(raw, dict):
        peers = raw.get("peers")
        if not isinstance(peers, list):
            peers = [
                dict(v, peer_id=k) for k, v in raw.items()
                if isinstance(v, dict)
            ]
    elif isinstance(raw, list):
        peers = raw
    else:
        peers = []

    emit("PERSISTED_PEERS", len(peers))
    peer_checks = []

    for i, peer in enumerate(peers):
        if not isinstance(peer, dict):
            continue
        pid = peer.get("peer_id") or peer.get("node_id") or "UNKNOWN"
        endpoint = peer.get("endpoint")
        expiry = float(peer.get("lease_expires_at") or 0)
        caps = peer.get("capabilities") or []
        grants = peer.get("granted_capabilities") or []
        revoked = bool(peer.get("revoked"))

        print(f"\n--- PEER {i+1}: {pid} ---")
        emit("REVOKED", revoked)
        emit("LEASE", "EXPIRED" if expiry <= time.time() else "VALID")
        emit("CAPABILITIES", ",".join(caps))
        emit("LOCAL_GRANTS", ",".join(grants))
        emit("KNOWLEDGE_SEARCH",
             "AUTHORIZED" if (
                 not revoked and expiry > time.time()
                 and "knowledge.search" in caps
                 and "knowledge.search" in grants
                 and "knowledge.search" in policy.get("allowed_capabilities", [])
             ) else "NOT_AUTHORIZED")

        if endpoint and not revoked and expiry > time.time():
            check = endpoint_check(
                endpoint,
                expected_id=pid,
                expected_key=peer.get("pubkey")
            )
        else:
            check = {
                "endpoint": endpoint,
                "status": "SKIPPED_REVOKED_OR_EXPIRED"
            }

        peer_checks.append({"peer_id": pid, **check})
        emit("ENDPOINT_STATUS", check.get("status"))
        if check.get("dns"):
            emit("DNS", check["dns"])
        if check.get("identity_http") is not None:
            emit("IDENTITY_HTTP", check["identity_http"])
        if check.get("remote_node_id"):
            emit("REMOTE_NODE_ID", check["remote_node_id"])
        if check.get("error"):
            emit("ENDPOINT_ERROR", check["error"])

    print("\n========== EXECUTION REPORT ==========")
    execution = load(EXEC_REPORT, {})
    emit("EXECUTOR_REPORT_EXISTS", EXEC_REPORT.exists())
    emit("EXECUTOR_STATUS", execution.get("status", "NO_REPORT"))
    emit("ADMIN_AUTHORITY_GRANTED",
         execution.get("administrative_authority_granted", "UNKNOWN"))

    if execution.get("results"):
        for r in execution["results"]:
            print("TASK_RESULT:", json.dumps(r, ensure_ascii=False))

    print("\n========== AUDIT EVIDENCE ==========")
    counts = {}
    recent = []
    if AUDIT_FILE.exists():
        try:
            with AUDIT_FILE.open(encoding="utf-8") as f:
                for line in f:
                    try:
                        event = json.loads(line)
                        name = event.get("event", "UNKNOWN")
                        counts[name] = counts.get(name, 0) + 1
                        recent.append(event)
                    except Exception:
                        counts["MALFORMED_LINES"] = counts.get("MALFORMED_LINES", 0) + 1
        except Exception as e:
            emit("AUDIT_READ_ERROR", str(e)[:160])

    for name in sorted(counts):
        emit("AUDIT_" + name, counts[name])

    relevant = [
        e for e in recent
        if any(x in str(e.get("event", "")).lower() for x in (
            "peer_enrolled", "already_enrolled", "capabilit",
            "federated_read", "task", "handshake", "failed"
        ))
    ]
    for e in relevant[-12:]:
        print("AUDIT_EVENT:", json.dumps(e, ensure_ascii=False)[:700])

    print("\n========== FINAL CLASSIFICATION ==========")
    verified = sum(
        1 for p in peer_checks if p.get("status") == "IDENTITY_MATCH"
    )
    executed = counts.get("federated_read_response", 0)
    failed = counts.get("federated_read_failed", 0)
    completed = sum(
        1 for e in recent
        if e.get("event") == "federated_read_response"
        and e.get("response_verified") is True
    )

    emit("PEERS_WITH_MATCHING_IDENTITY", verified)
    emit("AUDITED_READ_RESPONSES", executed)
    emit("VERIFIED_READ_RESPONSES", completed)
    emit("AUDITED_READ_FAILURES", failed)

    if completed:
        status = "FEDERATED_READ_RESPONSE_VERIFIED"
    elif verified:
        status = "IDENTITY_VERIFIED_NO_TASK_PROOF"
    elif peers:
        status = "PEERS_REGISTERED_BUT_EXTERNAL_EXECUTION_UNVERIFIED"
    else:
        status = "NO_REGISTERED_EXTERNAL_PEERS"

    emit("OVERALL_STATUS", status)
    emit("NOTE", "Enrollment, identity, capability grant and task execution are distinct states.")
    print("========== END STATUS ==========")

if __name__ == "__main__":
    main()
