#!/usr/bin/env python
"""IAO federation operator: safe readiness and HTTPS connectivity checks."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib, json, os, socket, ssl, sys
from urllib.parse import urlparse
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / ".state"
NODES = STATE / "iao-external-nodes.json"
REPORT = STATE / "iao-federation-agent-report.json"
PROTOCOL = "iao-federation-v1"
EXCHANGE_PATH = "/api/federation/v1/exchange"

def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def load_nodes():
    if not NODES.is_file():
        return {"status": "MISSING", "nodes": []}
    try:
        data = json.loads(NODES.read_text(encoding="utf-8"))
    except Exception:
        return {"status": "INVALID_JSON", "nodes": []}
    if not isinstance(data, dict):
        return {"status": "INVALID_ROOT", "nodes": []}
    nodes = data.get("nodes", [])
    if not isinstance(nodes, list):
        return {"status": "INVALID_NODES_FIELD", "nodes": []}
    safe = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        # Never display or export credentials.
        url = node.get("url") or node.get("endpoint") or node.get("base_url")
        if isinstance(url, str):
            safe.append({"url": url, "id": str(node.get("id", node.get("node_id", "unnamed")))[:100]})
    return {"status": "VALID", "nodes": safe}

def probe(url):
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return {"verdict": "REJECTED", "reason": "HTTPS_URL_REQUIRED"}
    if parsed.username or parsed.password:
        return {"verdict": "REJECTED", "reason": "URL_CREDENTIALS_FORBIDDEN"}
    host = parsed.hostname
    port = parsed.port or 443
    if port != 443:
        return {"verdict": "REJECTED", "reason": "NONSTANDARD_PORT_NOT_PROBED"}
    result = {"host": host, "port": port, "verdict": "UNKNOWN"}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                result["tls"] = tls.version()
                result["certificate_verified"] = True
        result["verdict"] = "TLS_REACHABLE"
        result["scope"] = "TRANSPORT_ONLY"
    except Exception as e:
        result["verdict"] = "UNREACHABLE"
        result["error_class"] = type(e).__name__
    return result

def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "status"
    cfg = load_nodes()
    data = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "agent": "IAO Federation Agent",
        "protocol_expected": PROTOCOL,
        "exchange_endpoint_expected": EXCHANGE_PATH,
        "config_status": cfg["status"],
        "configured_node_count": len(cfg["nodes"]),
        "results": [],
        "secrets_printed": False,
    }
    if mode not in ("status", "probe"):
        raise SystemExit("Usage: python tools/iao_federation_agent.py [status|probe]")
    if mode == "probe":
        for node in cfg["nodes"]:
            res = {"node_id": node["id"]}
            try:
                res.update(probe(node["url"]))
            except Exception as e:
                res.update({"verdict": "ERROR", "error_class": type(e).__name__})
            data["results"].append(res)
    data["federation_message_exchange"] = "NOT_TESTED"
    data["external_deployment"] = "NOT_PERFORMED"
    data["note"] = "TLS reachability does not prove IAO protocol compatibility or message exchange."
    STATE.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, sort_keys=True, indent=2) + "\n"
    REPORT.write_text(payload, encoding="utf-8")
    print("IAO FEDERATION AGENT")
    print("MODE=" + mode.upper())
    print("CONFIG_STATUS=" + cfg["status"])
    print("CONFIGURED_NODE_COUNT=" + str(len(cfg["nodes"])))
    for i, result in enumerate(data["results"], 1):
        print("NODE_RESULT_%d=%s" % (i, json.dumps(result, sort_keys=True)))
    print("FEDERATION_MESSAGE_EXCHANGE=NOT_TESTED")
    print("EXTERNAL_DEPLOYMENT=NOT_PERFORMED")
    print("REPORT_PATH=" + str(REPORT))
    print("REPORT_SHA256=" + sha(REPORT))

if __name__ == "__main__":
    main()
