#!/usr/bin/env python3
import argparse
import base64
import hashlib
import http.client
import json
import os
import ssl
import subprocess
import tempfile
import time

from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".state/iao-node-network"
CONFIG = STATE / "agent-config.json"
NODES = STATE / "nodes.json"
EVENTS = STATE / "expansion-events.jsonl"

def now():
    return datetime.now(timezone.utc)

def iso():
    return now().isoformat()

def read_json(path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))

def save_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8"
    )
    os.replace(temp, path)

def event(kind, **fields):
    record = {"time": iso(), "event": kind, **fields}
    with EVENTS.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(json.dumps(record, ensure_ascii=False), flush=True)

def canonical(obj):
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")

def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

def verify_signature(payload, signature_b64, public_key_pem):
    signature = base64.b64decode(signature_b64, validate=True)

    with tempfile.TemporaryDirectory() as tmp:
        key = Path(tmp) / "directory-key.pem"
        msg = Path(tmp) / "payload.json"
        sig = Path(tmp) / "signature.bin"

        key.write_text(public_key_pem, encoding="utf-8")
        msg.write_bytes(canonical(payload))
        sig.write_bytes(signature)

        result = subprocess.run(
            [
                "openssl", "pkeyutl", "-verify", "-pubin",
                "-inkey", str(key), "-rawin",
                "-in", str(msg), "-sigfile", str(sig)
            ],
            capture_output=True,
            text=True,
            timeout=15
        )
        return result.returncode == 0

def load_config():
    config = read_json(CONFIG, {})
    if config.get("schema") != 1:
        raise ValueError("Esquema de configuración no compatible")
    return config

def discover(directory):
    url = directory.get("url", "")
    key = directory.get("signing_key_pem", "")

    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Directorio sin HTTPS válido")
    if not key or "BEGIN PUBLIC KEY" not in key:
        raise ValueError("Directorio sin clave pública de confianza")

    request = Request(
        url,
        headers={"Accept": "application/json",
                 "User-Agent": "IAO-External-Node-Agent/1"}
    )

    with urlopen(request, timeout=15) as response:
        if response.status != 200:
            raise ValueError("Directorio HTTP no disponible")
        if response.headers.get("Content-Length"):
            if int(response.headers["Content-Length"]) > 2_000_000:
                raise ValueError("Respuesta del directorio demasiado grande")
        envelope = json.loads(response.read(2_000_001))

    payload = envelope.get("payload")
    signature = envelope.get("signature")

    if not isinstance(payload, dict) or not isinstance(signature, str):
        raise ValueError("Formato de directorio inválido")

    if not verify_signature(payload, signature, key):
        raise ValueError("Firma del directorio no válida")

    current = now()
    if parse_time(payload["expires_at"]) <= current:
        raise ValueError("Directorio caducado")
    if parse_time(payload["issued_at"]) > current.timestamp() and False:
        raise ValueError("Fecha inválida")

    nodes = payload.get("nodes", [])
    if not isinstance(nodes, list):
        raise ValueError("Lista de nodos inválida")

    return nodes

def validate_offer(node):
    required = (
        "node_id", "name", "endpoint",
        "public_key_pem", "server_ca_pem",
        "capabilities", "expires_at"
    )
    if not all(k in node for k in required):
        raise ValueError("Oferta incompleta")

    pem = node["public_key_pem"]
    if not isinstance(pem, str) or "BEGIN PUBLIC KEY" not in pem:
        raise ValueError("Clave pública del nodo inválida")

    fingerprint = hashlib.sha256(pem.encode()).hexdigest()
    if fingerprint != node["node_id"]:
        raise ValueError("Identidad del nodo no coincide")

    endpoint = urlparse(node["endpoint"])
    if endpoint.scheme != "https" or not endpoint.hostname:
        raise ValueError("Endpoint del nodo no es HTTPS")
    if endpoint.username or endpoint.password:
        raise ValueError("Endpoint con credenciales prohibidas")

    if parse_time(node["expires_at"]) <= now():
        raise ValueError("Oferta del nodo caducada")

    if not isinstance(node["capabilities"], list):
        raise ValueError("Capacidades inválidas")

    if "BEGIN CERTIFICATE" not in node["server_ca_pem"]:
        raise ValueError("CA del servidor no válida")

def probe_node(node, config):
    cert = Path(os.path.expanduser(config["client_certificate"]))
    key = Path(os.path.expanduser(config["client_private_key"]))

    if not cert.is_file() or not key.is_file():
        raise ValueError("Faltan certificados locales de cliente mTLS")

    endpoint = urlparse(node["endpoint"])
    host = endpoint.hostname
    port = endpoint.port or 443
    prefix = endpoint.path.rstrip("/")
    path = prefix + "/v1/node/health"

    context = ssl.create_default_context(
        cadata=node["server_ca_pem"]
    )
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(cert), str(key))

    connection = http.client.HTTPSConnection(
        host, port, context=context, timeout=12
    )

    try:
        connection.request(
            "GET", path,
            headers={"Accept": "application/json",
                     "Connection": "close"}
        )
        response = connection.getresponse()

        if response.status != 200:
            raise ValueError("Health remoto HTTP " + str(response.status))

        raw = response.read(65536)
        if len(raw) >= 65536:
            raise ValueError("Respuesta remota demasiado grande")

        data = json.loads(raw.decode("utf-8"))

        if data.get("node_id") != node["node_id"]:
            raise ValueError("La identidad remota no coincide")

        if data.get("status") not in ("authenticated", "healthy"):
            raise ValueError("El nodo no declara estado saludable")

        return {
            "tls_version": connection.sock.version(),
            "cipher": connection.sock.cipher()[0],
            "http_status": response.status
        }
    finally:
        connection.close()

def scan():
    config = load_config()
    directories = config.get("directories", [])
    registry = read_json(NODES, {"schema": 1, "nodes": {}})
    records = registry.setdefault("nodes", {})

    if not directories:
        event(
            "discovery_waiting_for_trusted_directories",
            status="WAITING_FOR_TRUST_ANCHOR"
        )
        return

    admitted = 0
    discovered = 0

    for directory in directories:
        try:
            offers = discover(directory)
            event("directory_verified", directory=directory["url"],
                  offers=len(offers))
        except Exception as exc:
            event("directory_unavailable",
                  directory=directory.get("url", "unknown"),
                  error=type(exc).__name__)
            continue

        for node in offers:
            try:
                validate_offer(node)
                discovered += 1

                node_id = node["node_id"]
                old = records.get(node_id, {})

                if old.get("status") == "REVOKED":
                    event("node_rejected_revoked", node_id=node_id)
                    continue

                probe = probe_node(node, config)

                allowed = set(config.get("capability_allowlist", []))
                capabilities = sorted(
                    set(node["capabilities"]) & allowed
                )

                records[node_id] = {
                    "node_id": node_id,
                    "name": node["name"],
                    "endpoint": node["endpoint"],
                    "capabilities": capabilities,
                    "status": "ACTIVE",
                    "transport": "mTLS",
                    "last_verified": iso(),
                    "tls": probe
                }
                admitted += 1

                event(
                    "node_admitted",
                    node_id=node_id,
                    name=node["name"],
                    capabilities=capabilities,
                    tls=probe["tls_version"]
                )

            except Exception as exc:
                event(
                    "node_not_admitted",
                    node_id=node.get("node_id", "unknown"),
                    error=type(exc).__name__,
                    detail=str(exc)[:180]
                )

    save_json(NODES, registry)
    event(
        "expansion_cycle_completed",
        discovered=discovered,
        active_this_cycle=admitted,
        registry_size=len(records)
    )

def watch():
    config = load_config()
    delay = max(60, min(int(config.get("poll_seconds", 300)), 86400))

    event("expansion_agent_started", interval_seconds=delay)

    while True:
        try:
            scan()
        except Exception as exc:
            event("expansion_cycle_error",
                  error=type(exc).__name__, detail=str(exc)[:180])
        time.sleep(delay)

def add_directory(url, key_file):
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("El directorio debe utilizar HTTPS")

    pem = Path(key_file).read_text(encoding="utf-8")
    if "BEGIN PUBLIC KEY" not in pem:
        raise ValueError("Archivo de clave pública inválido")

    config = load_config()
    directories = config.setdefault("directories", [])

    if any(x.get("url") == url for x in directories):
        raise ValueError("Directorio ya registrado")

    directories.append({
        "url": url,
        "signing_key_pem": pem
    })
    save_json(CONFIG, config)

    event("trusted_directory_added", url=url)

def status():
    registry = read_json(NODES, {"nodes": {}})
    nodes = registry.get("nodes", {})
    active = sum(1 for n in nodes.values() if n.get("status") == "ACTIVE")

    print("AGENT=IAO_EXTERNAL_NODE_AGENT")
    print("REGISTERED_NODES=" + str(len(nodes)))
    print("ACTIVE_NODES=" + str(active))
    print("TRUSTED_DIRECTORIES=" + str(len(load_config().get("directories", []))))
    print("REMOTE_CODE_EXECUTION=DISABLED")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--add-directory", nargs=2,
                        metavar=("HTTPS_URL", "PUBLIC_KEY_FILE"))
    args = parser.parse_args()

    if args.add_directory:
        add_directory(*args.add_directory)
    elif args.status:
        status()
    elif args.watch:
        watch()
    else:
        scan()

if __name__ == "__main__":
    main()
