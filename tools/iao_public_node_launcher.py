#!/usr/bin/env python3
"""Arranca nodo federado público con Cloudflare Tunnel.

Responsabilidades:
  1. Levanta FedServer en 127.0.0.1:8443 (HTTP; Cloudflare termina TLS).
  2. Arranca cloudflared tunnel --url http://127.0.0.1:8443.
  3. Captura la URL pública (*.trycloudflare.com).
  4. Construye y firma /.well-known/iao-federation.json.
  5. Adjunta la publicación al FedServer.
  6. Verifica que:
     - https://<url>/fed/v1/identity responde
     - https://<url>/.well-known/iao-federation.json responde y firma válida
     - https://<url>/fed/v1/handshake responde a un challenge
  7. Escribe publication.json firmado + metadatos de operación.
  8. Arranca federation_worker y autonomy --watch en background.

NO abre puertos públicos directamente. NO concede confianza a ningún peer.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".state"
NODE_STATE = STATE / "federation"
PUBLICATION = STATE / "iao-node-network" / "publication.json"
CF_LOG = STATE / "cloudflared.log"
FEDSERVER_LOG = STATE / "fedserver-public.log"
WORKER_LOG = STATE / "federation-worker-public.log"
AUTO_LOG = STATE / "federation-autonomy-public.log"

URL_PATTERN = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")


def utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_dirs() -> None:
    for p in (STATE, NODE_STATE, STATE / "iao-node-network"):
        p.mkdir(parents=True, exist_ok=True)


def load_identity():
    sys.path.insert(0, str(ROOT))
    from omega.federation_identity import load_or_create_key, public_identity
    key = load_or_create_key(NODE_STATE / "identity.key")
    node_id, public_hex = public_identity(key)
    return key, node_id, public_hex


def build_node():
    sys.path.insert(0, str(ROOT))
    from omega.store import Store
    from omega.tools.registry import ToolRegistry, ToolSpec
    from omega.tools.knowledge_search import KnowledgeCorpus
    from omega.federation import Node
    from omega.federation_identity import load_or_create_key

    key = load_or_create_key(NODE_STATE / "identity.key")
    corpus = KnowledgeCorpus(ROOT / "docs" / "corpus")
    reg = ToolRegistry()
    reg.register(ToolSpec("knowledge.search", "1.0.0", "knowledge.search",
                          "READ_ONLY", 5.0,
                          corpus.validate_input, corpus.run, corpus.verify))
    store = Store(str(NODE_STATE / "omega.db"),
                  audit_key=b"iao-public-node-audit-key-0123456789abcdef")
    return Node(store, reg, key=key, served=frozenset({"knowledge.search"}),
                peer_store_path=NODE_STATE / "peers.json")


def start_fedserver(node, port):
    sys.path.insert(0, str(ROOT))
    from omega.federation import FedServer
    server = FedServer(node, host="127.0.0.1", port=port).start()
    return server


def start_cloudflared(port):
    if not shutil.which("cloudflared"):
        raise RuntimeError("CLOUDFLARED_NO_INSTALADO")
    log = CF_LOG.open("ab")
    proc = subprocess.Popen(
        ["cloudflared", "tunnel", "--no-autoupdate",
         "--url", f"http://127.0.0.1:{port}"],
        cwd=str(ROOT), stdin=subprocess.DEVNULL,
        stdout=log, stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    return proc, log


def wait_public_url(timeout=45):
    end = time.time() + timeout
    while time.time() < end:
        try:
            text = CF_LOG.read_text(errors="replace")
            matches = URL_PATTERN.findall(text)
            if matches:
                return matches[-1]
        except OSError:
            pass
        time.sleep(1)
    raise RuntimeError("TUNNEL_URL_TIMEOUT")


def wait_public_https(url, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with urllib.request.urlopen(url + "/fed/v1/identity",
                                        timeout=5) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(1)
    return False


def verify_publication_remote(url):
    with urllib.request.urlopen(
        url + "/.well-known/iao-federation.json", timeout=8
    ) as r:
        return json.loads(r.read(65536).decode())


def verify_handshake_remote(url, node_id):
    requester = secrets.token_hex(8)
    nonce = secrets.token_hex(32)
    request_ts = time.time()
    challenge = {"v": 1, "from": requester, "to": node_id,
                 "nonce": nonce, "ts": request_ts}
    req = urllib.request.Request(
        url + "/fed/v1/handshake", method="POST",
        data=json.dumps(challenge).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=8) as r:
        return json.loads(r.read(65536).decode())


def main():
    ensure_dirs()

    # 1) identidad + nodo
    key, node_id, public_hex = load_identity()
    print(f"NODE_ID={node_id}")
    print(f"PUBLIC_KEY={public_hex[:16]}...")

    node = build_node()

    # 2) puerto local
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    print(f"FEDSERVER_LOCAL_PORT={port}")

    # 3) arrancar FedServer y cloudflared
    server = start_fedserver(node, port)
    print(f"FEDSERVER_READY=True")

    cf_proc, cf_log = start_cloudflared(port)
    print(f"CLOUDFLARED_PID={cf_proc.pid}")

    try:
        public_url = wait_public_url()
        print(f"PUBLIC_URL={public_url}")

        if not wait_public_https(public_url):
            raise RuntimeError("PUBLIC_HTTPS_NOT_READY")

        # 4) construir publicación firmada
        publication = node.identity_publication(public_url)
        server.set_publication(publication)
        print("PUBLICATION_SIGNED=True")

        # 5) verificar remote
        remote_pub = verify_publication_remote(public_url)
        if remote_pub.get("node_id") != node_id:
            raise RuntimeError("PUBLICATION_NODE_ID_MISMATCH")
        from omega.federation import Node
        if not Node.verify_publication(remote_pub):
            raise RuntimeError("PUBLICATION_SIGNATURE_INVALID")
        print("PUBLICATION_REMOTE_VERIFIED=True")

        # 6) handshake remoto
        response = verify_handshake_remote(public_url, node_id)
        if not isinstance(response, dict) or response.get("to") is None:
            raise RuntimeError("HANDSHAKE_REMOTE_INVALID")
        print("HANDSHAKE_REMOTE_OK=True")

        # 7) escribir publicación final
        final = {
            **publication,
            "published_at": utc(),
            "public_url": public_url,
            "local_port": port,
            "cloudflared_pid": cf_proc.pid,
            "verification": {
                "identity_remote_ok": True,
                "publication_remote_ok": True,
                "handshake_remote_ok": True,
            },
        }
        PUBLICATION.write_text(json.dumps(final, indent=2) + "\n",
                               encoding="utf-8")
        print(f"PUBLICATION_PATH={PUBLICATION}")

        # 8) workers de autonomía
        worker = subprocess.Popen(
            [sys.executable, str(ROOT / "tools/iao_federation_worker.py")],
            cwd=str(ROOT), stdin=subprocess.DEVNULL,
            stdout=WORKER_LOG.open("ab"), stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        print(f"FEDERATION_WORKER_PID={worker.pid}")

        auto = subprocess.Popen(
            [sys.executable, str(ROOT / "tools/iao_federation_autonomous.py"),
             "--watch"],
            cwd=str(ROOT), stdin=subprocess.DEVNULL,
            stdout=AUTO_LOG.open("ab"), stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        print(f"FEDERATION_AUTONOMY_PID={auto.pid}")

        print("NODE_PUBLIC_RUNNING=True")
        print(f"OPERATION_LOG_FEDERATION={STATE / 'iao-node-network' / 'federation-audit' / 'events.jsonl'}")

        # Mantener vivo hasta SIGTERM
        stop = threading.Event()
        def _stop(signum, frame):
            stop.set()
        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)
        while not stop.wait(5):
            if cf_proc.poll() is not None:
                print("CLOUDFLARED_DIED")
                break
        print("STOPPING")

    finally:
        try:
            cf_proc.terminate()
            cf_proc.wait(timeout=5)
        except Exception:
            pass
        cf_log.close()
        try:
            server.stop()
        except Exception:
            pass


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"FAIL: {type(exc).__name__}: {exc}")
        sys.exit(1)
