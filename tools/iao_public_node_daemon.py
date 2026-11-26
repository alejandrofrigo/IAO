#!/usr/bin/env python3
"""Daemon persistente de nodo federado público.

Responsabilidades:
  1. Cargar CA, cert, e identidad del nodo indicado.
  2. Arrancar FedServer con TLS.
  3. Arrancar `bore local` como subproceso.
  4. Esperar a que reporte `bore.pub:<puerto>`.
  5. Construir y publicar identidad firmada.
  6. Verificar remote.
  7. Persistir `publication-<node>.json` y `status-<node>.json`.
  8. Bloquear hasta SIGTERM. No termina solo.

Uso:
    python3 tools/iao_public_node_daemon.py --node a
    python3 tools/iao_public_node_daemon.py --node c

Para arrancarlo desacoplado, usar tools/launch_public_node.sh.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".state"

NODE_CONFIGS = {
    "a": {
        "state_dir": STATE / "federation",
        "pki_dir": STATE / "iao-node-network" / "pki",
        "audit_key": b"iao-public-node-audit-key-0123456789abc",
        "run_workers": True,
        "node_tag": "a",
    },
    "c": {
        "state_dir": STATE / "federation-c",
        "pki_dir": STATE / "iao-node-network" / "pki-c",
        "audit_key": b"iao-node-c-audit-key-0123456789abcdef",
        "run_workers": False,
        "node_tag": "c",
    },
}


def utc():
    return datetime.now(timezone.utc).isoformat()


def log(msg):
    print(f"[{utc()}] {msg}", flush=True)


def load_pki(pki_dir):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    ca_key = serialization.load_pem_private_key(
        (pki_dir / "ca.key").read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate((pki_dir / "ca.crt").read_bytes())
    return ca_key, ca_cert


def build_node(cfg):
    sys.path.insert(0, str(ROOT))
    from omega.federation_identity import load_or_create_key, public_identity
    from omega.store import Store
    from omega.tools.registry import ToolRegistry, ToolSpec
    from omega.tools.knowledge_search import KnowledgeCorpus
    from omega.federation import Node

    key = load_or_create_key(cfg["state_dir"] / "identity.key")
    node_id, public_hex = public_identity(key)

    corpus = KnowledgeCorpus(ROOT / "docs" / "corpus")
    reg = ToolRegistry()
    reg.register(ToolSpec("knowledge.search", "1.0.0", "knowledge.search",
                          "READ_ONLY", 5.0,
                          corpus.validate_input, corpus.run, corpus.verify))
    store = Store(str(cfg["state_dir"] / "omega.db"),
                  audit_key=cfg["audit_key"])
    node = Node(store, reg, key=key,
                served=frozenset({"knowledge.search"}),
                peer_store_path=cfg["state_dir"] / "peers.json")
    return node, node_id, public_hex


def launch_bore(local_port, max_attempts=8):
    log_path = STATE / f"bore-{os.getpid()}.log"
    log_path.write_text("")
    fh = log_path.open("ab")
    delays = [3, 5, 10, 20, 30, 30, 30, 30]
    for attempt in range(max_attempts):
        log(f"BORE_ATTEMPT_{attempt+1}/{max_attempts}")
        bp = subprocess.Popen(
            ["bore", "local", str(local_port), "--to", "bore.pub"],
            cwd=str(ROOT), stdin=subprocess.DEVNULL,
            stdout=fh, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        end = time.time() + 20
        while time.time() < end:
            time.sleep(0.5)
            if bp.poll() is not None:
                log(f"BORE_DIED exit={bp.returncode}")
                break
            try:
                text = log_path.read_text(errors="replace")
                m = re.search(r"listening at bore\.pub:(\d+)", text)
                if m:
                    log(f"BORE_OK public_port={m.group(1)} pid={bp.pid}")
                    return bp, m.group(1), log_path
            except OSError:
                pass
        if bp.poll() is None:
            bp.terminate()
            try:
                bp.wait(timeout=3)
            except subprocess.TimeoutExpired:
                bp.kill()
        if attempt < max_attempts - 1:
            time.sleep(delays[attempt])
    raise RuntimeError("BORE_ALL_ATTEMPTS_FAILED")



def sync_peer_endpoints(cfg, own_node, own_publication=None):
    """Sincroniza el endpoint del peer en peers.json y en Node.peers (memoria).

    Hace dos cosas:
    1. Si existe publication-<peer>.json, actualiza peers.json de este nodo
       con el endpoint del peer y persiste. Llamar ANTES de build_node().
    2. Si se pasa own_node, actualiza node.peers[peer_id]["endpoint"] en
       memoria con el endpoint del peer. Llamar DESPUÉS de arrancar FedServer.

    El propósito es sobrevivir a la naturaleza efímera de bore.pub (puerto
    distinto en cada arranque) sin necesidad de ciclo manual de arranques.
    """
    peer_map = {"a": "c", "c": "a"}
    peer = peer_map.get(cfg.get("node_tag", ""))
    if peer is None:
        return

    pub_peer_file = STATE / "iao-node-network" / f"publication-{peer}.json"
    if not pub_peer_file.is_file():
        log(f"PEER_PUBLICATION_MISSING peer={peer}")
        return

    try:
        pub_peer = json.loads(pub_peer_file.read_text())
    except Exception as e:
        log(f"PEER_PUBLICATION_READ_ERROR {type(e).__name__}")
        return

    # Solo se aceptan publicaciones cuya firma cubre todos sus campos.
    try:
        from omega.federation import Node
        if not Node.verify_publication(pub_peer):
            log(f"PEER_PUBLICATION_SIGNATURE_INVALID peer={peer}")
            return

        peer_id = pub_peer.get("node_id")
        signed_endpoint = pub_peer.get("endpoint")
        if not peer_id or not isinstance(signed_endpoint, str):
            log(f"PEER_PUBLICATION_FIELDS_INVALID peer={peer}")
            return

        from urllib.parse import urlsplit
        parsed = urlsplit(signed_endpoint)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.username
            or parsed.password
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            log(f"PEER_SIGNED_ENDPOINT_INVALID peer={peer}")
            return

        peer_endpoint = signed_endpoint.rstrip("/") + "/fed/v1/message"
    except Exception as e:
        log(f"PEER_PUBLICATION_VALIDATION_ERROR {type(e).__name__}")
        return

    # 1. Actualizar peers.json en disco (antes de build_node)
    if own_publication is None:
        peers_file = cfg["state_dir"] / "peers.json"
        if peers_file.is_file():
            try:
                peers = json.loads(peers_file.read_text())
                updated = False
                for p in peers.get("peers", []):
                    if p.get("peer_id") == peer_id:
                        if p.get("endpoint") != peer_endpoint:
                            p["endpoint"] = peer_endpoint
                            updated = True
                if updated:
                    peers_file.write_text(json.dumps(peers, indent=2))
                    log(f"PEERS_JSON_SYNCED peer={peer} endpoint={peer_endpoint}")
                else:
                    log(f"PEERS_JSON_ALREADY_CURRENT peer={peer}")
            except Exception as e:
                log(f"PEERS_JSON_SYNC_ERROR {type(e).__name__}: {e}")
    else:
        # 2. Actualizar Node.peers en memoria (después de construir Node)
        try:
            with own_node._lock:
                if peer_id in own_node.peers:
                    if own_node.peers[peer_id].get("endpoint") != peer_endpoint:
                        own_node.peers[peer_id]["endpoint"] = peer_endpoint
                        own_node._save_persistent_peers()
                        log(f"NODE_MEMORY_SYNCED peer={peer} endpoint={peer_endpoint}")
                    else:
                        log(f"NODE_MEMORY_ALREADY_CURRENT peer={peer}")
                else:
                    log(f"NODE_PEER_NOT_IN_MEMORY peer={peer} id={peer_id}")
        except Exception as e:
            log(f"NODE_MEMORY_SYNC_ERROR {type(e).__name__}: {e}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", required=True, choices=["a", "c"])
    args = parser.parse_args()

    cfg = NODE_CONFIGS[args.node]
    log(f"DAEMON_STARTING node={args.node}")
    log(f"STATE_DIR={cfg['state_dir']}")
    log(f"PKI_DIR={cfg['pki_dir']}")

    # 1. Cargar PKI
    ca_key, ca_cert = load_pki(cfg["pki_dir"])
    ca_fp = hashlib.sha256(
        ca_cert.public_bytes(__import__("cryptography.hazmat.primitives.serialization",
                                        fromlist=["x"]).Encoding.DER)
    ).hexdigest()
    log(f"CA_FINGERPRINT_SHA256={ca_fp}")

    # 2a. Sincronizar endpoint del peer en peers.json (antes de construir Node)
    sync_peer_endpoints(cfg, None)

    # 2b. Construir Node
    node, node_id, public_hex = build_node(cfg)
    log(f"NODE_ID={node_id}")

    # 3. Arrancar FedServer con TLS
    from omega.federation import FedServer
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    local_tls_port = s.getsockname()[1]
    s.close()
    log(f"LOCAL_TLS_PORT={local_tls_port}")

    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(str(cfg["pki_dir"] / "node.crt"),
                          str(cfg["pki_dir"] / "node.key"))
    sctx.minimum_version = ssl.TLSVersion.TLSv1_2
    server = FedServer(node, host="127.0.0.1",
                        port=local_tls_port, ssl_context=sctx).start()
    log("FEDSERVER_TLS_READY=True")

    # Verificar local
    ca_file = cfg["pki_dir"] / "ca.crt"
    ctx_local = ssl.create_default_context(cafile=str(ca_file))
    try:
        with urllib.request.urlopen(
            f"https://127.0.0.1:{local_tls_port}/fed/v1/identity",
            timeout=5, context=ctx_local) as r:
            if r.status != 200:
                raise RuntimeError("LOCAL_IDENTITY_NOT_200")
        log("LOCAL_TLS_OK=True")
    except Exception as e:
        log(f"LOCAL_TLS_FAIL {type(e).__name__}: {e}")
        server.stop()
        return 1

    # 4. Arrancar bore
    bore_proc, public_port, bore_log = launch_bore(local_tls_port)
    public_url = f"https://bore.pub:{public_port}"
    log(f"PUBLIC_URL={public_url}")

    # 5. Publicación firmada
    publication = node.identity_publication(public_url)
    server.set_publication(publication)
    log("PUBLICATION_SIGNED=True")

    # 5. Sincronizar endpoint del peer en Node.peers (memoria) tras publicación
    #    (por si el otro nodo ya publicó y nosotros arrancamos después)
    sync_peer_endpoints(cfg, node, own_publication=publication)

    # 6. Verificar remote (con reintentos)
    remote_ok = False
    for attempt in range(30):
        try:
            with urllib.request.urlopen(
                public_url + "/fed/v1/identity",
                timeout=10, context=ctx_local) as r:
                r.read(500)
                remote_ok = True
                log(f"REMOTE_IDENTITY_OK attempt={attempt+1}")
                break
        except Exception as e:
            if attempt % 5 == 0:
                log(f"REMOTE_ATTEMPT_{attempt+1}: {type(e).__name__}")
        time.sleep(2)

    if not remote_ok:
        log("REMOTE_IDENTITY_FAIL")
        bore_proc.terminate()
        server.stop()
        return 2

    # 7. Persistir publication-<node>.json y status-<node>.json
    publication_file = STATE / "iao-node-network" / f"publication-{args.node}.json"
    # Guardar intacta la publicación Ed25519: no añadir metadatos tras firmarla.
    publication_file.write_text(
        json.dumps(publication, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    log(f"PUBLICATION_PATH={publication_file}")

    # 8. Arrancar workers si aplica
    worker_pid = None
    autonomy_pid = None
    if cfg["run_workers"]:
        worker = subprocess.Popen(
            [sys.executable, str(ROOT / "tools" / "iao_federation_worker.py")],
            cwd=str(ROOT), stdin=subprocess.DEVNULL,
            stdout=(STATE / f"worker-{args.node}.log").open("ab"),
            stderr=subprocess.STDOUT, start_new_session=True,
        )
        worker_pid = worker.pid
        autonomy = subprocess.Popen(
            [sys.executable, str(ROOT / "tools" / "iao_federation_autonomous.py"),
             "--watch"],
            cwd=str(ROOT), stdin=subprocess.DEVNULL,
            stdout=(STATE / f"autonomy-{args.node}.log").open("ab"),
            stderr=subprocess.STDOUT, start_new_session=True,
        )
        autonomy_pid = autonomy.pid
        log(f"WORKERS: worker={worker_pid} autonomy={autonomy_pid}")

    status_file = STATE / "iao-node-network" / f"status-{args.node}.json"
    status = {
        "node": args.node,
        "node_id": node_id,
        "public_url": public_url,
        "public_endpoint": f"bore.pub:{public_port}/fed/v1/message",
        "ca_fingerprint": ca_fp,
        "ca_pem": ca_cert.public_bytes(
            __import__("cryptography.hazmat.primitives.serialization",
                       fromlist=["x"]).Encoding.PEM).decode(),
        "started_at": utc(),
        "bore_pid": bore_proc.pid,
        "worker_pid": worker_pid,
        "autonomy_pid": autonomy_pid,
        "daemon_pid": os.getpid(),
        "local_tls_port": local_tls_port,
    }
    status_file.write_text(json.dumps(status, indent=2), encoding="utf-8")
    log(f"STATUS_PATH={status_file}")

    # 9. Avisar a Node A que recargue su publicación (para el próximo arranque)
    # No hace falta ahora; cada uno lee su propio publication-<node>.json.

    log("DAEMON_READY=True")

    # 10. Bloquear hasta SIGTERM + polling de sincronizacion cada 30s
    import threading
    stop = {"v": False}

    def _stop(signum, frame):
        stop["v"] = True
        log(f"STOP_SIGNAL={signum}")

    def _poller():
        while not stop["v"]:
            try:
                sync_peer_endpoints(cfg, node)
            except Exception as e:
                log(f"POLLER_ERROR {type(e).__name__}")
            for _ in range(30):
                if stop["v"]:
                    return
                time.sleep(1)

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    poller = threading.Thread(target=_poller, daemon=True,
                              name="iao-peer-sync-poller")
    poller.start()
    log("POLLER_STARTED interval_seconds=30")
    while not stop["v"]:
        time.sleep(2)
        if bore_proc.poll() is not None:
            log(f"BORE_DIED exit={bore_proc.returncode}")
            break

    log("DAEMON_STOPPING")
    try:
        bore_proc.terminate()
        bore_proc.wait(timeout=5)
    except Exception:
        try: bore_proc.kill()
        except Exception: pass
    try:
        server.stop()
    except Exception:
        pass
    log("DAEMON_STOPPED")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"DAEMON_FAIL {type(exc).__name__}: {exc}", flush=True)
        sys.exit(1)
