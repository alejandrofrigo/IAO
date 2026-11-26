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
import hashlib
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


def _load_public_node_audit_key():
    """Load or atomically create a private persistent audit HMAC key."""
    import os
    import secrets
    import stat
    from pathlib import Path

    configured = os.environ.get("IAO_PUBLIC_NODE_AUDIT_KEY_FILE")
    path = Path(configured).expanduser() if configured else (
        Path.home() / ".config" / "iao" / "public-node-audit-hmac-key"
    )
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    try:
        fd = os.open(str(path), flags, 0o600)
    except FileExistsError:
        fd = None

    if fd is not None:
        try:
            os.fchmod(fd, 0o600)
            key = secrets.token_bytes(32)
            with os.fdopen(fd, "wb") as stream:
                fd = None
                stream.write(key)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            if fd is not None:
                os.close(fd)
    else:
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("Audit key path is not a regular file")
        os.chmod(path, 0o600)
        key = path.read_bytes()

    if len(key) < 32:
        raise RuntimeError("Persistent audit key is too short")
    return key


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
                  audit_key=_load_public_node_audit_key())
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
    try:
        proc = subprocess.Popen(
            ["cloudflared", "tunnel", "--no-autoupdate",
             "--url", f"http://127.0.0.1:{port}"],
            cwd=str(ROOT), stdin=subprocess.DEVNULL,
            stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except BaseException:
        log.close()
        raise
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


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open_public_https(url, *, data=None, headers=None, timeout=8):
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.netloc or parts.username or parts.password:
        raise RuntimeError("PUBLIC_HTTPS_URL_REQUIRED")
    opener = urllib.request.build_opener(_NoRedirectHandler)
    req = urllib.request.Request(
        url, data=data, headers=headers or {},
        method="POST" if data is not None else "GET",
    )
    response = opener.open(req, timeout=timeout)
    final_url = response.geturl()
    if final_url != url:
        response.close()
        raise RuntimeError("PUBLIC_HTTPS_REDIRECT_REFUSED")
    return response


def _verify_handshake_evidence(
    identity, response, *, node_id, requester, nonce, request_ts, now=None
):
    from tools.iao_federation_binding import verify_binding

    checked = verify_binding(
        identity,
        response,
        expected_node_id=node_id,
        requester_id=requester,
        nonce=nonce,
        request_ts=float(request_ts),
        now=time.time() if now is None else float(now),
        skew=60.0,
    )
    if not checked.get("ok"):
        raise RuntimeError(
            "HANDSHAKE_CRYPTOGRAPHIC_VERIFICATION_FAILED:"
            + str(checked.get("error", "UNKNOWN"))
        )
    return {
        "identity": identity,
        "response": response,
        "requester_id": requester,
        "nonce": nonce,
        "request_ts": float(request_ts),
        "transport": {
            "https_verified": True,
            "redirected": False,
        },
        "cryptographic_verification": checked,
    }


def verify_handshake_remote(url, node_id):
    base = url.rstrip("/")
    identity_url = base + "/fed/v1/identity"
    with _open_public_https(identity_url, timeout=8) as r:
        if r.status != 200:
            raise RuntimeError("REMOTE_IDENTITY_HTTP_STATUS")
        identity = json.loads(r.read(65536).decode("utf-8"))

    if not isinstance(identity, dict):
        raise RuntimeError("REMOTE_IDENTITY_INVALID")
    if identity.get("node_id") != node_id:
        raise RuntimeError("REMOTE_IDENTITY_NODE_ID_MISMATCH")

    requester = secrets.token_hex(8)
    nonce = secrets.token_hex(32)
    request_ts = time.time()
    challenge = {
        "v": 1, "from": requester, "to": node_id,
        "nonce": nonce, "ts": request_ts,
    }
    handshake_url = base + "/fed/v1/handshake"
    with _open_public_https(
        handshake_url,
        data=json.dumps(challenge).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        timeout=8,
    ) as r:
        if r.status != 200:
            raise RuntimeError("REMOTE_HANDSHAKE_HTTP_STATUS")
        response = json.loads(r.read(65536).decode("utf-8"))

    if not isinstance(response, dict):
        raise RuntimeError("HANDSHAKE_REMOTE_INVALID")

    return _verify_handshake_evidence(
        identity,
        response,
        node_id=node_id,
        requester=requester,
        nonce=nonce,
        request_ts=request_ts,
        now=time.time(),
    )



def _persistable_handshake_evidence(evidence):
    """Construye metadatos auditables sin persistir el challenge ni la respuesta."""
    if not isinstance(evidence, dict):
        raise RuntimeError("HANDSHAKE_EVIDENCE_INVALID")

    identity = evidence.get("identity")
    response = evidence.get("response")
    transport = evidence.get("transport")
    verification = evidence.get("cryptographic_verification")

    if not all(isinstance(x, dict) for x in (
        identity, response, transport, verification
    )):
        raise RuntimeError("HANDSHAKE_EVIDENCE_INCOMPLETE")

    if not verification.get("ok"):
        raise RuntimeError("HANDSHAKE_NOT_VERIFIED")
    if verification.get("authorization_granted") is not False:
        raise RuntimeError("HANDSHAKE_AUTHORIZATION_STATE_UNSAFE")
    if verification.get("enrollment_performed") is not False:
        raise RuntimeError("HANDSHAKE_ENROLLMENT_STATE_UNSAFE")
    if transport.get("https_verified") is not True:
        raise RuntimeError("HANDSHAKE_HTTPS_NOT_VERIFIED")
    if transport.get("redirected") is not False:
        raise RuntimeError("HANDSHAKE_REDIRECT_DETECTED")

    node_id = identity.get("node_id")
    public_key = identity.get("public_key")
    if not isinstance(node_id, str) or not node_id:
        raise RuntimeError("HANDSHAKE_IDENTITY_NODE_ID_MISSING")
    if not isinstance(public_key, str) or not public_key:
        raise RuntimeError("HANDSHAKE_IDENTITY_PUBLIC_KEY_MISSING")

    # El hash compromete también la respuesta firmada, el nonce y el
    # contexto del challenge, pero esos datos no se guardan en claro.
    digest_input = {
        "identity": identity,
        "response": response,
        "requester_id": evidence.get("requester_id"),
        "nonce": evidence.get("nonce"),
        "request_ts": evidence.get("request_ts"),
        "transport": transport,
        "cryptographic_verification": verification,
    }
    canonical = json.dumps(
        digest_input, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")

    return {
        "schema": 1,
        "remote_node_id": node_id,
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "signature_verified": True,
        "identity": {
            "protocol": identity.get("protocol"),
            "version": identity.get("version"),
            "node_id": node_id,
            "public_key": public_key,
        },
        "transport": {
            "https_verified": True,
            "redirected": False,
        },
        "authorization_granted": False,
        "enrollment_performed": False,
        "evidence_sha256": hashlib.sha256(canonical).hexdigest(),
    }


def main():
    server = cf_proc = cf_log = worker = auto = None
    worker_log = auto_log = None
    try:
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
            handshake_evidence = verify_handshake_remote(public_url, node_id)
            if not handshake_evidence.get("cryptographic_verification", {}).get("ok"):
                raise RuntimeError("HANDSHAKE_REMOTE_CRYPTOGRAPHIC_VERIFICATION_REQUIRED")
            print("HANDSHAKE_REMOTE_OK=True")
            print("HANDSHAKE_SIGNATURE_VERIFIED=True")

            # 7) escribir publicación final
            persisted_handshake = _persistable_handshake_evidence(
                handshake_evidence
            )
            # El documento principal conserva exclusivamente los campos firmados.
            PUBLICATION.parent.mkdir(parents=True, exist_ok=True)
            PUBLICATION.write_text(
                json.dumps(publication, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

            # Los datos operativos no forman parte de la firma Ed25519.
            runtime_file = PUBLICATION.with_name("publication-runtime.json")
            runtime = {
                "published_at": utc(),
                "public_url": public_url,
                "local_port": port,
                "cloudflared_pid": cf_proc.pid,
                "verification": {
                    "identity_remote_ok": True,
                    "publication_remote_ok": True,
                    "handshake_remote_ok": True,
                    "handshake_signature_verified": True,
                },
                "handshake_evidence": persisted_handshake,
            }
            runtime_file.write_text(
                json.dumps(runtime, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            print(f"PUBLICATION_PATH={PUBLICATION}")
            print(f"PUBLICATION_RUNTIME_PATH={runtime_file}")

            # 8) workers de autonomía
            worker_log = WORKER_LOG.open("ab")
            worker = subprocess.Popen(
                [sys.executable, str(ROOT / "tools/iao_federation_worker.py")],
                cwd=str(ROOT), stdin=subprocess.DEVNULL,
                stdout=worker_log, stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            print(f"FEDERATION_WORKER_PID={worker.pid}")

            auto_log = AUTO_LOG.open("ab")
            auto = subprocess.Popen(
                [sys.executable, str(ROOT / "tools/iao_federation_autonomous.py"),
                 "--watch"],
                cwd=str(ROOT), stdin=subprocess.DEVNULL,
                stdout=auto_log, stderr=subprocess.STDOUT,
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
        # Solo se detienen procesos creados por esta ejecución.
        for _proc_name, _proc in (("auto", auto), ("worker", worker),
                                  ("cloudflared", cf_proc)):
            if _proc is None:
                continue
            try:
                if _proc.poll() is None:
                    _proc.terminate()
                    try:
                        _proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        _proc.kill()
                        _proc.wait(timeout=2)
                record_status = f"CLEANUP_{_proc_name.upper()}=OK"
                print(record_status)
            except ProcessLookupError:
                pass
            except Exception as _exc:
                print(f"CLEANUP_{_proc_name.upper()}_ERROR={type(_exc).__name__}")

        if server is not None:
            try:
                server.stop()
                print("CLEANUP_FEDSERVER=OK")
            except Exception as _exc:
                print(f"CLEANUP_FEDSERVER_ERROR={type(_exc).__name__}")

        for _log_name, _handle in (("worker", worker_log),
                                    ("autonomy", auto_log),
                                    ("cloudflared", cf_log)):
            if _handle is not None:
                try:
                    _handle.close()
                except Exception:
                    pass

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"FAIL: {type(exc).__name__}: {exc}")
        sys.exit(1)
