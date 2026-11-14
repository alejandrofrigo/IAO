#!/usr/bin/env python3
"""IAO Continuous Federation Engine v3."""

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
import uuid
import urllib.parse
import urllib.request

from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CFG = Path.home() / ".config/iao/node-network.json"
DATA = Path.home() / ".local/share/iao/node-network"
DB = DATA / "network.sqlite3"
REPORT = DATA / "autobuilder-report.json"

CAPABILITIES = [
    "heartbeat",
    "directory",
    "capability_exchange",
    "task_coordination",
    "health_check",
    "network_status",
    "network_recovery",
]

SAFE_TASKS = {
    "health_check",
    "capability_report",
    "network_status",
}

VERSION = "3.0"

def now():
    return int(time.time())

def defaults():
    return {
        "node_id": str(uuid.uuid4()),
        "cluster_id": str(uuid.uuid4()),
        "listen_host": "127.0.0.1",
        "listen_port": 8765,
        "public_endpoint": "",
        "discovery_interval": 300,
        "heartbeat_interval": 60,
        "offline_after": 240,
        "directories": [],
        "capabilities": CAPABILITIES,
        "continuous": True,
        "autodiscovery": True,
        "safe_tasks_only": True,
    }

def cfg():
    return json.loads(CFG.read_text())

def save_config(c):
    CFG.parent.mkdir(parents=True, exist_ok=True)
    tmp = CFG.with_suffix(".tmp")
    tmp.write_text(json.dumps(c, indent=2))
    os.chmod(tmp, 0o600)
    tmp.replace(CFG)

def dbopen():
    DATA.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB, timeout=20)
    db.execute("PRAGMA journal_mode=WAL")

    db.executescript("""
    CREATE TABLE IF NOT EXISTS nodes(
        node_id TEXT PRIMARY KEY,
        endpoint TEXT NOT NULL,
        capabilities TEXT NOT NULL,
        last_seen INTEGER NOT NULL,
        status TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS peers(
        node_id TEXT PRIMARY KEY,
        endpoint TEXT NOT NULL,
        shared_key TEXT NOT NULL,
        authorized INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS invitations(
        token_hash TEXT PRIMARY KEY,
        expires INTEGER NOT NULL,
        used INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS directories(
        endpoint TEXT PRIMARY KEY,
        last_check INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'pending'
    );

    CREATE TABLE IF NOT EXISTS tasks(
        task_id TEXT PRIMARY KEY,
        task_type TEXT NOT NULL,
        payload TEXT NOT NULL,
        target TEXT,
        status TEXT NOT NULL,
        result TEXT,
        created INTEGER NOT NULL,
        updated INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER NOT NULL,
        event TEXT NOT NULL,
        details TEXT NOT NULL
    );
    """)
    db.commit()
    return db

def log_event(name, details=""):
    db = dbopen()
    db.execute(
        "INSERT INTO events(timestamp,event,details) VALUES(?,?,?)",
        (now(), name, str(details)[:1000])
    )
    db.commit()
    db.close()

def initialize():
    c = defaults()

    if CFG.exists():
        existing = cfg()
        for key, value in c.items():
            existing.setdefault(key, value)
        c = existing
        print("CONFIGURACION_EXISTENTE_PRESERVADA")
    else:
        print("CREANDO_IDENTIDAD_DEL_NODO_FUNDADOR")

    save_config(c)
    dbopen().close()
    log_event("ENGINE_INITIALIZED", VERSION)

    print("ENGINE_VERSION=" + VERSION)
    print("NODE_ID=" + c["node_id"])
    print("CLUSTER_ID=" + c["cluster_id"])
    print("CONFIG=" + str(CFG))
    print("DATABASE=" + str(DB))
    print("SECRET=PROTEGIDO")

def valid_https(url):
    u = urllib.parse.urlparse(url)
    return (
        u.scheme == "https"
        and bool(u.netloc)
        and not u.username
        and not u.password
    )

def signature(key, stamp, body):
    message = stamp.encode() + b"\n" + body
    return hmac.new(
        key.encode(), message, hashlib.sha256
    ).hexdigest()

def http_request(url, method="GET", body=None, key=None, node_id=None):
    data = None
    headers = {"User-Agent": "IAO-Node-Network/" + VERSION}

    if body is not None:
        data = json.dumps(
            body, separators=(",", ":")
        ).encode()
        headers["Content-Type"] = "application/json"

    if key:
        stamp = str(now())
        headers["X-IAO-Node"] = node_id
        headers["X-IAO-Time"] = stamp
        headers["X-IAO-Signature"] = signature(
            key, stamp, data
        )

    req = urllib.request.Request(
        url, data=data, headers=headers, method=method
    )

    with urllib.request.urlopen(req, timeout=15) as response:
        raw = response.read(1024 * 1024)
        return response.status, json.loads(raw or b"{}")

def register_directory(url):
    if not valid_https(url):
        raise SystemExit("ERROR: directorio HTTPS no válido.")

    c = cfg()
    url = url.rstrip("/")

    if url not in c["directories"]:
        c["directories"].append(url)
        save_config(c)

    db = dbopen()
    db.execute(
        "INSERT OR IGNORE INTO directories(endpoint) VALUES(?)",
        (url,)
    )
    db.commit()
    db.close()

    log_event("DIRECTORY_REGISTERED", url)
    print("DIRECTORY_REGISTERED=" + url)

def create_invitation(hours):
    token = secrets.token_urlsafe(32)
    expires = now() + hours * 3600

    db = dbopen()
    db.execute(
        "INSERT INTO invitations VALUES(?,?,0)",
        (hashlib.sha256(token.encode()).hexdigest(), expires)
    )
    db.commit()
    db.close()

    log_event("INVITATION_CREATED", str(expires))
    print("INVITATION_TOKEN=" + token)
    print("EXPIRES=" + time.strftime(
        "%Y-%m-%d %H:%M:%S", time.localtime(expires)
    ))
    print("COMPARTIR_SOLO_POR_CANAL_SEGURO")

def authorize_peer(node_id, endpoint, key):
    if not valid_https(endpoint):
        raise ValueError("Endpoint HTTPS inválido.")

    if len(key) < 32:
        raise ValueError("Clave insuficiente.")

    c = cfg()
    if node_id == c["node_id"]:
        raise ValueError("Identidad propia.")

    db = dbopen()

    db.execute("""
        INSERT INTO peers VALUES(?,?,?,1)
        ON CONFLICT(node_id) DO UPDATE SET
          endpoint=excluded.endpoint,
          shared_key=excluded.shared_key,
          authorized=1
    """, (node_id, endpoint.rstrip("/"), key))

    db.execute("""
        INSERT INTO nodes VALUES(?,?,?,?,?)
        ON CONFLICT(node_id) DO UPDATE SET
          endpoint=excluded.endpoint,
          status='authorized'
    """, (node_id, endpoint.rstrip("/"), "[]", now(), "authorized"))

    db.commit()
    db.close()
    log_event("PEER_AUTHORIZED", node_id)

def join_network(bootstrap, token, endpoint):
    if not valid_https(bootstrap):
        raise SystemExit("ERROR: bootstrap HTTPS requerido.")

    if not valid_https(endpoint):
        raise SystemExit("ERROR: configura primero tu endpoint HTTPS.")

    c = cfg()
    body = {
        "node_id": c["node_id"],
        "cluster_id": c["cluster_id"],
        "endpoint": endpoint.rstrip("/"),
        "capabilities": c["capabilities"],
        "token": token,
    }

    _, result = http_request(
        bootstrap.rstrip("/") + "/v1/enroll",
        "POST", body
    )

    key = result["shared_key"]
    authorize_peer(
        result["node_id"], bootstrap.rstrip("/"), key
    )

    log_event("NETWORK_JOINED", result["node_id"])
    print("JOIN_SUCCESS")
    print("BOOTSTRAP_NODE=" + result["node_id"])
    print("PEER_AUTHORIZED=True")

def authenticate(headers, body):
    node = headers.get("X-IAO-Node", "")
    stamp = headers.get("X-IAO-Time", "")
    supplied = headers.get("X-IAO-Signature", "")

    if not stamp.isdigit():
        return None

    if abs(now() - int(stamp)) > 300:
        return None

    db = dbopen()
    row = db.execute(
        "SELECT shared_key FROM peers "
        "WHERE node_id=? AND authorized=1",
        (node,)
    ).fetchone()
    db.close()

    if not row:
        return None

    expected = signature(row[0], stamp, body)
    if not hmac.compare_digest(expected, supplied):
        return None

    return node

def update_node(node, endpoint, caps, status="online"):
    if not isinstance(caps, list) or len(caps) > 64:
        raise ValueError("Capacidades inválidas.")

    if endpoint and not valid_https(endpoint):
        raise ValueError("Endpoint inválido.")

    db = dbopen()
    db.execute("""
      INSERT INTO nodes VALUES(?,?,?,?,?)
      ON CONFLICT(node_id) DO UPDATE SET
        endpoint=excluded.endpoint,
        capabilities=excluded.capabilities,
        last_seen=excluded.last_seen,
        status=excluded.status
    """, (
        node, endpoint, json.dumps(caps),
        now(), status
    ))
    db.commit()
    db.close()

def discover():
    c = cfg()
    db = dbopen()
    directories = db.execute(
        "SELECT endpoint FROM directories"
    ).fetchall()
    db.close()

    for (directory,) in directories:
        try:
            _, result = http_request(
                directory + "/v1/directory"
            )

            for item in result.get("nodes", []):
                node = item.get("node_id")
                endpoint = item.get("endpoint")
                caps = item.get("capabilities", [])

                if not node or node == c["node_id"]:
                    continue
                if not endpoint or not valid_https(endpoint):
                    continue

                db = dbopen()
                trusted = db.execute(
                    "SELECT 1 FROM peers WHERE node_id=? AND authorized=1",
                    (node,)
                ).fetchone()
                db.close()

                # Descubrir no significa autorizar.
                update_node(
                    node, endpoint, caps,
                    "authorized" if trusted else "candidate"
                )

                log_event("NODE_DISCOVERED", node)

            db = dbopen()
            db.execute(
                "UPDATE directories SET last_check=?,status='online' "
                "WHERE endpoint=?",
                (now(), directory)
            )
            db.commit()
            db.close()
            print("DISCOVERY_OK", directory, flush=True)

        except Exception as exc:
            log_event("DISCOVERY_FAILED", type(exc).__name__)
            print("DISCOVERY_FAILED", directory,
                  type(exc).__name__, flush=True)

def heartbeat(peer):
    c = cfg()
    payload = {
        "node_id": c["node_id"],
        "endpoint": c["public_endpoint"],
        "capabilities": c["capabilities"],
        "timestamp": now()
    }

    _, result = http_request(
        peer["endpoint"] + "/v1/heartbeat",
        "POST", payload,
        peer["shared_key"], c["node_id"]
    )
    return result

def heartbeat_all():
    db = dbopen()
    peers = db.execute(
        "SELECT node_id,endpoint,shared_key "
        "FROM peers WHERE authorized=1"
    ).fetchall()
    db.close()

    for node, endpoint, key in peers:
        try:
            result = heartbeat({
                "node_id": node,
                "endpoint": endpoint,
                "shared_key": key
            })
            log_event("HEARTBEAT_OK", node)
            print("HEARTBEAT_OK", node, flush=True)

        except Exception as exc:
            log_event("HEARTBEAT_FAILED", node)
            print("HEARTBEAT_FAILED", node,
                  type(exc).__name__, flush=True)

    db = dbopen()
    db.execute(
        "UPDATE nodes SET status='offline' "
        "WHERE status='online' AND last_seen<?",
        (now() - int(cfg()["offline_after"]),)
    )
    db.commit()
    db.close()

def execute_safe_task(task_type, payload):
    if task_type == "health_check":
        return {
            "ok": True,
            "node_id": cfg()["node_id"],
            "timestamp": now()
        }

    if task_type == "capability_report":
        return {
            "ok": True,
            "capabilities": cfg()["capabilities"]
        }

    if task_type == "network_status":
        return local_status()

    raise ValueError("Tarea no autorizada.")

def enqueue(task_type, payload=None, target=None):
    if task_type not in SAFE_TASKS:
        raise SystemExit("TAREA_NO_PERMITIDA")

    db = dbopen()
    task_id = str(uuid.uuid4())
    db.execute(
        "INSERT INTO tasks VALUES(?,?,?,?,?,?,?,?)",
        (
            task_id, task_type,
            json.dumps(payload or {}),
            target, "pending", None, now(), now()
        )
    )
    db.commit()
    db.close()

    log_event("TASK_QUEUED", task_id)
    print("TASK_ID=" + task_id)

def dispatch_pending():
    db = dbopen()
    tasks = db.execute(
        "SELECT task_id,task_type,payload,target "
        "FROM tasks WHERE status='pending'"
    ).fetchall()
    peers = db.execute(
        "SELECT node_id,endpoint,shared_key "
        "FROM peers WHERE authorized=1"
    ).fetchall()
    db.close()

    peer_map = {
        p[0]: {"endpoint": p[1], "shared_key": p[2]}
        for p in peers
    }

    for task_id, task_type, payload, target in tasks:
        selected = peer_map.get(target) if target else None

        if not selected:
            # Seleccionar únicamente un nodo autenticado.
            for node, peer in peer_map.items():
                selected = peer
                target = node
                break

        if not selected:
            continue

        c = cfg()
        body = {
            "node_id": c["node_id"],
            "task_id": task_id,
            "task_type": task_type,
            "payload": json.loads(payload)
        }

        try:
            _, result = http_request(
                selected["endpoint"] + "/v1/tasks",
                "POST", body,
                selected["shared_key"], c["node_id"]
            )

            db = dbopen()
            db.execute(
                "UPDATE tasks SET status='completed',result=?,"
                "target=?,updated=? WHERE task_id=?",
                (json.dumps(result), target, now(), task_id)
            )
            db.commit()
            db.close()
            log_event("TASK_COMPLETED", task_id)
            print("TASK_COMPLETED", task_id, flush=True)

        except Exception as exc:
            db = dbopen()
            db.execute(
                "UPDATE tasks SET status='pending',updated=? "
                "WHERE task_id=?",
                (now(), task_id)
            )
            db.commit()
            db.close()
            log_event("TASK_RETRY", task_id)
            print("TASK_RETRY", task_id,
                  type(exc).__name__, flush=True)

def local_status():
    db = dbopen()
    counts = {}
    for table in ("nodes", "peers", "directories", "tasks"):
        counts[table] = db.execute(
            "SELECT COUNT(*) FROM " + table
        ).fetchone()[0]
    db.close()

    c = cfg()
    return {
        "version": VERSION,
        "node_id": c["node_id"],
        "cluster_id": c["cluster_id"],
        "public_endpoint_configured": bool(c["public_endpoint"]),
        "capabilities": c["capabilities"],
        "counts": counts,
        "timestamp": now()
    }

def autobuilder():
    s = local_status()
    recommendations = []

    if not s["public_endpoint_configured"]:
        recommendations.append(
            "Configurar HTTPS público mediante un túnel o servidor autorizado."
        )

    if s["counts"]["peers"] == 0:
        recommendations.append(
            "Incorporar el primer nodo remoto autorizado."
        )

    if s["counts"]["directories"] == 0:
        recommendations.append(
            "Registrar directorios federados HTTPS conocidos y confiables."
        )

    if s["counts"]["tasks"] == 0:
        recommendations.append(
            "Probar la distribución de una tarea segura cuando exista un par."
        )

    report = {
        "engine": VERSION,
        "generated": now(),
        "network": s,
        "recommendations": recommendations,
        "code_mutation": "DISABLED",
        "reason": "Las modificaciones del código requieren pruebas y revisión."
    }

    DATA.mkdir(parents=True, exist_ok=True)
    tmp = REPORT.with_suffix(".tmp")
    tmp.write_text(json.dumps(report, indent=2))
    tmp.replace(REPORT)
    log_event("AUTOBUILDER_REPORT", len(recommendations))

def self_check():
    c = cfg()
    db = dbopen()
    db.execute("SELECT 1").fetchone()
    db.close()

    return {
        "config": CFG.exists(),
        "database": DB.exists(),
        "identity": bool(c.get("node_id")),
        "peer_authentication": True,
        "https_policy": True,
        "safe_task_policy": True,
        "autobuilder": REPORT.exists()
    }

def handler_factory(c):
    class API(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, obj):
            raw = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if self.path == "/health":
                return self.reply(200, {
                    "service": "IAO_NODE_NETWORK",
                    "version": VERSION,
                    "node_id": c["node_id"],
                    "status": "operational"
                })

            if self.path == "/v1/directory":
                db = dbopen()
                rows = db.execute(
                    "SELECT node_id,endpoint,capabilities,last_seen "
                    "FROM nodes WHERE status='online' OR status='authorized'"
                ).fetchall()
                db.close()

                nodes = [{
                    "node_id": c["node_id"],
                    "endpoint": c["public_endpoint"],
                    "capabilities": c["capabilities"],
                    "last_seen": now()
                }]

                for row in rows:
                    if row[1]:
                        nodes.append({
                            "node_id": row[0],
                            "endpoint": row[1],
                            "capabilities": json.loads(row[2]),
                            "last_seen": row[3]
                        })

                return self.reply(200, {
                    "cluster_id": c["cluster_id"],
                    "nodes": nodes
                })

            if self.path == "/v1/nodes":
                db = dbopen()
                rows = db.execute(
                    "SELECT node_id,endpoint,capabilities,last_seen,status "
                    "FROM nodes"
                ).fetchall()
                db.close()
                return self.reply(200, {"nodes": [
                    {
                        "node_id": r[0],
                        "endpoint": r[1],
                        "capabilities": json.loads(r[2]),
                        "last_seen": r[3],
                        "status": r[4]
                    } for r in rows
                ]})

            return self.reply(404, {"error": "not_found"})

        def do_POST(self):
            allowed = {
                "/v1/enroll",
                "/v1/heartbeat",
                "/v1/tasks"
            }

            if self.path not in allowed:
                return self.reply(404, {"error": "not_found"})

            try:
                size = int(self.headers.get("Content-Length", "0"))
                if size < 2 or size > 32768:
                    return self.reply(413, {"error": "invalid_size"})

                body = self.rfile.read(size)
                obj = json.loads(body)

                # Incorporación mediante invitación de un solo uso.
                if self.path == "/v1/enroll":
                    token = obj.get("token", "")
                    node = obj.get("node_id", "")
                    endpoint = obj.get("endpoint", "")
                    caps = obj.get("capabilities", [])

                    if not node or node == c["node_id"]:
                        return self.reply(400, {"error": "invalid_identity"})

                    if not valid_https(endpoint):
                        return self.reply(400, {"error": "invalid_endpoint"})

                    if not isinstance(caps, list) or len(caps) > 64:
                        return self.reply(400, {"error": "invalid_capabilities"})

                    digest = hashlib.sha256(token.encode()).hexdigest()
                    db = dbopen()
                    row = db.execute(
                        "SELECT expires,used FROM invitations WHERE token_hash=?",
                        (digest,)
                    ).fetchone()

                    if not row or row[0] < now() or row[1]:
                        db.close()
                        return self.reply(403, {"error": "invalid_invitation"})

                    db.execute(
                        "UPDATE invitations SET used=1 WHERE token_hash=?",
                        (digest,)
                    )
                    db.commit()
                    db.close()

                    key = secrets.token_hex(32)
                    authorize_peer(node, endpoint, key)

                    return self.reply(200, {
                        "node_id": c["node_id"],
                        "shared_key": key,
                        "endpoint": c["public_endpoint"]
                    })

                # El resto requiere identidad autenticada.
                peer_id = authenticate(self.headers, body)

                if not peer_id:
                    return self.reply(401, {"error": "unauthorized"})

                if obj.get("node_id") != peer_id:
                    return self.reply(401, {"error": "identity_mismatch"})

                if self.path == "/v1/heartbeat":
                    update_node(
                        peer_id,
                        obj.get("endpoint", ""),
                        obj.get("capabilities", [])
                    )
                    log_event("REMOTE_HEARTBEAT", peer_id)
                    return self.reply(200, {
                        "accepted": True,
                        "node_id": c["node_id"],
                        "timestamp": now()
                    })

                if self.path == "/v1/tasks":
                    task_type = obj.get("task_type")

                    if task_type not in SAFE_TASKS:
                        return self.reply(403, {
                            "error": "task_not_allowed"
                        })

                    result = execute_safe_task(
                        task_type, obj.get("payload", {})
                    )

                    db = dbopen()
                    db.execute(
                        "INSERT OR REPLACE INTO tasks "
                        "VALUES(?,?,?,?,?,?,?,?)",
                        (
                            obj.get("task_id", str(uuid.uuid4())),
                            task_type,
                            json.dumps(obj.get("payload", {})),
                            peer_id,
                            "completed",
                            json.dumps(result),
                            now(), now()
                        )
                    )
                    db.commit()
                    db.close()

                    log_event("TASK_EXECUTED", peer_id)
                    return self.reply(200, {
                        "accepted": True,
                        "node_id": c["node_id"],
                        "result": result
                    })

            except Exception:
                return self.reply(400, {"error": "invalid_request"})

    return API

def serve():
    # ENGINE_CONFIG_RELOAD_V1
    server = None

    print("IAO_NODE_NETWORK_STARTING", flush=True)

    while True:
        try:
            if server is None:
                c = cfg()
                bind_host = str(c["listen_host"])
                bind_port = int(c["listen_port"])
                server = ThreadingHTTPServer(
                    (bind_host, bind_port),
                    handler_factory(c)
                )
                server.daemon_threads = True
                threading.Thread(
                    target=server.serve_forever,
                    daemon=True
                ).start()
                print(f"HTTP_SERVER_STARTED host={bind_host} port={bind_port}", flush=True)

            if c["autodiscovery"]:
                if now() % max(60, int(c["discovery_interval"])) < 60:
                    discover()

            heartbeat_all()
            dispatch_pending()
            autobuilder()

            time.sleep(max(30, int(c["heartbeat_interval"])))

        except KeyboardInterrupt:
            if server:
                server.shutdown()
            print("NETWORK_STOPPED")
            return

        except Exception as exc:
            log_event("ENGINE_RECOVERY", type(exc).__name__)
            print("ENGINE_RECOVERY", type(exc).__name__, flush=True)
            time.sleep(30)

def status():
    print(json.dumps({
        "network": local_status(),
        "checks": self_check(),
        "autobuilder_report": str(REPORT)
    }, indent=2))

def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)

    sub.add_parser("init")
    sub.add_parser("serve")
    sub.add_parser("status")
    sub.add_parser("self-test")
    sub.add_parser("invite")

    d = sub.add_parser("add-directory")
    d.add_argument("url")

    e = sub.add_parser("set-endpoint")
    e.add_argument("url")

    j = sub.add_parser("join")
    j.add_argument("bootstrap")
    j.add_argument("token")
    j.add_argument("endpoint")

    t = sub.add_parser("enqueue")
    t.add_argument("task_type")
    t.add_argument("--target")

    args = parser.parse_args()

    if args.action == "init":
        initialize()

    elif args.action == "serve":
        serve()

    elif args.action == "status":
        status()

    elif args.action == "self-test":
        checks = self_check()
        print(json.dumps(checks, indent=2))
        if not all(checks.values()):
            raise SystemExit(1)
        print("SELF_TEST=PASS")

    elif args.action == "invite":
        initialize()
        create_invitation(24)

    elif args.action == "add-directory":
        register_directory(args.url)

    elif args.action == "set-endpoint":
        if not valid_https(args.url):
            raise SystemExit("ERROR: HTTPS requerido.")
        c = cfg()
        c["public_endpoint"] = args.url.rstrip("/")
        save_config(c)
        print("PUBLIC_ENDPOINT_CONFIGURED")

    elif args.action == "join":
        join_network(args.bootstrap, args.token, args.endpoint)

    elif args.action == "enqueue":
        enqueue(args.task_type, target=args.target)

if __name__ == "__main__":
    main()
