#!/usr/bin/env python3
"""Gestor seguro de conectividad externa IAO. No enrola ni autoriza pares."""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".state" / "federation-external"
PID_DIR = STATE / "pids"
FED_PID = PID_DIR / "fedserver.pid"
CF_PID = PID_DIR / "cloudflared.pid"
PUBLICATION = STATE / "publication.json"
FED_LOG = STATE / "fedserver.log"
CF_LOG = STATE / "cloudflared.log"
LOCAL_URL = "http://127.0.0.1:8443/fed/v1/identity"
URL_PATTERN = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")

def now():
    return datetime.now(timezone.utc).isoformat()

def atomic_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n")
    os.replace(tmp, path)

def process_matches(pidfile, expected):
    try:
        raw = pidfile.read_text().strip()
        try:
            record = json.loads(raw)
            pid = int(record["pid"]) if isinstance(record, dict) else int(record)
        except (json.JSONDecodeError, TypeError, KeyError):
            pid = int(raw)
        if pid <= 1:
            return None
        raw_cmd = Path(f"/proc/{pid}/cmdline").read_bytes()
        cmd = raw_cmd.replace(bytes([0]), b" ").decode(errors="replace")
        if expected not in cmd:
            return None
        os.kill(pid, 0)
        return pid
    except (OSError, ValueError, TypeError):
        return None


def process_args(pid):
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
        return [x.decode(errors="replace") for x in raw.split(bytes([0])) if x]
    except OSError:
        return []


def find_fedserver_process():
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        args = process_args(entry.name)
        if "tools/iao_fedserver_public.py" not in " ".join(args):
            continue
        if "--port" not in args:
            continue
        i = args.index("--port")
        if args[i + 1:i + 2] != ["8443"]:
            continue
        try:
            os.kill(int(entry.name), 0)
            return int(entry.name)
        except OSError:
            pass
    return None


def find_cloudflared_process():
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        args = process_args(entry.name)
        if not any(Path(x).name == "cloudflared" for x in args[:3]):
            continue
        if "tunnel" not in args or "--url" not in args:
            continue
        i = args.index("--url")
        if args[i + 1:i + 2] != ["http://127.0.0.1:8443"]:
            continue
        try:
            os.kill(int(entry.name), 0)
            return int(entry.name)
        except OSError:
            pass
    return None


def identity_matches_private_key(identity):
    try:
        from cryptography.hazmat.primitives import serialization
        key_path = ROOT / ".state/federation/identity/private.pem"
        key = serialization.load_pem_private_key(
            key_path.read_bytes(), password=None
        )
        public = key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        ).hex()
        return identity.get("public_key") == public
    except Exception:
        return False


def backup_pidfile(path):
    if path.exists():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        target = path.with_name(path.name + ".before-adoption-" + stamp + ".bak")
        shutil.copy2(path, target)
        print("PIDFILE_BACKUP=" + str(target))


def adopt_pidfile(path, pid):
    current = None
    if path.exists():
        try:
            raw = path.read_text().strip()
            try:
                obj = json.loads(raw)
                current = int(obj["pid"]) if isinstance(obj, dict) else int(obj)
            except Exception:
                current = int(raw)
        except Exception:
            pass
    if current != pid:
        backup_pidfile(path)
        write_pid(path, pid)
    return pid


def process_log_path(pid):
    for fd in ("1", "2"):
        try:
            target = Path(os.readlink(f"/proc/{pid}/fd/{fd}"))
            if target.is_file():
                return target
        except OSError:
            pass
    return None


def port_open(port):
    with socket.socket() as sock:
        sock.settimeout(0.5)
        return sock.connect_ex(("127.0.0.1", port)) == 0

def get_json(url, timeout=8):
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        if response.status != 200:
            raise RuntimeError(f"HTTP_{response.status}")
        if not response.geturl().startswith("https://") and not url.startswith("http://127.0.0.1"):
            raise RuntimeError("TRANSPORTE_NO_HTTPS")
        raw = response.read(65537)
        if len(raw) > 65536:
            raise RuntimeError("RESPUESTA_DEMASIADO_GRANDE")
        obj = json.loads(raw)
        if not isinstance(obj, dict):
            raise RuntimeError("IDENTITY_NO_ES_OBJETO")
        return obj

def launch(command, pidfile, logfile, marker):
    existing = process_matches(pidfile, marker)
    if existing:
        print(f"PROCESO_EXISTENTE pid={existing} marcador={marker}")
        return existing

    logfile.parent.mkdir(parents=True, exist_ok=True)
    with logfile.open("ab") as out:
        proc = subprocess.Popen(
            command, cwd=ROOT, stdin=subprocess.DEVNULL,
            stdout=out, stderr=subprocess.STDOUT,
            start_new_session=True, close_fds=True
        )
    atomic_json(pidfile, {"pid": proc.pid, "started_at": now()})
    # PID file stores JSON; process_matches accepts both formats below.
    return proc.pid

def write_pid(path, pid):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(str(pid) + "\n")
    os.replace(tmp, path)

def start_process(command, pidfile, logfile, marker):
    existing = process_matches(pidfile, marker)
    if existing:
        print(f"YA_ACTIVO pid={existing}: {marker}")
        return existing
    if pidfile.exists():
        pidfile.unlink()
    logfile.parent.mkdir(parents=True, exist_ok=True)
    with logfile.open("ab") as out:
        proc = subprocess.Popen(
            command, cwd=ROOT, stdin=subprocess.DEVNULL,
            stdout=out, stderr=subprocess.STDOUT,
            start_new_session=True, close_fds=True
        )
    write_pid(pidfile, proc.pid)
    return proc.pid

def status():
    fed = process_matches(FED_PID, "iao_fedserver_public.py") or find_fedserver_process()
    cf = process_matches(CF_PID, "cloudflared tunnel") or find_cloudflared_process()
    print(f"FEDSERVER_PID={fed or 'NO_VERIFICADO'}")
    print(f"CLOUDFLARED_PID={cf or 'NO_VERIFICADO'}")
    print(f"LOCAL_PORT_8443={'OCUPADO' if port_open(8443) else 'LIBRE'}")
    try:
        identity = get_json(LOCAL_URL)
        print("LOCAL_IDENTITY=HTTP_200_JSON")
        print("LOCAL_NODE_ID=" + str(identity.get("node_id", "NO_PUBLICADO")))
    except Exception as exc:
        print(f"LOCAL_IDENTITY=ERROR:{type(exc).__name__}:{exc}")
    if PUBLICATION.exists():
        try:
            data = json.loads(PUBLICATION.read_text())
            print("PUBLICATION_FILE=EXISTS")
            print("PUBLICATION_URL=" + str(data.get("url", "NO_URL")))
            print("PUBLICATION_VERIFIED=" + str(data.get("https_identity_verified", False)))
        except Exception:
            print("PUBLICATION_FILE=INVALID")
    else:
        print("PUBLICATION_FILE=NOT_CREATED")

def start():
    STATE.mkdir(parents=True, exist_ok=True)
    PID_DIR.mkdir(parents=True, exist_ok=True)

    if not (ROOT / "tools/iao_fedserver_public.py").is_file():
        raise RuntimeError("FALTA tools/iao_fedserver_public.py")
    if not (ROOT / ".state/federation/identity/private.pem").is_file():
        raise RuntimeError("FALTA CLAVE DE IDENTIDAD; NO SE GENERA NI MODIFICA")
    if not shutil.which("cloudflared"):
        raise RuntimeError("CLOUDFLARED_NO_INSTALADO")

    fed_pid = process_matches(FED_PID, "iao_fedserver_public.py")
    if not fed_pid:
        fed_pid = find_fedserver_process()
    fed_was_existing = bool(fed_pid)

    if not fed_pid and port_open(8443):
        raise RuntimeError("PUERTO_8443_OCUPADO_POR_PROCESO_NO_GESTIONADO; NO SE TOCA")

    if not fed_pid:
        if FED_PID.exists():
            backup_pidfile(FED_PID)
        fed_pid = start_process(
            [sys.executable, "tools/iao_fedserver_public.py", "--host", "127.0.0.1", "--port", "8443"],
            FED_PID, FED_LOG, "iao_fedserver_public.py"
        )
        print(f"FEDSERVER_LAUNCH_PID={fed_pid}")

    identity = None
    for _ in range(20):
        try:
            identity = get_json(LOCAL_URL)
            break
        except Exception:
            time.sleep(1)
    if identity is None:
        raise RuntimeError("FEDSERVER_NO_SUPERA_IDENTIDAD_LOCAL; revisar " + str(FED_LOG))

    if not identity_matches_private_key(identity):
        raise RuntimeError("IDENTIDAD_LOCAL_NO_COINCIDE_CON_CLAVE_PERSISTENTE")

    if fed_was_existing:
        adopt_pidfile(FED_PID, fed_pid)

    cf_pid = process_matches(CF_PID, "cloudflared tunnel")
    if not cf_pid:
        cf_pid = find_cloudflared_process()
    cf_was_existing = bool(cf_pid)

    if cf_pid:
        adopt_pidfile(CF_PID, cf_pid)

    if not cf_pid:
        if CF_PID.exists():
            backup_pidfile(CF_PID)
        cf_pid = start_process(
            ["cloudflared", "tunnel", "--no-autoupdate", "--url", "http://127.0.0.1:8443"],
            CF_PID, CF_LOG, "cloudflared tunnel"
        )
        print(f"CLOUDFLARED_LAUNCH_PID={cf_pid}")

    tunnel_url = None
    active_log = process_log_path(cf_pid)
    if cf_was_existing and active_log is None:
        raise RuntimeError(
            "TUNEL_EXISTENTE_ADOPTADO_PERO_LOG_NO_ACCESIBLE; "
            "NO_SE_USARA_URL_HISTORICA_NI_SE_INICIARA_OTRO_TUNEL"
        )
    selected_log = active_log if active_log is not None else CF_LOG

    for _ in range(35):
        if process_matches(CF_PID, "cloudflared tunnel") is None:
            raise RuntimeError("CLOUDFLARED_TERMINO; revisar " + str(selected_log))
        try:
            contents = selected_log.read_text(errors="replace")
            matches = URL_PATTERN.findall(contents)
            if matches:
                tunnel_url = matches[-1]
                break
        except OSError:
            pass
        time.sleep(1)

    if not tunnel_url:
        raise RuntimeError("NO_SE_OBTUVO_URL_PUBLICA; revisar " + str(CF_LOG))

    # Comprobación externa HTTPS real: no basta con extraer la URL del log.
    remote_identity = None
    last_error = None
    for _ in range(8):
        try:
            remote_identity = get_json(tunnel_url + "/fed/v1/identity", timeout=12)
            break
        except Exception as exc:
            last_error = f"{type(exc).__name__}:{exc}"
            time.sleep(2)

    if remote_identity is None:
        raise RuntimeError("IDENTIDAD_EXTERNA_NO_VERIFICADA:" + str(last_error))

    local_id = identity.get("node_id")
    remote_id = remote_identity.get("node_id")
    if local_id and remote_id and local_id != remote_id:
        raise RuntimeError("IDENTIDAD_LOCAL_Y_EXTERNA_DIFIEREN")

    # No modificar iao-external-nodes.json ni conceder autorizaciones.
    record = {
        "protocol": "iao-local-publication",
        "version": 1,
        "url": tunnel_url,
        "local_node_id": local_id,
        "remote_node_id": remote_id,
        "https_identity_verified": True,
        "verification": "HTTPS_GET_IDENTITY_ONLY",
        "challenge": "NOT_TESTED",
        "enrollment": "NOT_PERFORMED",
        "capability_exchange": "NOT_PERFORMED",
        "updated_at": now(),
        "fedserver_pid": fed_pid,
        "cloudflared_pid": cf_pid
    }
    if PUBLICATION.exists():
        backup = PUBLICATION.with_name("publication.before-" +
                  datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".bak")
        shutil.copy2(PUBLICATION, backup)
        print("PUBLICATION_BACKUP=" + str(backup))
    atomic_json(PUBLICATION, record)

    print("PUBLICATION=" + str(PUBLICATION))
    print("PUBLIC_URL=" + tunnel_url)
    print("HTTPS_IDENTITY=VERIFIED")
    print("CHALLENGE=NOT_TESTED")
    print("ENROLLMENT=NOT_PERFORMED")
    print("PEER_CONFIG=UNCHANGED")
    print("WATCH_PIPELINE=NOT_STARTED")

if __name__ == "__main__":
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in ("status", "start"):
            print("Uso: python3 tools/iao_federation_connectivity.py status|start")
            sys.exit(2)
        if sys.argv[1] == "status":
            status()
        else:
            start()
    except Exception as exc:
        print(f"ERROR={type(exc).__name__}:{exc}", file=sys.stderr)
        sys.exit(1)
