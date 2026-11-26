#!/usr/bin/env python3
"""Bootstrap seguro del servidor federativo local de IAO."""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
HOST = "127.0.0.1"
PORT = 8443
BASE = f"http://{HOST}:{PORT}"
SERVER = ROOT / "tools/iao_fedserver_public.py"
STATE = ROOT / ".state"
LOG = STATE / "logs/federation-public-node.log"
PIDFILE = STATE / "iao-fedserver-local.pid"

def probe():
    try:
        req = urllib.request.Request(
            BASE + "/fed/v1/identity",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=4) as response:
            if response.status != 200:
                return None
            data = json.loads(response.read(65536))
            return data if isinstance(data, dict) else None
    except Exception:
        return None

def port_open():
    with socket.socket() as sock:
        sock.settimeout(1)
        return sock.connect_ex((HOST, PORT)) == 0

def main():
    STATE.mkdir(exist_ok=True)
    LOG.parent.mkdir(parents=True, exist_ok=True)

    if not SERVER.is_file():
        print("ERROR: falta tools/iao_fedserver_public.py")
        return 2

    identity_file = STATE / "federation/identity/private.pem"
    if not identity_file.is_file():
        print("ERROR: no existe la identidad privada federativa.")
        print("No se generará otra identidad ni se sustituirán claves.")
        return 3

    current = probe()
    if current is not None:
        node_id = current.get("node_id", "NO_PUBLICADO")
        print("FEDSERVER=YA_ACTIVO_Y_COMPATIBLE")
        print("NODE_ID=" + str(node_id))
        print("IDENTITY_FIELDS=" + ",".join(sorted(current.keys())))
        print("ENDPOINT_LOCAL=" + BASE + "/fed/v1/identity")
        return 0

    if port_open():
        print("ERROR: el puerto 8443 está ocupado por un servicio no identificado.")
        print("No se detuvo ni modificó ningún proceso.")
        return 4

    command = [
        sys.executable, str(SERVER),
        "--host", HOST, "--port", str(PORT),
    ]

    with LOG.open("ab", buffering=0) as output:
        process = subprocess.Popen(
            command,
            cwd=str(ROOT),
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            close_fds=True,
        )

    PIDFILE.write_text(str(process.pid) + "\n", encoding="utf-8")
    print(f"FEDSERVER_LAUNCH_PID={process.pid}")

    for attempt in range(20):
        time.sleep(1)
        if process.poll() is not None:
            print("ERROR: FedServer terminó durante el arranque.")
            print("LOG=" + str(LOG))
            return 5
        data = probe()
        if data is not None:
            node_id = data.get("node_id")
            if not isinstance(node_id, str) or not node_id:
                print("ERROR: identidad HTTP sin node_id válido.")
                return 6
            print("FEDSERVER=RUNNING")
            print("IDENTITY_ENDPOINT=HTTP_200")
            print("NODE_ID=" + node_id)
            print("IDENTITY_FIELDS=" + ",".join(sorted(data.keys())))
            print("BIND=127.0.0.1:8443")
            print("PUBLIC_TLS=NOT_CONFIGURED")
            print("REMOTE_PEERS=NOT_YET_CONNECTED")
            print("LOG=" + str(LOG))
            return 0

    print("ERROR: no se pudo verificar /fed/v1/identity.")
    print("LOG=" + str(LOG))
    return 7

if __name__ == "__main__":
    try:
        result = main()
    except Exception as exc:
        print("BOOTSTRAP_ERROR=" + type(exc).__name__ + ": " + str(exc))
        result = 10
    print("BOOTSTRAP_EXIT=" + str(result))
