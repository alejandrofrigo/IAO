#!/data/data/com.termux/files/usr/bin/bash

set +e

BASE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$BASE" || exit 1

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
STATE="$BASE/.state/iao-activation"
LOGS="$STATE/logs"
REPORT="$STATE/ACTIVACION-EJECUCION-$STAMP.txt"

mkdir -p "$LOGS"

exec > >(tee -a "$REPORT") 2>&1

echo "=================================================="
echo "IAO — ACTIVACIÓN OPERATIVA INTEGRAL"
echo "=================================================="
echo "UTC=$(date -u +%FT%TZ)"
echo "BASE=$BASE"
echo "MODO=ACTIVACION_CON_SEGURIDAD_Y_SIN_DUPLICADOS"
echo

start_once() {
    LABEL="$1"
    PATTERN="$2"
    shift 2

    echo "===== $LABEL ====="

    if pgrep -f "$PATTERN" >/dev/null 2>&1; then
        echo "RESULTADO=YA_ACTIVO"
        pgrep -af "$PATTERN" 2>/dev/null | head -3
        return
    fi

    nohup "$@" >> "$LOGS/$LABEL.log" 2>&1 </dev/null &
    PID=$!
    sleep 2

    if kill -0 "$PID" 2>/dev/null; then
        echo "RESULTADO=INICIADO"
        echo "PID=$PID"
    else
        echo "RESULTADO=INICIO_NO_CONFIRMADO"
        echo "LOG=$LOGS/$LABEL.log"
    fi
}

echo "===== 1. MOTORES Y SUPERVISIÓN ====="

start_once "five_motor_supervisor" \
    '[t]ools/iao_five_motor_supervisor.py start' \
    python -u tools/iao_five_motor_supervisor.py start

start_once "internet_guardian" \
    '[t]ools/iao_internet_guardian.py' \
    python -u tools/iao_internet_guardian.py

echo
echo "===== 2. PADGE Y AUTONOMÍA ====="

start_once "padge_loop" \
    '[t]ools/iao_padge_loop_entry.py' \
    python -u tools/iao_padge_loop_entry.py

start_once "autonomous_worker_supervisor" \
    '[-]m tools.iao_autonomous_worker_supervisor' \
    python -u -m tools.iao_autonomous_worker_supervisor

start_once "autonomous_worker" \
    '[-]m tools\.iao_autonomous_worker$' \
    python -u -m tools.iao_autonomous_worker

start_once "autonomy_daemon" \
    '[t]ools/iao_autonomy_daemon.py' \
    python -u tools/iao_autonomy_daemon.py

start_once "autonomy_watch" \
    '[t]ools/iao_autonomy.py --watch' \
    python -u tools/iao_autonomy.py --watch

echo
echo "===== 3. RED EXTERNA Y FEDERACIÓN ====="

start_once "node_network_engine" \
    '[t]ools/iao_node_network_engine.py serve' \
    python -u tools/iao_node_network_engine.py serve

start_once "federation_worker" \
    '[t]ools/iao_federation_worker.py' \
    python -u tools/iao_federation_worker.py

start_once "external_node_agent" \
    '[t]ools/iao_external_node_agent.py --watch' \
    python -u tools/iao_external_node_agent.py --watch

start_once "federation_control" \
    '[t]ools/iao_federation_control.py watch' \
    python -u tools/iao_federation_control.py watch

echo
echo "===== 4. SERVIDOR PRINCIPAL ====="

start_once "omega_supervisor" \
    '[-]m omega.supervisor' \
    python -u -m omega.supervisor

echo
echo "===== 5. CICLO DEL CONTROL PLANE ====="

if [ -f tools/iao_control_plane.py ]; then
    echo "EJECUTANDO=python tools/iao_control_plane.py --once"
    python tools/iao_control_plane.py --once
    echo "CONTROL_PLANE_EXIT=$?"
else
    echo "CONTROL_PLANE=ARCHIVO_NO_ENCONTRADO"
fi

echo
echo "===== 6. VALIDACIÓN DE COMPILACIÓN ====="

python -m compileall -q omega tools
echo "COMPILEALL_EXIT=$?"

echo
echo "===== 7. COMPROBACIÓN HTTP ====="

python - <<'PY'
import json
import urllib.error
import urllib.request

for path in ("/health/live", "/health/ready"):
    url = "http://127.0.0.1:8080" + path
    print(f"\nENDPOINT={path}")
    try:
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=8) as response:
            body = response.read(12000).decode("utf-8", "replace")
            print("HTTP_STATUS=", response.status)
            try:
                data = json.loads(body)
                print("JSON_STATUS=", data.get("status"))
                print("CHECKS=", json.dumps(
                    data.get("checks", {}),
                    ensure_ascii=False,
                ))
            except Exception:
                print("BODY=", body[:1000])
    except urllib.error.HTTPError as exc:
        print("HTTP_STATUS=", exc.code)
        print("BODY=", exc.read(3000).decode("utf-8", "replace"))
    except Exception as exc:
        print("HTTP_ERROR=", type(exc).__name__, str(exc))
PY

echo
echo "===== 8. ESTADO DE PROCESOS IAO ====="

for PATTERN in \
    '[t]ools/iao_five_motor_supervisor.py' \
    '[t]ools/iao_padge_loop_entry.py' \
    '[t]ools/iao_internet_guardian.py' \
    '[t]ools/iao_node_network_engine.py' \
    '[t]ools/iao_federation_worker.py' \
    '[t]ools/iao_external_node_agent.py' \
    '[t]ools/iao_federation_control.py' \
    '[-]m tools.iao_autonomous_worker_supervisor' \
    '[-]m tools\.iao_autonomous_worker$' \
    '[t]ools/iao_autonomy_daemon.py' \
    '[t]ools/iao_autonomy.py --watch' \
    '[-]m omega.supervisor' \
    '[o]mega.server'
do
    COUNT="$(pgrep -fc "$PATTERN" 2>/dev/null)"
    echo "PROCESOS=$COUNT PATRON=$PATTERN"
done

echo
echo "===== 9. POLÍTICA DE ADMISIÓN EXTERNA ====="

python - <<'PY'
import json
from pathlib import Path

paths = [
    Path(".state/iao-node-network/federation-policy.json"),
    Path(".state/iao-node-network/agent-config.json"),
    Path(".state/iao-node-network/authorized-peers.json"),
]

for path in paths:
    print(f"\nARCHIVO={path}")
    if not path.exists():
        print("ESTADO=NO_EXISTE")
        continue
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if path.name == "federation-policy.json":
            for key in (
                "enabled",
                "automatic_admission",
                "automatic_revalidation",
                "require_trusted_directory_signature",
                "require_mtls",
                "max_nodes",
                "allowed_capabilities",
                "remote_code_execution",
                "remote_policy_changes",
                "remote_security_administration",
            ):
                print(f"{key}={data.get(key)}")
            print("DIRECTORIOS_CONFIABLES=",
                  len(data.get("directories", [])))
        elif path.name == "authorized-peers.json":
            print("NODOS_AUTORIZADOS=",
                  len(data.get("authorized_peers", [])))
        else:
            print("CONFIGURACION=CARGADA")
            print("DIRECTORIOS_CONFIGURADOS=",
                  len(data.get("directories", [])))
    except Exception as exc:
        print("ERROR_CONFIGURACION=", repr(exc))
PY

echo
echo "===== 10. RESULTADO ====="
echo "ACTIVATION_FINISHED=YES"
echo "REPORT=$REPORT"
echo "LOGS=$LOGS"
echo "UTC=$(date -u +%FT%TZ)"
