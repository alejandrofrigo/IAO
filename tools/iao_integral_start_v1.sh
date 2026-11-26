#!/data/data/com.termux/files/usr/bin/bash
set -Eeuo pipefail

ROOT="$HOME/so-omega-prime"
cd "$ROOT"

STATE="$ROOT/.state/integral-boot"
LOG="$STATE/logs/integral-start.log"
LOCK="$STATE/integral-start.lock"

mkdir -p "$STATE/logs"
exec > >(tee -a "$LOG") 2>&1

echo
echo "================================================"
echo " IAO — ARRANQUE INTEGRAL"
echo " $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "================================================"

if ! command -v flock >/dev/null 2>&1; then
    echo "ERROR: falta flock; no se inicia para evitar duplicados."
    exit 1
fi

exec 9>"$LOCK"
if ! flock -n 9; then
    echo "ARRANQUE_OMITIDO: otro lanzador está trabajando."
    exit 0
fi

has_proc() {
    pgrep -f "$1" >/dev/null 2>&1
}

show_proc() {
    local label="$1" pattern="$2"
    echo
    echo "--- $label ---"
    if pgrep -af "$pattern"; then
        :
    else
        echo "NO_DETECTADO"
    fi
}

start_if_missing() {
    local label="$1" pattern="$2"
    shift 2
    if has_proc "$pattern"; then
        echo "CONSERVADO: $label ya está activo."
    else
        echo "INICIANDO: $label"
        nohup "$@" >> "$LOG" 2>&1 </dev/null &
        echo "PID_LANZADO=$!"
    fi
}

echo
echo "FASE 1 — NÚCLEO Y SUPERVISIÓN"

if [ ! -f tools/iao_integral_runtime.py ]; then
    echo "ERROR: falta tools/iao_integral_runtime.py"
    exit 1
fi

start_if_missing \
    "Runtime integral" \
    'tools/iao_integral_runtime\.py' \
    python -u tools/iao_integral_runtime.py

sleep 5

start_if_missing \
    "Supervisor principal" \
    '[p]ython.*-m omega\.supervisor' \
    python -u -m omega.supervisor

sleep 5

echo
echo "FASE 2 — PADGE"

PADGE_PATTERN='-m omega\.padge loop|iao_padge_loop_entry\.py'

if has_proc "$PADGE_PATTERN"; then
    echo "CONSERVADO: PADGE ya tiene proceso activo."
else
    if grep -q 'PADGE_SINGLETON_LOCK_V1' omega/padge.py; then
        echo "INICIANDO PADGE con protección singleton instalada."
        nohup python -u -m omega.padge loop >> "$LOG" 2>&1 </dev/null &
        echo "PADGE_PID_LANZADO=$!"
    else
        echo "PADGE_NO_INICIADO: no se encontró el parche singleton."
    fi
fi

sleep 8

echo
echo "FASE 3 — VALIDACIÓN DE PROCESOS"

show_proc "Runtime integral" 'tools/iao_integral_runtime\.py'
show_proc "Supervisor IAO" '[p]ython.*-m omega\.supervisor'
show_proc "Servidor IAO" '[p]ython.*omega\.server'
show_proc "PADGE" "$PADGE_PATTERN"
show_proc "Supervisor de workers" 'iao_autonomous_worker_supervisor'
show_proc "Worker autónomo" 'iao_autonomous_worker'
show_proc "Federación" 'federation_public_node|federation.*worker'
show_proc "Guardian" 'iao.*guardian|guardian.*iao'
show_proc "Continuidad" 'iao_continuity_core|continuity-core'

echo
echo "FASE 4 — SALUD HTTP REAL"

python - <<'PY'
import json
import urllib.error
import urllib.request

for port in (8080, 8765):
    for path in ("/health/live", "/health/ready"):
        url = f"http://127.0.0.1:{port}{path}"
        try:
            with urllib.request.urlopen(url, timeout=4) as response:
                body = response.read(2500).decode("utf-8", "replace")
                try:
                    body = json.dumps(json.loads(body), ensure_ascii=False)
                except Exception:
                    pass
                print(f"HTTP {response.status} {url}")
                print(body)
        except urllib.error.HTTPError as exc:
            body = exc.read(1500).decode("utf-8", "replace")
            print(f"HTTP {exc.code} {url}")
            print(body)
        except Exception as exc:
            print(f"NO_DISPONIBLE {url}: {type(exc).__name__}: {exc}")
PY

echo
echo "FASE 5 — VALIDACIÓN DEL PARCHE Y CÓDIGO"

bash -n tools/iao_integral_start_v1.sh
python -m py_compile \
    omega/padge.py \
    omega/store.py \
    omega/service.py \
    tools/iao_integral_runtime.py

echo "SINTAXIS_BASH=PASS"
echo "PY_COMPILE=PASS"

echo
echo "================================================"
echo "ARRANQUE_INTEGRAL_FINALIZADO"
echo "REGISTRO=$LOG"
echo "================================================"
