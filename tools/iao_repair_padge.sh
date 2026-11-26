#!/data/data/com.termux/files/usr/bin/bash
# Reparacion de PADGE bajo el supervisor (causa: ModuleNotFoundError: No module named 'omega').
# Uso, desde la raiz del repo:  bash tools/iao_repair_padge.sh
# No toca policy.py, no borra datos, no usa kill -9. Para si algo no cuadra.
set -u
cd "$(dirname "$0")/.." || exit 1
ROOT="$PWD"
STATE=".state/iao-five-motors"
ENTRY="tools/iao_padge_loop_entry.py"
SUP="tools/iao_five_motor_supervisor.py"

[ -f "$ENTRY" ] && [ -f "$SUP" ] || { echo "ABORTA: faltan $ENTRY o $SUP"; exit 1; }
command -v termux-wake-lock >/dev/null 2>&1 && termux-wake-lock

echo "== 1/5 Parche de ruta de importacion (idempotente, con copia .bak)"
python - "$ENTRY" <<'PY' || { echo "ABORTA: fallo el parche"; exit 1; }
import ast, shutil, sys
p = sys.argv[1]
src = open(p, encoding="utf-8").read()
if "IAO_ROOT_PATH_FIX" in src:
    print("YA_PARCHEADO")
    sys.exit(0)
shutil.copy(p, p + ".bak")
fix = ("import os as _os, sys as _sys  # IAO_ROOT_PATH_FIX\n"
       "_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))  # IAO_ROOT_PATH_FIX\n")
lines = src.splitlines(keepends=True)
head = lines[0] if lines and lines[0].startswith("#!") else ""
body = src[len(head):]
new = head + fix + body
ast.parse(new)  # no escribe si la sintaxis queda rota
open(p, "w", encoding="utf-8").write(new)
print("PARCHEADO (copia en %s.bak)" % p)
PY

echo "== 2/5 Parar el PADGE suelto (el que lanzaste aparte), con TERM"
PID_FILE="$STATE/padge-standalone.pid"
if [ -f "$PID_FILE" ]; then
  OLD="$(tr -d ' \n' < "$PID_FILE")"
  if [ -n "$OLD" ] && kill -0 "$OLD" 2>/dev/null; then
    kill -TERM "$OLD"
    for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$OLD" 2>/dev/null || break; sleep 1; done
    if kill -0 "$OLD" 2>/dev/null; then
      echo "ABORTA: PID $OLD no termino con TERM. Revisalo a mano."; exit 1
    fi
    echo "PADGE suelto $OLD detenido"
  else
    echo "PADGE suelto no estaba vivo"
  fi
else
  echo "Sin $PID_FILE; sigo"
fi

echo "== 3/5 Parar el supervisor (detiene sus motores; AUTONOMY_CONTINUOUS no depende de el)"
python "$SUP" stop || { echo "ABORTA: 'stop' fallo; no reinicio nada. Revisa $SUP"; exit 1; }
sleep 3

echo "== 4/5 Arrancar el supervisor con PYTHONPATH apuntando a la raiz"
PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" nohup python "$SUP" start \
  >> "$STATE/logs/supervisor-restart.log" 2>&1 &
sleep 20

echo "== 5/5 Verificacion de latido"
python tools/iao_health_check.py
RC=$?
echo
echo "PADGE desde supervisor:"
tail -n 5 "$STATE/logs/supervisor.log" 2>/dev/null
if grep -q "motor_exited.*PADGE" "$STATE/logs/supervisor.log" 2>/dev/null; then
  echo "AVISO: mira si 'motor_exited' de PADGE es reciente; si lo es, sigue fallando."
fi
echo "Para volver al modo suelto:  PYTHONPATH=\"$ROOT\" nohup python $ENTRY > $STATE/logs/padge-standalone-manual.log 2>&1 &"
exit $RC
