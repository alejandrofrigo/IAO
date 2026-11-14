#!/data/data/com.termux/files/usr/bin/bash

cd "$HOME/so-omega-prime" || exit 1

set +e
export PYTHONUNBUFFERED=1
umask 077

STATE="$HOME/so-omega-prime/.state/padge"
LOG="$STATE/continuous-worker.log"
PIDFILE="$STATE/continuous-worker.pid"
LOCK="$STATE/continuous-worker.lock"

mkdir -p "$STATE"

case "${1:-status}" in

run)
    if mkdir "$LOCK" 2>/dev/null; then
        echo "$BASHPID" > "$PIDFILE"
    else
        echo "PADGE ya tiene un supervisor activo."
        exit 1
    fi

    cleanup() {
        rm -f "$PIDFILE"
        rmdir "$LOCK" 2>/dev/null
    }

    trap cleanup EXIT INT TERM

    echo "IAO PADGE CONTINUOUS START $(date -Iseconds)" >> "$LOG"

    CYCLE=0

    while true; do
        CYCLE=$((CYCLE + 1))

        {
            echo
            echo "======================================"
            echo "CICLO: $CYCLE"
            echo "FECHA: $(date -Iseconds)"
            echo "======================================"

            if python -m omega.padge once; then
                echo "RESULTADO: CICLO EJECUTADO"
            else
                echo "RESULTADO: ERROR EN CICLO"
            fi

            echo "SIGUIENTE CICLO: 900 segundos"
        } >> "$LOG" 2>&1

        sleep 900
    done
    ;;

status)
    if [ -f "$PIDFILE" ] &&
       kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        echo "SUPERVISOR: ACTIVO"
        echo "PID: $(cat "$PIDFILE")"
    else
        echo "SUPERVISOR: DETENIDO"
    fi

    echo
    tail -35 "$LOG" 2>/dev/null
    ;;

stop)
    if [ -f "$PIDFILE" ]; then
        PID="$(cat "$PIDFILE")"
        if kill -0 "$PID" 2>/dev/null; then
            kill "$PID"
            echo "SOLICITUD DE DETENCION ENVIADA"
        else
            echo "EL PROCESO YA NO EXISTE"
        fi
    else
        echo "NO HAY PID REGISTRADO"
    fi
    ;;

*)
    echo "Uso: $0 run|status|stop"
    exit 2
    ;;
esac
