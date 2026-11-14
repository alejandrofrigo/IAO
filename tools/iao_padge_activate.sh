#!/data/data/com.termux/files/usr/bin/bash
set -eu

ROOT="$HOME/so-omega-prime"
cd "$ROOT"

ENTRY="tools/iao_padge_loop_entry.py"
PIDFILE=".state/padge/padge.pid"
LOG=".state/padge/logs/padge-autonomia-total.log"

mkdir -p .state/padge/logs

valid_pid() {
    local p="${1:-}"
    [ -n "$p" ] || return 1
    kill -0 "$p" 2>/dev/null || return 1
    [ -r "/proc/$p/cmdline" ] || return 1
    tr '\000' ' ' < "/proc/$p/cmdline" |
        grep -Fq "$ENTRY"
}

case "${1:-status}" in

start)
    if [ -f "$PIDFILE" ]; then
        PID="$(cat "$PIDFILE" 2>/dev/null || true)"
        if valid_pid "$PID"; then
            echo "PADGE YA ACTIVO. PID=$PID"
            exit 0
        fi
        rm -f "$PIDFILE"
    fi

    EXISTING="$(pgrep -f '[i]ao_padge_loop_entry.py' || true)"
    if [ -n "$EXISTING" ]; then
        echo "Se detectó PADGE sin PID registrado:"
        echo "$EXISTING"
        echo "No se creará otra instancia."
        exit 1
    fi

    if command -v termux-wake-lock >/dev/null 2>&1; then
        termux-wake-lock || true
        echo "Solicitud de bloqueo de suspensión realizada."
    else
        echo "AVISO: termux-wake-lock no está disponible."
    fi

    echo "Iniciando PADGE continuo..."
    nohup python -u "$ENTRY" >> "$LOG" 2>&1 </dev/null &
    PID=$!
    echo "$PID" > "$PIDFILE"

    sleep 3

    if valid_pid "$PID"; then
        echo "PADGE_AUTONOMO=ACTIVO"
        echo "PID=$PID"
        echo "LOG=$LOG"
    else
        rm -f "$PIDFILE"
        echo "ERROR: PADGE no permaneció activo."
        tail -n 50 "$LOG" 2>/dev/null || true
        exit 1
    fi
    ;;

status)
    PID="$(cat "$PIDFILE" 2>/dev/null || true)"
    if valid_pid "$PID"; then
        echo "PADGE=ACTIVO"
        echo "PID=$PID"
    else
        echo "PADGE=NO_CONFIRMADO"
        pgrep -af '[i]ao_padge_loop_entry.py' || true
    fi
    echo "LOG=$LOG"
    echo "ULTIMA ACTIVIDAD:"
    tail -n 30 "$LOG" 2>/dev/null || true
    ;;

stop)
    PID="$(cat "$PIDFILE" 2>/dev/null || true)"
    if valid_pid "$PID"; then
        kill -TERM "$PID"
        echo "Señal de parada enviada a PADGE: $PID"
        echo "Comprueba su salida con status."
    else
        echo "No se confirmó un proceso PADGE asociado."
    fi
    ;;

*)
    echo "Uso: $0 {start|status|stop}"
    exit 2
    ;;
esac
