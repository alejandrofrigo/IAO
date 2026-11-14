#!/data/data/com.termux/files/usr/bin/bash
set -u

ROOT="$HOME/so-omega-prime"
SUP="$ROOT/tools/iao_padge_supervisor.sh"
cd "$ROOT" || exit 1

ENTRY="tools/iao_padge_loop_entry.py"
BASE=".state/padge"
PIDFILE="$BASE/supervisor.pid"
CHILD="$BASE/padge.pid"
LOG="$BASE/logs/padge-supervisor.log"
PADGELOG="$BASE/logs/padge-autonomia.log"

mkdir -p "$BASE/logs"

alive() {
    local p="${1:-}"
    local needle="$2"
    [ -n "$p" ] || return 1
    kill -0 "$p" 2>/dev/null || return 1
    [ -r "/proc/$p/cmdline" ] || return 1
    tr '\000' ' ' < "/proc/$p/cmdline" |
        grep -Fq "$needle"
}

find_padge_pid() {
    pgrep -f '[i]ao_padge_loop_entry.py|[o]mega\.padge loop' 2>/dev/null | head -n 1
}

padge_alive() {
    local p
    p="$(find_padge_pid)"
    [ -n "$p" ] || return 1
    echo "$p" > "$CHILD"
    return 0
}

supervisor_alive() {
    alive "$(cat "$PIDFILE" 2>/dev/null || true)" "$SUP"
}

case "${1:-status}" in

run)
    echo "$$" > "$PIDFILE"
    trap 'STOP=1' TERM INT
    STOP=0
    LAST_START=0

    echo "$(date -Is) SUPERVISOR_STARTED pid=$$" >> "$LOG"

    while [ "$STOP" -eq 0 ]; do
        if ! padge_alive; then
            NOW="$(date +%s)"
            if [ $((NOW-LAST_START)) -ge 30 ]; then
                rm -f "$CHILD"
                echo "$(date -Is) PADGE_START_REQUEST" >> "$LOG"

                nohup python -u "$ENTRY" >> "$PADGELOG" 2>&1 </dev/null &
                P=$!
                echo "$P" > "$CHILD"
                LAST_START="$NOW"

                sleep 4

                if padge_alive; then
                    echo "$(date -Is) PADGE_RUNNING pid=$P" >> "$LOG"
                else
                    echo "$(date -Is) PADGE_START_NOT_CONFIRMED pid=$P" >> "$LOG"
                    rm -f "$CHILD"
                fi
            fi
        fi

        sleep 15 &
        wait $! || true
    done

    echo "$(date -Is) SUPERVISOR_STOPPED" >> "$LOG"
    rm -f "$PIDFILE"
    ;;

start)
    if supervisor_alive; then
        echo "SUPERVISOR_ALREADY_ACTIVE"
        echo "PID=$(cat "$PIDFILE")"
        exit 0
    fi

    # No adoptar ni duplicar un proceso PADGE desconocido
    EXISTING="$(find_padge_pid)"
    if [ -n "$EXISTING" ]; then
        echo "PADGE_EXISTENTE_DETECTADO:"
        echo "$EXISTING"
        echo "No se iniciará una segunda instancia."
        exit 1
    fi

    nohup bash "$SUP" run >> "$LOG" 2>&1 </dev/null &
    P=$!

    sleep 3

    if alive "$P" "$SUP"; then
        echo "SUPERVISOR_STARTED pid=$P"
    else
        echo "ERROR: supervisor no confirmado."
        tail -n 30 "$LOG" 2>/dev/null || true
        exit 1
    fi
    ;;

status)
    echo "=== SUPERVISOR ==="
    if supervisor_alive; then
        echo "ACTIVO PID=$(cat "$PIDFILE")"
    else
        echo "NO CONFIRMADO"
    fi

    echo
    echo "=== PADGE ==="
    if padge_alive; then
        echo "ACTIVO PID=$(cat "$CHILD")"
    else
        echo "NO CONFIRMADO"
    fi

    echo
    echo "=== ACTIVIDAD ==="
    tail -n 20 "$LOG" 2>/dev/null || true
    echo
    tail -n 25 "$PADGELOG" 2>/dev/null || true
    ;;

stop)
    SP="$(cat "$PIDFILE" 2>/dev/null || true)"
    CP="$(cat "$CHILD" 2>/dev/null || true)"

    if alive "$SP" "$SUP"; then
        kill -TERM "$SP"
        echo "Parada solicitada al supervisor."
    fi

    if alive "$CP" "$ENTRY"; then
        kill -TERM "$CP"
        echo "Parada solicitada a PADGE."
    fi

    sleep 2
    echo "Comprueba el estado con: bash $SUP status"
    ;;

*)
    echo "Uso: bash $SUP {start|status|stop}"
    exit 2
    ;;
esac
