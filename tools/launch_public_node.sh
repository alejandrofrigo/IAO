#!/data/data/com.termux/files/usr/bin/bash
# Lanza el daemon del nodo público como proceso desacoplado del shell.
# Uso: bash tools/launch_public_node.sh a
#      bash tools/launch_public_node.sh c
set -euo pipefail
NODE="${1:-}"
if [ "$NODE" != "a" ] && [ "$NODE" != "c" ]; then
    echo "Uso: $0 {a|c}"
    exit 2
fi
cd "$(dirname "$0")/.."
PIDFILE=".state/iao-node-network/daemon-${NODE}.pid"
LOGFILE=".state/iao-node-network/daemon-${NODE}.log"
mkdir -p .state/iao-node-network
if [ -f "$PIDFILE" ]; then
    OLD_PID=$(cat "$PIDFILE" 2>/dev/null || echo "")
    if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
        echo "DAEMON_${NODE}_ALREADY_RUNNING pid=$OLD_PID"
        exit 0
    fi
    rm -f "$PIDFILE"
fi
nohup setsid python3 tools/iao_public_node_daemon.py --node "$NODE" \
    > "$LOGFILE" 2>&1 < /dev/null &
NEW_PID=$!
echo "$NEW_PID" > "$PIDFILE"
echo "DAEMON_${NODE}_STARTED pid=$NEW_PID"
echo "LOG=$LOGFILE"
echo "PIDFILE=$PIDFILE"
sleep 2
if kill -0 "$NEW_PID" 2>/dev/null; then
    echo "DAEMON_${NODE}_ALIVE=True"
else
    echo "DAEMON_${NODE}_ALIVE=False"
    echo "--- LOG (tail) ---"
    tail -30 "$LOGFILE" 2>/dev/null
    exit 1
fi
