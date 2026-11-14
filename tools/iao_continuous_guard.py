import os
import sys
import time
import fcntl
import subprocess
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / ".state/iao-integrated-operations"
LOG = STATE / "logs/continuous-guard.log"

STATE.mkdir(parents=True, exist_ok=True)

SUP = ROOT / "tools/iao_integrated_supervisor.py"
CENTRAL_LOCK = STATE / "central-supervisor.lock"
GUARD_LOCK = STATE / "continuous-guard.lock"

def record(message):
    line = (
        datetime.now(timezone.utc).isoformat()
        + " " + message
    )
    with LOG.open("a", encoding="utf-8") as f:
        f.write(line + "\n")
    print(line, flush=True)

with GUARD_LOCK.open("w") as guard:
    try:
        fcntl.flock(
            guard, fcntl.LOCK_EX | fcntl.LOCK_NB
        )
    except BlockingIOError:
        print("CONTINUOUS_GUARD_ALREADY_ACTIVE")
        sys.exit(0)

    delay = 5

    record("GUARDIAN_CONTINUO_INICIADO")

    while True:
        if not SUP.is_file():
            record("ERROR_SUPERVISOR_CENTRAL_AUSENTE")
            time.sleep(30)
            continue

        lock = CENTRAL_LOCK.open("a")

        try:
            try:
                fcntl.flock(
                    lock, fcntl.LOCK_EX | fcntl.LOCK_NB
                )
            except BlockingIOError:
                lock.close()
                time.sleep(10)
                continue

            # El supervisor no está activo.
            # Liberamos el bloqueo antes de iniciarlo.
            fcntl.flock(lock, fcntl.LOCK_UN)
            lock.close()

            record("INICIANDO_SUPERVISOR_CENTRAL")

            with LOG.open("a", encoding="utf-8") as output:
                process = subprocess.Popen(
                    [sys.executable, str(SUP)],
                    cwd=ROOT,
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    start_new_session=True
                )

                record(
                    "SUPERVISOR_LANZADO_PID="
                    + str(process.pid)
                )

                code = process.wait()

            record(
                "SUPERVISOR_FINALIZADO_CODIGO="
                + str(code)
            )

        except Exception as error:
            record(
                "ERROR_RECUPERACION="
                + type(error).__name__
                + ": " + str(error)
            )

        time.sleep(delay)
        delay = min(delay * 2, 60)
