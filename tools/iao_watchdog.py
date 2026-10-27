#!/usr/bin/env python
"""IAO watchdog: supervisa HTTP local e intenta recuperar omega.supervisor."""
from pathlib import Path
import hashlib, os, socket, subprocess, sys, time
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / ".state"
PIDFILE = STATE / "iao-watchdog.pid"
LOG = STATE / "iao-watchdog.log"
URL = "http://127.0.0.1:8080/"
INTERVAL = 10

def log(msg):
    line = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + " " + msg + "\n"
    with LOG.open("a", encoding="utf-8") as f:
        f.write(line)

def port_open():
    try:
        with socket.create_connection(("127.0.0.1", 8080), timeout=1):
            return True
    except OSError:
        return False

def healthy():
    try:
        with urlopen(URL, timeout=3) as r:
            return r.status == 200
    except Exception:
        return False

def self_test():
    assert ROOT.is_dir()
    assert (ROOT / "omega" / "supervisor.py").is_file(), "omega/supervisor.py missing"
    assert INTERVAL >= 5
    print("WATCHDOG_SELF_TEST=PASS")
    print("SUPERVISOR_MODULE=FOUND")
    print("ROOT=" + str(ROOT))

def daemon():
    STATE.mkdir(parents=True, exist_ok=True)
    PIDFILE.write_text(str(os.getpid()) + "\n", encoding="utf-8")
    child = None
    delay = 10
    log("WATCHDOG_STARTED pid=" + str(os.getpid()))
    try:
        while True:
            if healthy():
                log("HEALTH=PASS http=200")
                delay = 10
                if child is not None and child.poll() is not None:
                    log("SUPERVISOR_CHILD_EXITED code=" + str(child.returncode))
                    child = None
            elif port_open():
                # A listener already owns the port; avoid spawning a duplicate.
                log("HEALTH=FAIL port=occupied action=no_duplicate_start")
                delay = min(delay * 2, 120)
            else:
                if child is None or child.poll() is not None:
                    try:
                        log("RECOVERY=STARTING python -m omega.supervisor")
                        child = subprocess.Popen(
                            [sys.executable, "-m", "omega.supervisor"],
                            cwd=str(ROOT),
                            stdin=subprocess.DEVNULL,
                            stdout=LOG.open("a", encoding="utf-8"),
                            stderr=subprocess.STDOUT,
                            start_new_session=True,
                        )
                        log("SUPERVISOR_CHILD_PID=" + str(child.pid))
                        time.sleep(3)
                        if healthy():
                            log("RECOVERY=PASS http=200")
                            delay = 10
                        else:
                            log("RECOVERY=PENDING_OR_FAILED")
                            delay = min(delay * 2, 120)
                    except Exception as e:
                        log("RECOVERY_ERROR=" + type(e).__name__)
                        delay = min(delay * 2, 120)
                else:
                    log("SUPERVISOR_CHILD=RUNNING health=pending")
            time.sleep(delay)
    finally:
        try:
            PIDFILE.unlink(missing_ok=True)
        except Exception:
            pass
        log("WATCHDOG_STOPPED")

if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()
    elif "--daemon" in sys.argv:
        daemon()
    else:
        print("Usage: python tools/iao_watchdog.py --self-test|--daemon")
