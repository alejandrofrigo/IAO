#!/usr/bin/env python3
import os, sys, json, time, hashlib, shutil, subprocess, urllib.request
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / ".state"
AUDIT = STATE / "autonomy-audit.jsonl"
LOG = STATE / "autonomy.log"
PIDFILE = Path.home() / ".iao-autonomy.pid"
BASE = os.environ.get("IAO_URL", "http://127.0.0.1:8080").rstrip("/")
INTERVAL = max(30, int(os.environ.get("IAO_AUTONOMY_INTERVAL", "60")))
MAX_RESTARTS = 3
restart_times = []

def now():
    return datetime.now(timezone.utc).isoformat()

def log(message):
    STATE.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(f"{now()} {message}\n")
    print(message, flush=True)

def verify_audit():
    if not AUDIT.exists():
        return True, "Sin registros previos"
    previous = "GENESIS"
    try:
        for n, line in enumerate(AUDIT.read_text().splitlines(), 1):
            event = json.loads(line)
            actual = event.pop("hash")
            if event.get("previous_hash") != previous:
                return False, f"Enlace roto en registro {n}"
            raw = json.dumps(event, sort_keys=True, separators=(",", ":"))
            expected = hashlib.sha256(raw.encode()).hexdigest()
            if actual != expected:
                return False, f"Hash incorrecto en registro {n}"
            previous = actual
        return True, f"{n} registros íntegros" if AUDIT.stat().st_size else "Sin registros"
    except Exception as e:
        return False, f"Auditoría ilegible: {e}"

def record(event):
    STATE.mkdir(parents=True, exist_ok=True)
    ok, detail = verify_audit()
    if not ok:
        raise RuntimeError("Auditoría dañada; no se añadieron registros: " + detail)
    previous = "GENESIS"
    if AUDIT.exists() and AUDIT.stat().st_size:
        last = json.loads(AUDIT.read_text().splitlines()[-1])
        previous = last["hash"]
    event["time"] = now()
    event["previous_hash"] = previous
    raw = json.dumps(event, sort_keys=True, separators=(",", ":"))
    event["hash"] = hashlib.sha256(raw.encode()).hexdigest()
    with AUDIT.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, sort_keys=True) + "\n")

def http(path):
    try:
        req = urllib.request.Request(BASE + path, headers={"User-Agent":"IAO-Autonomy/1.0"})
        with urllib.request.urlopen(req, timeout=5) as r:
            body = r.read(32768).decode("utf-8", "replace")
            try:
                body = json.loads(body)
            except ValueError:
                body = body[:500]
            return {"status": r.status, "body": body}
    except Exception as e:
        return {"status": 0, "error": type(e).__name__ + ": " + str(e)}

def supervisors():
    result = []
    for p in Path("/proc").glob("[0-9]*"):
        try:
            cmd = (p / "cmdline").read_bytes().replace(b"\0", b" ").decode()
            if "omega.supervisor" in cmd and "iao_autonomy.py" not in cmd:
                result.append(int(p.name))
        except (OSError, ValueError):
            pass
    return result

def syntax_check():
    package = ROOT / "omega"
    if not package.is_dir():
        return False, "No existe el directorio omega"
    r = subprocess.run(
        [sys.executable, "-m", "compileall", "-q", str(package)],
        cwd=str(ROOT), capture_output=True, text=True, timeout=90
    )
    return r.returncode == 0, (r.stderr or r.stdout or "Sintaxis válida")[-1500:]

def snapshot():
    usage = shutil.disk_usage(str(ROOT))
    root = http("/")
    ready = http("/health/ready")
    pids = supervisors()
    syntax, syntax_detail = syntax_check()
    audit_ok, audit_detail = verify_audit()
    return {
        "http_monitor": root,
        "readiness_monitor": ready,
        "supervisor_pids": pids,
        "syntax_ok": syntax,
        "syntax_detail": syntax_detail,
        "disk_free_bytes": usage.free,
        "audit_ok": audit_ok,
        "audit_detail": audit_detail,
    }

def recover_supervisor(data):
    global restart_times
    t = time.time()
    restart_times = [x for x in restart_times if t - x < 900]
    if len(restart_times) >= MAX_RESTARTS:
        log("AUTORREPARACIÓN BLOQUEADA: límite de reinicios alcanzado.")
        return "BLOCKED"
    if not data["syntax_ok"] or data["supervisor_pids"]:
        return "NOT_NEEDED_OR_UNSAFE"
    if not data["audit_ok"]:
        log("AUTORREPARACIÓN BLOQUEADA: auditoría local dañada.")
        return "BLOCKED"

    # Revalidación justo antes de iniciar.
    ok, detail = syntax_check()
    if not ok or supervisors():
        log("Inicio cancelado: cambió el estado o falló la sintaxis.")
        return "CANCELLED"

    logfile = STATE / "autonomy-supervisor.log"
    with logfile.open("ab") as out:
        p = subprocess.Popen(
            [sys.executable, "-m", "omega.supervisor"],
            cwd=str(ROOT), stdin=subprocess.DEVNULL,
            stdout=out, stderr=subprocess.STDOUT,
            start_new_session=True
        )
    restart_times.append(t)
    time.sleep(3)
    result = {"pid": p.pid, "alive": p.poll() is None, "http": http("/")}
    log("AUTORREPARACIÓN: " + json.dumps(result))
    return "RECOVERED" if result["alive"] else "FAILED"

def cycle():
    data = snapshot()
    root_ok = data["http_monitor"]["status"] == 200
    ready_ok = data["readiness_monitor"]["status"] == 200
    log("Diagnóstico: " + json.dumps(data, ensure_ascii=False))
    if not data["audit_ok"]:
        log("ALERTA: auditoría local inválida; se bloquean nuevas acciones.")
        return
    repair = "NOT_NEEDED"
    if not data["supervisor_pids"]:
        repair = recover_supervisor(data)

    # El ciclo propone mejoras; no altera código automáticamente.
    proposals = []
    if not root_ok:
        proposals.append("Investigar endpoint HTTP y log del supervisor")
    if not ready_ok:
        proposals.append("Diagnosticar readiness y dependencias internas")
    if data["disk_free_bytes"] < 200 * 1024 * 1024:
        proposals.append("Espacio bajo: revisar uso de disco sin borrar datos")
    if not data["syntax_ok"]:
        proposals.append("Revisar errores de sintaxis antes de cualquier reparación")
    record({
        "type": "maintenance_cycle",
        "http_ok": root_ok,
        "readiness_ok": ready_ok,
        "syntax_ok": data["syntax_ok"],
        "repair": repair,
        "improvement_proposals": proposals,
    })
    audit_ok, audit_detail = verify_audit()
    log("Auditoría posterior: " + audit_detail)
    log("CICLO: " + ("PASS" if root_ok and ready_ok and data["syntax_ok"] and audit_ok else "DEGRADED"))

def main():
    if "--verify" in sys.argv:
        ok, detail = verify_audit()
        print(("PASS: " if ok else "FAIL: ") + detail)
        sys.exit(0 if ok else 1)
    if "--check" in sys.argv:
        data = snapshot()
        print(json.dumps(data, indent=2, ensure_ascii=False))
        sys.exit(0 if data["syntax_ok"] and data["audit_ok"] else 1)
    if "--watch" not in sys.argv:
        print("Uso: python tools/iao_autonomy.py --check | --verify | --watch")
        sys.exit(2)
    log("AGENTE 24/7 solicitado; intervalo " + str(INTERVAL) + "s")
    while True:
        try:
            cycle()
        except Exception as e:
            log("ERROR DE MANTENIMIENTO: " + repr(e))
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
