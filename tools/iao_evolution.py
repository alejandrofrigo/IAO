#!/usr/bin/env python3
"""IAO Evolution: ciclo continuo, validación y reversión conservadora."""
import os
import sys
import json
import time
import shutil
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "omega"
STATE = ROOT / ".state" / "evolution"
GOOD = STATE / "last_good_omega"
AUDIT = STATE / "evolution.jsonl"
INTERVAL = max(60, int(os.environ.get("IAO_EVOLUTION_INTERVAL", "300")))
MAX_CYCLES = int(os.environ.get("IAO_EVOLUTION_MAX_CYCLES", "0"))

def stamp():
    return datetime.now(timezone.utc).isoformat()

def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            h.update(block)
    return h.hexdigest()

def record(event, details):
    STATE.mkdir(parents=True, exist_ok=True)
    item = {"time": stamp(), "event": event, "details": details}
    with AUDIT.open("a", encoding="utf-8") as f:
        f.write(json.dumps(item, sort_keys=True) + "\n")

def run(args, timeout=120):
    try:
        p = subprocess.run(
            args, cwd=str(ROOT), capture_output=True, text=True,
            timeout=timeout
        )
        return {
            "returncode": p.returncode,
            "stdout": p.stdout[-5000:],
            "stderr": p.stderr[-5000:]
        }
    except Exception as e:
        return {"returncode": 999, "error": repr(e)}

def syntax_check():
    if not PKG.is_dir():
        return {"returncode": 1, "error": "No existe omega/"}
    return run([sys.executable, "-m", "compileall", "-q", str(PKG)], 120)

def test_check():
    # No instala dependencias ni ejecuta pruebas externas a unittest.
    tests = ROOT / "tests"
    if not tests.is_dir():
        return {"status": "UNKNOWN", "reason": "No existe directorio tests/"}
    result = run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
        180
    )
    result["status"] = "PASS" if result["returncode"] == 0 else "FAIL"
    return result

def files_under(path):
    return {
        str(p.relative_to(path)): p
        for p in path.rglob("*")
        if p.is_file()
        and "__pycache__" not in p.parts
        and p.suffix != ".pyc"
    }

def save_good():
    tmp = STATE / "snapshot_tmp"
    if tmp.exists():
        shutil.rmtree(tmp)
    shutil.copytree(
        PKG, tmp,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc")
    )
    if GOOD.exists():
        shutil.rmtree(GOOD)
    tmp.rename(GOOD)

def restore_good():
    if not GOOD.is_dir():
        record("rollback_blocked", {
            "reason": "No hay versión validada anterior"
        })
        return False
    # Solo modifica omega/; preserva bases de datos, secretos y configuración.
    failed_copy = STATE / ("failed_" + str(int(time.time())))
    shutil.copytree(
        PKG, failed_copy,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc")
    )
    replacement = STATE / "omega_restore_tmp"
    if replacement.exists():
        shutil.rmtree(replacement)
    shutil.copytree(GOOD, replacement)
    shutil.rmtree(PKG)
    replacement.rename(PKG)
    result = syntax_check()
    record("rollback", {
        "result": result,
        "failed_code_backup": str(failed_copy)
    })
    return result.get("returncode") == 0

def cycle():
    if not PKG.is_dir():
        record("blocked", {"reason": "No existe omega/"})
        return

    before = {
        name: digest(path)
        for name, path in files_under(PKG).items()
    }
    syntax = syntax_check()

    if syntax.get("returncode") != 0:
        record("syntax_failure", syntax)
        if restore_good():
            record("repair_result", {
                "status": "RESTORED",
                "reason": "La sintaxis fallaba; se restauró la versión validada"
            })
        else:
            record("repair_result", {
                "status": "BLOCKED",
                "reason": "No fue posible una restauración segura"
            })
        return

    tests = test_check()
    after = {
        name: digest(path)
        for name, path in files_under(PKG).items()
    }
    changed = sorted(
        name for name in set(before) | set(after)
        if before.get(name) != after.get(name)
    )

    # Si hay pruebas y fallan, no se acepta el código como nueva versión buena.
    if tests.get("status") == "FAIL":
        record("test_failure", {
            "tests": tests,
            "changed_files": changed
        })
        if GOOD.is_dir():
            restored = restore_good()
            record("repair_result", {
                "status": "RESTORED" if restored else "BLOCKED",
                "reason": "Las pruebas fallaron"
            })
        else:
            record("repair_result", {
                "status": "BLOCKED",
                "reason": "No hay versión anterior para revertir"
            })
        return

    # Las pruebas inexistentes no se presentan como superadas.
    if tests.get("status") == "PASS":
        save_good()
        status = "VALIDATED"
    else:
        status = "SYNTAX_ONLY"

    record("evolution_cycle", {
        "status": status,
        "syntax": "PASS",
        "tests": tests.get("status", "UNKNOWN"),
        "changed_files": changed,
        "automatic_code_generation": False,
        "next_action": (
            "Revisar oportunidades de mejora y crear cambios aislados"
        )
    })
    print(
        stamp(), "status=", status,
        "tests=", tests.get("status", "UNKNOWN"),
        "changed_files=", len(changed),
        flush=True
    )

def main():
    if "--once" in sys.argv or "--check" in sys.argv:
        cycle()
        return
    if "--seed" in sys.argv:
        syntax = syntax_check()
        tests = test_check()
        if syntax.get("returncode") != 0 or tests.get("status") == "FAIL":
            print("BLOQUEADO: la versión actual no supera las comprobaciones.")
            sys.exit(1)
        save_good()
        record("baseline_created", {
            "syntax": "PASS",
            "tests": tests.get("status", "UNKNOWN")
        })
        print("Versión de referencia guardada.")
        return

    count = 0
    record("agent_started", {"interval_seconds": INTERVAL})
    while True:
        try:
            cycle()
        except Exception as e:
            record("agent_error", {"error": repr(e)})
        count += 1
        if MAX_CYCLES and count >= MAX_CYCLES:
            break
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
