"""
IAO Autonomous Builder
Motor persistente de construcción controlada para IAO.
Solo modifica su espacio de trabajo; no publica ni altera el núcleo.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / ".iao_autobuilder"
WORKSPACE = STATE / "workspace"
QUEUE = STATE / "queue"
DONE = STATE / "completed"
FAILED = STATE / "failed"
LOG = STATE / "builder.log"
STOP = False


def now():
    return datetime.now(timezone.utc).isoformat()


def log(message):
    STATE.mkdir(parents=True, exist_ok=True)
    line = f"{now()} | {message}"
    print(line, flush=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def safe_path(base, relative):
    path = (base / relative).resolve()
    if path != base.resolve() and base.resolve() not in path.parents:
        raise ValueError("Ruta fuera del espacio autorizado")
    return path


def inventory():
    files = []
    for folder in ("omega", "tests", "tools", "web"):
        base = ROOT / folder
        if not base.exists():
            continue
        for p in base.rglob("*.py"):
            if any(x in p.parts for x in (".git", "__pycache__", ".venv")):
                continue
            try:
                files.append({
                    "path": str(p.relative_to(ROOT)),
                    "bytes": p.stat().st_size,
                    "sha256": digest(p),
                })
            except OSError:
                pass
    return files


def build_inventory():
    """Construye un artefacto real con el estado del código."""
    data = {
        "generated_at": now(),
        "project": ROOT.name,
        "python": sys.version,
        "files": inventory(),
    }
    out = WORKSPACE / "project_inventory.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    temp = out.with_suffix(".tmp")
    temp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    temp.replace(out)
    return out, len(data["files"])


def validate_python(path):
    if path.suffix == ".py":
        ast.parse(path.read_text(encoding="utf-8"))
    return True


def run_task(task_file):
    """Ejecuta tareas de escritura únicamente dentro del workspace."""
    task = json.loads(task_file.read_text(encoding="utf-8"))
    if task.get("action") != "create_or_update":
        raise ValueError("Acción no permitida")
    relative = task.get("path", "")
    if not relative or Path(relative).is_absolute():
        raise ValueError("Ruta de tarea inválida")
    target = safe_path(WORKSPACE, relative)
    content = task.get("content")
    if not isinstance(content, str):
        raise ValueError("Falta el contenido textual")
    if len(content.encode("utf-8")) > 200_000:
        raise ValueError("Tarea supera el límite de 200 KB")

    target.parent.mkdir(parents=True, exist_ok=True)
    old = target.read_bytes() if target.exists() else None
    temp = target.with_name(target.name + ".iao-tmp")
    temp.write_text(content, encoding="utf-8")

    try:
        validate_python(temp if target.suffix == ".py" else target)
        if target.suffix == ".py":
            ast.parse(content)
        temp.replace(target)

        if target.suffix == ".py":
            result = subprocess.run(
                [sys.executable, "-m", "py_compile", str(target)],
                cwd=ROOT, capture_output=True, text=True, timeout=30
            )
            if result.returncode:
                raise RuntimeError(result.stderr[-3000:])

        return {"path": str(target.relative_to(ROOT)), "sha256": digest(target)}
    except Exception:
        temp.unlink(missing_ok=True)
        if old is None:
            target.unlink(missing_ok=True)
        else:
            target.write_bytes(old)
        raise


def cycle():
    STATE.mkdir(parents=True, exist_ok=True)
    for d in (WORKSPACE, QUEUE, DONE, FAILED):
        d.mkdir(parents=True, exist_ok=True)

    log("CICLO_INICIADO")
    report = {"time": now(), "tasks": [], "errors": []}

    try:
        artifact, count = build_inventory()
        report["inventory"] = {
            "artifact": str(artifact.relative_to(ROOT)),
            "python_files": count,
            "sha256": digest(artifact),
        }
        log(f"INVENTARIO_CONSTRUIDO archivos={count}")
    except Exception as exc:
        report["errors"].append("inventory: " + repr(exc))
        log("ERROR_INVENTARIO " + repr(exc))

    for task_file in sorted(QUEUE.glob("*.json")):
        try:
            result = run_task(task_file)
            destination = DONE / task_file.name
            task_file.replace(destination)
            report["tasks"].append({"task": task_file.name, "result": result})
            log(f"TAREA_COMPLETADA {task_file.name}")
        except Exception as exc:
            report["errors"].append(f"{task_file.name}: {exc}")
            destination = FAILED / task_file.name
            try:
                task_file.replace(destination)
            except OSError:
                pass
            log(f"TAREA_RECHAZADA {task_file.name}: {exc}")

    report_path = STATE / "last_report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    log(f"CICLO_FINALIZADO errores={len(report['errors'])}")
    return report


def stop_handler(*_):
    global STOP
    STOP = True


def main():
    parser = argparse.ArgumentParser(description="IAO Autonomous Builder")
    parser.add_argument("--once", action="store_true", help="Ejecuta un ciclo")
    parser.add_argument("--loop", action="store_true", help="Ejecución persistente")
    parser.add_argument("--interval", type=int, default=300)
    parser.add_argument("--status", action="store_true")
    args = parser.parse_args()

    if args.status:
        report = STATE / "last_report.json"
        print(report.read_text() if report.exists() else "Todavía no hay ciclos.")
        return

    if args.once or not args.loop:
        cycle()
        return

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)
    log("MOTOR_PERSISTENTE_INICIADO")
    while not STOP:
        cycle()
        for _ in range(max(10, args.interval)):
            if STOP:
                break
            time.sleep(1)
    log("MOTOR_DETENIDO")


if __name__ == "__main__":
    main()
