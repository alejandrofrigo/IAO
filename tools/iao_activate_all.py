#!/usr/bin/env python3
import os
import re
import sys
import time
import json
import subprocess
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
LOGDIR = ROOT / ".state" / "iao-total-activation"
STAMP = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
OUT = LOGDIR / STAMP
OUT.mkdir(parents=True, exist_ok=True)

# Entrypoints conocidos. Solo se arrancan si su propia ayuda
# confirma que aceptan el subcomando "start".
CANDIDATES = [
    ("supervisor_integrado", "tools/iao_integrated_supervisor.py"),
    ("supervisor cinco motores", "tools/iao_five_motor_supervisor.py"),
    ("supervisor workers autonomos", "tools/iao_autonomous_worker_supervisor.py"),
    ("conectividad federada", "tools/iao_federation_connectivity.py"),
    ("launcher nodo publico", "tools/iao_public_node_launcher.py"),
    ("runtime", "tools/run_runtime.py"),
    ("daemon nodo publico", "tools/iao_public_node_daemon.py"),
]

def record(name, status, detail=""):
    line = {
        "time": datetime.now(timezone.utc).isoformat(),
        "component": name,
        "status": status,
        "detail": str(detail)[:1500],
    }
    with (OUT / "activation.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps(line, ensure_ascii=False) + "\n")
    print(f"[{status}] {name}: {detail}")

def run_help(path):
    try:
        p = subprocess.run(
            [sys.executable, str(path), "--help"],
            cwd=ROOT, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=12
        )
        return p.stdout or ""
    except Exception as e:
        return f"HELP_ERROR: {e}"

def supports_start(help_text):
    # Acepta subcomandos mostrados en el uso o en la lista de comandos.
    patterns = [
        r"\{[^}]*\bstart\b[^}]*\}",
        r"\bstart\s*[,|]\s*(?:stop|status)\b",
        r"\b(start|stop|status)\s*[,|]\s*(?:stop|status|start)\b",
    ]
    return any(re.search(p, help_text, re.I) for p in patterns)

def start_component(name, rel):
    path = ROOT / rel
    if not path.is_file():
        record(name, "NO_EXISTE", rel)
        return

    help_text = run_help(path)
    (OUT / (path.stem + ".help.txt")).write_text(
        help_text, encoding="utf-8"
    )

    if not supports_start(help_text):
        record(name, "SIN_INTERFAZ_START",
               "No se ejecutó a ciegas; revisar archivo help.txt")
        return

    try:
        p = subprocess.run(
            [sys.executable, str(path), "start"],
            cwd=ROOT, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=45
        )
        (OUT / (path.stem + ".start.log")).write_text(
            p.stdout or "", encoding="utf-8"
        )
        record(name, "START_OK" if p.returncode == 0 else "START_ERROR",
               f"exit={p.returncode}; log={path.stem}.start.log")
    except subprocess.TimeoutExpired as e:
        output = e.stdout or ""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        (OUT / (path.stem + ".start.log")).write_text(
            str(output), encoding="utf-8"
        )
        record(name, "START_TIMEOUT",
               "El comando superó 45 segundos; comprobar proceso antes de repetir")
    except Exception as e:
        record(name, "ERROR", repr(e))

print("ROOT:", ROOT)
print("INICIO:", STAMP)

for name, rel in CANDIDATES:
    start_component(name, rel)

# Estado posterior de los supervisores con interfaz conocida.
for name, rel in [
    ("estado supervisor cinco motores",
     "tools/iao_five_motor_supervisor.py"),
    ("estado supervisor integrado",
     "tools/iao_integrated_supervisor.py"),
    ("estado supervisor workers",
     "tools/iao_autonomous_worker_supervisor.py"),
]:
    path = ROOT / rel
    if not path.is_file():
        record(name, "NO_EXISTE", rel)
        continue
    try:
        h = run_help(path)
        if re.search(r"\bstatus\b", h, re.I):
            p = subprocess.run(
                [sys.executable, str(path), "status"],
                cwd=ROOT, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, timeout=20
            )
            (OUT / (path.stem + ".status.log")).write_text(
                p.stdout or "", encoding="utf-8"
            )
            record(name, "STATUS_OBTENIDO",
                   f"exit={p.returncode}; log={path.stem}.status.log")
        else:
            record(name, "SIN_INTERFAZ_STATUS", "No se ejecutó status")
    except Exception as e:
        record(name, "STATUS_ERROR", repr(e))

print("REPORTE:", OUT)
