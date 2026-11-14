#!/usr/bin/env python3
"""Puente de propuestas PADGE con preflight V12."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / ".state" / "padge" / "bridge"
CANDIDATES = STATE / "candidates"
REPORTS = STATE / "reports"
EVENTS = STATE / "events.jsonl"
PREFLIGHT = ROOT / "tools" / "iao_v12_preflight.py"

MAX_FILES = 15
MAX_FILE_BYTES = 100_000


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime(
        "%Y%m%dT%H%M%S%fZ"
    )


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def log_event(name: str, **fields: Any) -> None:
    STATE.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": name,
        **fields,
    }
    with EVENTS.open("a", encoding="utf-8") as stream:
        stream.write(
            json.dumps(record, ensure_ascii=False) + "\n"
        )


def load_padge():
    sys.path.insert(0, str(ROOT))

    from omega import padge

    for name in ("inspect", "ask_iao"):
        if not callable(getattr(padge, name, None)):
            raise RuntimeError(
                f"Interfaz PADGE ausente: {name}"
            )

    return padge


def validate_snapshot(snapshot: Any) -> dict:
    if not isinstance(snapshot, dict):
        raise TypeError("PADGE inspect() no devolvió un diccionario")

    for key in ("branch", "commit", "working_changes", "files"):
        if key not in snapshot:
            raise ValueError(
                f"Snapshot PADGE incompleto: falta {key}"
            )

    if not isinstance(snapshot["files"], list):
        raise TypeError("snapshot.files no es una lista")

    return snapshot


def validate_plan(plan: Any) -> dict:
    if not isinstance(plan, dict):
        raise TypeError("PADGE no devolvió un plan JSON")

    for key in ("goal", "reason", "changes"):
        if key not in plan:
            raise ValueError(
                f"Plan PADGE incompleto: falta {key}"
            )

    if not isinstance(plan["goal"], str):
        raise TypeError("goal debe ser texto")

    if not isinstance(plan["reason"], str):
        raise TypeError("reason debe ser texto")

    changes = plan["changes"]

    if not isinstance(changes, list):
        raise TypeError("changes debe ser una lista")

    if len(changes) > MAX_FILES:
        raise ValueError("El plan supera el límite de 15 archivos")

    seen = set()

    for index, item in enumerate(changes):
        if not isinstance(item, dict):
            raise TypeError(
                f"El cambio {index} no es un objeto"
            )

        relative = item.get("path")
        content = item.get("content")

        if not isinstance(relative, str) or not isinstance(content, str):
            raise ValueError(
                f"El cambio {index} requiere path y content de texto"
            )

        path = PurePosixPath(relative)

        if (
            path.is_absolute()
            or ".." in path.parts
            or not path.parts
            or path.parts[0] not in {"omega", "tools", "docs"}
        ):
            raise ValueError(
                f"Ruta no permitida en propuesta: {relative}"
            )

        if relative in seen:
            raise ValueError(
                f"Ruta duplicada en propuesta: {relative}"
            )

        seen.add(relative)

        if not content.strip():
            raise ValueError(
                f"Contenido vacío: {relative}"
            )

        if len(content.encode("utf-8")) > MAX_FILE_BYTES:
            raise ValueError(
                f"Archivo superior a 100000 bytes: {relative}"
            )

    return plan


def inspect_only(padge) -> None:
    snapshot = validate_snapshot(padge.inspect())

    summary = {
        "branch": snapshot["branch"],
        "commit": snapshot["commit"],
        "working_changes": snapshot["working_changes"],
        "tracked_python_files": len(snapshot["files"]),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    output = REPORTS / f"inspection-{utc_stamp()}.json"
    write_json(output, summary)

    log_event(
        "bridge_inspection_saved",
        report=str(output.relative_to(ROOT)),
        files=summary["tracked_python_files"],
    )

    print("INSPECCIÓN PADGE: OK")
    print("Rama:", summary["branch"])
    print("Commit:", summary["commit"])
    print("Archivos Python inspeccionados:", summary["tracked_python_files"])
    print("Informe:", output)


def propose(padge) -> int:
    if not PREFLIGHT.is_file():
        raise RuntimeError("No se encuentra el preflight V12")

    snapshot = validate_snapshot(padge.inspect())

    print("Snapshot real obtenido.")
    print("Rama:", snapshot["branch"])
    print("Commit:", snapshot["commit"])
    print("Archivos inspeccionados:", len(snapshot["files"]))
    print("Invocando omega.padge.ask_iao(snapshot)...")

    log_event(
        "bridge_generation_started",
        branch=snapshot["branch"],
        commit=snapshot["commit"],
    )

    plan = validate_plan(padge.ask_iao(snapshot))

    stamp = utc_stamp()
    candidate_dir = CANDIDATES / f"proposal-{stamp}"
    candidate_dir.mkdir(parents=True, exist_ok=False)

    staged = []

    for index, item in enumerate(plan["changes"], start=1):
        relative = PurePosixPath(item["path"])
        filename = f"{index:02d}-{relative.name}"
        target = candidate_dir / filename

        data = item["content"].encode("utf-8")
        target.write_bytes(data)

        staged.append({
            "requested_path": item["path"],
            "candidate_path": str(target),
            "sha256": digest(data),
            "bytes": len(data),
        })

    preflight = {
        "status": "NOT_APPLICABLE",
        "exit_code": None,
        "output": "",
    }

    if staged:
        command = [
            sys.executable,
            str(PREFLIGHT),
            *[item["candidate_path"] for item in staged],
        ]

        result = subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

        preflight = {
            "status": (
                "STATIC_CHECK_ACCEPTED"
                if result.returncode == 0
                else "STATIC_CHECK_REJECTED"
            ),
            "exit_code": result.returncode,
            "output": (result.stdout or "")[-10000:],
            "error": (result.stderr or "")[-5000:],
        }

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "goal": plan["goal"],
        "reason": plan["reason"],
        "branch": snapshot["branch"],
        "commit": snapshot["commit"],
        "changes": staged,
        "preflight": preflight,
        "execution": "NOT_EXECUTED",
        "promotion": "NOT_PERFORMED",
        "integration": "NOT_INTEGRATED",
    }

    report_path = REPORTS / f"proposal-{stamp}.json"
    write_json(report_path, report)

    log_event(
        "bridge_proposal_saved",
        report=str(report_path.relative_to(ROOT)),
        candidate_count=len(staged),
        preflight_status=preflight["status"],
        promotion="NOT_PERFORMED",
    )

    print("\n=== PROPUESTA PADGE ===")
    print("Objetivo:", plan["goal"])
    print("Justificación:", plan["reason"][:1000])
    print("Cambios propuestos:", len(staged))

    for item in staged:
        print("\nRuta propuesta:", item["requested_path"])
        print("Candidato:", item["candidate_path"])
        print("SHA256:", item["sha256"])

    print("\nPreflight V12:", preflight["status"])
    if preflight["exit_code"] is not None:
        print("Código de salida V12:", preflight["exit_code"])

    if preflight["output"]:
        print("\n--- SALIDA V12 ---")
        print(preflight["output"])

    if preflight.get("error"):
        print("\n--- ERRORES V12 ---")
        print(preflight["error"])

    print("\nInforme:", report_path)
    print("Código ejecutado: NO")
    print("Promoción: NO")
    print("Integración: NO")

    return 0 if preflight["exit_code"] in (0, None) else 2


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Puente de propuestas PADGE con preflight V12"
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--inspect-only",
        action="store_true",
        help="Guarda un resumen de la inspección real de PADGE",
    )
    mode.add_argument(
        "--propose",
        action="store_true",
        help="Solicita un plan a PADGE y lo guarda como candidato",
    )

    args = parser.parse_args()

    STATE.mkdir(parents=True, exist_ok=True)
    CANDIDATES.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)

    padge = load_padge()

    if args.inspect_only:
        inspect_only(padge)
        return 0

    if args.propose:
        return propose(padge)

    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        try:
            log_event(
                "bridge_error",
                error_type=type(exc).__name__,
                error=str(exc)[:1000],
            )
        except Exception:
            pass

        print(
            f"ERROR: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        raise SystemExit(1)
