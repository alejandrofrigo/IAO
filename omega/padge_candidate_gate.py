from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PREFLIGHT = ROOT / "tools" / "iao_v12_preflight.py"
LEDGER = ROOT / ".state" / "iao-life" / "candidate-gate.jsonl"

ALLOWED = {"PASS_STATIC", "PASS_STATIC_WITH_WARNINGS"}


def utc():
    return datetime.now(timezone.utc).isoformat()


def record(event, **fields):
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    row = {"time": utc(), "event": event, **fields}
    with LEDGER.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def digest(path):
    h = hashlib.sha256()
    if path.is_file():
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
    else:
        for item in sorted(path.rglob("*")):
            if not item.is_file():
                continue
            if ".git" in item.parts or "__pycache__" in item.parts:
                continue
            h.update(str(item.relative_to(path)).encode())
            with item.open("rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
    return h.hexdigest()


def load_preflight():
    if not PREFLIGHT.is_file():
        raise FileNotFoundError(f"Preflight ausente: {PREFLIGHT}")

    spec = importlib.util.spec_from_file_location(
        "iao_v12_preflight_runtime", PREFLIGHT
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("No se pudo cargar el preflight")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    function = getattr(module, "inspect_candidate", None)
    if not callable(function):
        raise RuntimeError("inspect_candidate no está disponible")
    return function


def validate(candidate):
    raw = Path(candidate).expanduser()
    path = (ROOT / raw).resolve() if not raw.is_absolute() else raw.resolve()

    if not path.exists():
        raise FileNotFoundError(f"Candidato inexistente: {path}")

    if path != ROOT and ROOT not in path.parents:
        raise PermissionError("El candidato está fuera del repositorio")

    inspect_candidate = load_preflight()
    before = digest(path)

    if path.is_file():
        if path.suffix != ".py":
            raise ValueError("Solo se admiten archivos Python")
        result = inspect_candidate(str(path))
        results = [result]
    else:
        files = sorted(path.rglob("*.py"))
        if not files:
            raise ValueError("No hay archivos Python en el candidato")
        results = [inspect_candidate(str(item)) for item in files]

    statuses = []
    rejected = []

    for item in results:
        if not isinstance(item, dict):
            rejected.append({"error": "Resultado preflight no válido"})
            continue

        status = item.get("status", "UNKNOWN")
        statuses.append(status)

        if status not in ALLOWED:
            rejected.append(item)

    after = digest(path)
    if before != after:
        raise RuntimeError("El candidato cambió durante la validación")

    outcome = "PASS" if not rejected else "REJECTED"

    record(
        "CANDIDATE_VALIDATION_FINISHED",
        candidate=str(path.relative_to(ROOT)),
        sha256=after,
        outcome=outcome,
        statuses=statuses,
        rejected=rejected[:30],
        file_count=len(results),
        execution="NOT_EXECUTED",
        promotion="NOT_PERFORMED",
        integration="NOT_INTEGRATED",
    )

    return {
        "outcome": outcome,
        "candidate": str(path.relative_to(ROOT)),
        "sha256": after,
        "file_count": len(results),
        "statuses": statuses,
        "rejected": rejected[:30],
        "execution": "NOT_EXECUTED",
        "promotion": "NOT_PERFORMED",
        "integration": "NOT_INTEGRATED",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate")
    args = parser.parse_args()

    try:
        result = validate(args.candidate)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["outcome"] == "PASS" else 2
    except Exception as exc:
        record(
            "CANDIDATE_VALIDATION_ERROR",
            candidate=args.candidate,
            error=f"{type(exc).__name__}: {exc}",
        )
        print(f"VALIDATION_ERROR: {type(exc).__name__}: {exc}")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
