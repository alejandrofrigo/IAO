"""IAO Evolution Engine: propuestas, verificaciones y aprobacion limitada."""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / ".state" / "evolution"
CANDIDATES = STATE / "candidates"
EVENTS = STATE / "events.jsonl"
GENESIS = "0" * 64

# La autoaprobacion solo permite pasar a staging, nunca desplegar a produccion.
MAX_FILES = 20
MAX_FILE_BYTES = 256_000
MAX_TOTAL_BYTES = 1_000_000
SAFE_EXTENSIONS = {".py", ".md", ".toml", ".yaml", ".yml", ".json"}
FORBIDDEN_PARTS = {
    ".git", ".env", "secrets", "credentials", "private", "token",
    "password", "audit-hmac-key", "dev-token-key", "dev_token_key",
}
FORBIDDEN_PATHS = {
    "omega/server.py", "omega/audit.py", "omega/store.py",
    "omega/evolution.py",
}

def _canonical(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")

def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _record(event: dict) -> None:
    STATE.mkdir(parents=True, exist_ok=True)
    previous = GENESIS
    if EVENTS.exists():
        with EVENTS.open("r", encoding="utf-8") as f:
            for line in f:
                try:
                    previous = json.loads(line)["hash"]
                except (ValueError, KeyError):
                    raise RuntimeError("Registro de evolución dañado; escritura detenida")
    body = {
        "time": time.time(),
        "previous_hash": previous,
        **event,
    }
    body["hash"] = _sha(previous.encode() + b"\n" + _canonical(body))
    fd = os.open(EVENTS, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(json.dumps(body, ensure_ascii=False, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())

def verify_log() -> tuple[bool, int | None]:
    previous = GENESIS
    if not EVENTS.exists():
        return True, None
    with EVENTS.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            try:
                row = json.loads(line)
                claimed = row.pop("hash")
                if row.get("previous_hash") != previous:
                    return False, i
                actual = _sha(previous.encode() + b"\n" + _canonical(row))
                if actual != claimed:
                    return False, i
                previous = claimed
            except (ValueError, KeyError, TypeError):
                return False, i
    return True, None

def _safe_path(name: str) -> Path:
    if not isinstance(name, str) or not name or "\\" in name:
        raise ValueError("Ruta inválida")
    p = Path(name)
    if p.is_absolute() or ".." in p.parts:
        raise ValueError("Ruta fuera del proyecto")
    if not p.parts or p.parts[0] != "omega":
        raise ValueError("Solo se permiten propuestas dentro de omega/")
    if p.suffix.lower() not in SAFE_EXTENSIONS:
        raise ValueError("Tipo de archivo no permitido")
    if any(part.lower() in FORBIDDEN_PARTS for part in p.parts):
        raise ValueError("Ruta sensible bloqueada")
    if name in FORBIDDEN_PATHS:
        raise ValueError("Componente crítico bloqueado para autoaprobación")
    return p

def _validate_proposal(proposal: dict) -> dict:
    if not isinstance(proposal, dict):
        raise ValueError("La propuesta debe ser un objeto JSON")
    title = proposal.get("title")
    changes = proposal.get("files")
    tests = proposal.get("checks")
    if not isinstance(title, str) or not title.strip() or len(title) > 160:
        raise ValueError("Título ausente o demasiado largo")
    if not isinstance(changes, dict) or not changes or len(changes) > MAX_FILES:
        raise ValueError("Cantidad de archivos inválida")
    if not isinstance(tests, list) or not tests:
        raise ValueError("Faltan comprobaciones explícitas")
    if any(x != "compileall" for x in tests):
        raise ValueError("Solo se admite la comprobación compileall en esta versión")

    clean = {}
    total = 0
    for name, content in changes.items():
        path = _safe_path(name)
        if not isinstance(content, str):
            raise ValueError("El contenido de cada archivo debe ser texto")
        data = content.encode("utf-8")
        if len(data) > MAX_FILE_BYTES:
            raise ValueError("Archivo demasiado grande")
        total += len(data)
        clean[path.as_posix()] = content
    if total > MAX_TOTAL_BYTES:
        raise ValueError("Propuesta demasiado grande")
    return {"title": title.strip(), "files": clean, "checks": tests}

def submit(proposal: dict) -> dict:
    """Guarda una propuesta aislada; no modifica el código activo."""
    ok, bad = verify_log()
    if not ok:
        raise RuntimeError(f"Registro de evolución no verificable en línea {bad}")
    clean = _validate_proposal(proposal)
    proposal_id = _sha(_canonical(clean))[:16]
    folder = CANDIDATES / proposal_id
    folder.mkdir(parents=True, exist_ok=True)
    for name, content in clean["files"].items():
        dest = folder / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")
    file_hashes = {
        name: _sha(content.encode("utf-8"))
        for name, content in clean["files"].items()
    }
    metadata = {
        "id": proposal_id,
        "title": clean["title"],
        "checks": clean["checks"],
        "files": sorted(clean["files"]),
        "file_hashes": file_hashes,
        "proposal_hash": _sha(_canonical(clean)),
        "status": "PENDING_VERIFICATION",
        "created": time.time(),
    }
    (folder / "proposal.json").write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    _record({"type": "PROPOSAL_CREATED", "id": proposal_id,
             "title": clean["title"], "files": sorted(clean["files"])})
    return metadata

def evaluate(proposal_id: str) -> dict:
    """Revalidate immutable proposal contents; never execute candidate code."""
    if not re.fullmatch(r"[0-9a-f]{16}", proposal_id):
        raise ValueError("Identificador inválido")
    ok, bad = verify_log()
    if not ok:
        raise RuntimeError(f"Registro de evolución no verificable en línea {bad}")
    folder = CANDIDATES / proposal_id
    if folder.is_symlink() or not folder.is_dir():
        raise FileNotFoundError("Directorio de propuesta inexistente o no seguro")
    meta_path = folder / "proposal.json"
    if meta_path.is_symlink() or not meta_path.is_file():
        raise FileNotFoundError("Metadatos de propuesta inexistentes o no seguros")
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    files = meta.get("files")
    hashes = meta.get("file_hashes")
    if (not isinstance(files, list) or not files or len(files) > MAX_FILES
            or not isinstance(hashes, dict)
            or set(files) != set(hashes)
            or meta.get("id") != proposal_id):
        raise ValueError("MANIFEST_INVALID")
    checks = list(meta.get("checks", []))
    if not checks or any(item != "compileall" for item in checks):
        raise ValueError("CHECK_POLICY_INVALID")

    failures = []
    total = 0
    normalized = {}
    for name in files:
        rel = _safe_path(name)
        src = folder / rel
        # Reject symlinks at every candidate path component.
        cursor = folder
        for part in rel.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                failures.append(f"{name}: SYMLINK_REFUSED")
                break
        if name in {failure.split(":")[0] for failure in failures}:
            continue
        if not src.is_file():
            failures.append(f"{name}: MISSING_OR_NOT_REGULAR_FILE")
            continue
        data = src.read_bytes()
        total += len(data)
        if len(data) > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
            failures.append(f"{name}: SIZE_LIMIT_EXCEEDED")
            continue
        actual_hash = _sha(data)
        if not isinstance(hashes.get(name), str) or actual_hash != hashes[name]:
            failures.append(f"{name}: CONTENT_HASH_MISMATCH")
            continue
        content = data.decode("utf-8")
        normalized[name] = content
        if rel.suffix == ".py":
            try:
                compile(content, name, "exec")
            except (SyntaxError, ValueError, TypeError) as exc:
                failures.append(f"{name}: SYNTAX_INVALID:{type(exc).__name__}")

    clean = {
        "title": meta.get("title"),
        "files": normalized,
        "checks": checks,
    }
    if len(normalized) == len(files):
        if _sha(_canonical(clean)) != meta.get("proposal_hash"):
            failures.append("PROPOSAL_HASH_MISMATCH")
    else:
        failures.append("PROPOSAL_INCOMPLETE")

    if failures:
        meta["status"] = "REJECTED"
        meta["failures"] = failures
        meta["validation"] = {
            "manifest_valid": False,
            "content_hashes_valid": False,
            "syntax_valid": False,
            "candidate_code_executed": False,
        }
        _record({"type": "PROPOSAL_REJECTED", "id": proposal_id,
                 "failures": failures})
    else:
        meta["status"] = "APPROVED_FOR_STAGING"
        meta["validation"] = {
            "manifest_valid": True,
            "content_hashes_valid": True,
            "syntax_valid": True,
            "candidate_code_executed": False,
        }
        meta["notice"] = (
            "Solo integridad y sintaxis verificadas. No se ejecutó el candidato; "
            "faltan pruebas funcionales, seguridad y revisión de integración. "
            "No está autorizado para promoción ni despliegue."
        )
        _record({"type": "PROPOSAL_APPROVED_FOR_STAGING",
                 "id": proposal_id, "files": meta["files"],
                 "validation": meta["validation"]})
    meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False),
                         encoding="utf-8")
    return meta

def status() -> dict:
    ok, bad = verify_log()
    items = []
    if CANDIDATES.exists():
        for p in sorted(CANDIDATES.glob("*/proposal.json")):
            try:
                items.append(json.loads(p.read_text(encoding="utf-8")))
            except Exception:
                items.append({"status": "UNREADABLE", "path": str(p)})
    return {"log_valid": ok, "first_bad_line": bad,
            "proposals": items}

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Motor de evolución controlada de IAO")
    parser.add_argument("action", choices=("status", "verify"))
    args = parser.parse_args()
    result = status() if args.action == "status" else {
        "log_valid": verify_log()[0], "first_bad_line": verify_log()[1]
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))
