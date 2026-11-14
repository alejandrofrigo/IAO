#!/usr/bin/env python3
"""IAO Production Evolution Engine.
Builds isolated candidates from the complete current working tree.
Never deploys, pushes, changes credentials, or edits the original checkout.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOME = Path.home()
BASE = HOME / "iao-autobuild"
CANDIDATES = BASE / "production-candidates"
REPORTS = BASE / "reports"
INTERVAL = 6 *  60 * 60
MAX_PATCH = 80000
MAX_FILES = 15

# Datos locales, secretos y entornos nunca se copian al candidato.
EXCLUDED_DIRS = {
    ".git", ".venv", "venv", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", ".state", "node_modules",
    "dist", "build", "iao-backups", "logs", "runtime",
}
EXCLUDED_NAMES = {
    ".env", ".env.local", ".env.production",
    "credentials.json", "token.json",
}
EXCLUDED_SUFFIXES = {
    ".db", ".sqlite", ".sqlite3", ".pem", ".key",
}

ALLOWED = ("omega/", "tools/", "tests/", "docs/", "web/")
BLOCKED_PARTS = (
    ".env", "secret", "credential", "token", "password",
    "private_key", "id_rsa", "id_ed25519",
)

def run(args, cwd=ROOT, timeout=1800, check=True):
    p = subprocess.run(
        args, cwd=cwd, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=timeout
    )
    if check and p.returncode:
        raise RuntimeError(
            f"Comando fallido: {' '.join(map(str,args))}\n"
            + p.stdout[-10000:]
        )
    return p

def emit(message):
    REPORTS.mkdir(parents=True, exist_ok=True)
    line = f"{dt.datetime.now(dt.timezone.utc).isoformat()} {message}"
    print(line, flush=True)
    with (REPORTS / "engine.log").open("a") as f:
        f.write(line + "\n")

def safe_copy_tree(src: Path, dst: Path):
    """Copy current source, including modified and untracked files."""
    dst.mkdir(parents=True, exist_ok=True)
    for item in src.iterdir():
        if item.name in EXCLUDED_DIRS or item.name in EXCLUDED_NAMES:
            continue
        if item.is_symlink():
            continue
        if item.is_dir():
            safe_copy_tree(item, dst / item.name)
        elif item.is_file():
            if item.suffix.lower() in EXCLUDED_SUFFIXES:
                continue
            if item.stat().st_size > 2_000_000:
                continue
            shutil.copy2(item, dst / item.name)

def inventory(candidate: Path):
    result = []
    for folder in ("omega", "tools", "tests", "docs", "web"):
        base = candidate / folder
        if not base.exists():
            continue
        for p in base.rglob("*"):
            if not p.is_file() or p.suffix not in (
                ".py", ".md", ".toml", ".yml", ".yaml",
                ".json", ".js", ".html", ".css"
            ):
                continue
            if any(x in EXCLUDED_DIRS for x in p.parts):
                continue
            try:
                content = p.read_text(errors="replace")
            except OSError:
                continue
            result.append({
                "path": p.relative_to(candidate).as_posix(),
                "content": content[:12000],
            })
    return result

def inspect(candidate: Path):
    files = inventory(candidate)
    markers = []
    for item in files:
        lines = item["content"].splitlines()
        hits = [
            f"{i+1}: {line.strip()[:160]}"
            for i, line in enumerate(lines)
            if any(x in line for x in ("TODO", "FIXME", "NotImplementedError"))
        ]
        if hits:
            markers.append({"file": item["path"], "markers": hits[:10]})
    return {
        "file_count": len(files),
        "files": files[:180],
        "unfinished_markers": markers[:80],
        "git_status": run(
            ["git", "status", "--short"], cwd=candidate, check=False
        ).stdout[:10000],
    }

def make_candidate(stamp):
    CANDIDATES.mkdir(parents=True, exist_ok=True)
    candidate = CANDIDATES / stamp
    if candidate.exists():
        raise RuntimeError(f"El candidato ya existe: {candidate}")

    # Clone conserva el historial; la copia posterior incorpora todos
    # los cambios locales y archivos fuente no versionados.
    run(["git", "clone", "--shared", "--no-hardlinks", str(ROOT), str(candidate)])
    safe_copy_tree(ROOT, candidate)

    # El candidato parte del estado de trabajo actual, no del HEAD antiguo.
    return candidate

def load_model():
    sys.path.insert(0, str(ROOT))
    from omega.llm_router import RouterModelAdapter, providers
    available = providers()
    if not available:
        raise RuntimeError("No hay proveedores de IA configurados.")
    return RouterModelAdapter()

def request_improvement(model, state):
    prompt = """Eres el arquitecto y constructor de IAO.
Evalúa el proyecto completo y propón UNA mejora que acerque el sistema
a producción real.

Prioridades:
1. Integridad, autenticación, autorización y auditoría.
2. Control plane, estados NORMAL/DEGRADED/RESTRICTED y recuperación.
3. Persistencia, aislamiento de usuarios y privacidad.
4. API, chat público y conectividad real.
5. Proveedores de IA, límites, errores y observabilidad.
6. Pruebas, mantenibilidad, documentación y despliegue reproducible.

Reglas obligatorias:
- Devuelve un diff Git unificado y nada más.
- Si no hay mejora segura, devuelve NO_CHANGE.
- Máximo 15 archivos y 80 KB.
- Solo omega/, tools/, tests/, docs/ y web/.
- No modifiques credenciales, secretos, políticas de permisos,
  autenticación, autorización, claves de auditoría ni bases de datos.
- No elimines pruebas ni rebajes controles para lograr una prueba verde.
- No agregues dependencias.
- No inventes conectividad ni declares pruebas ejecutadas.
- No introduzcas funciones ficticias ni endpoints simulados.
- La mejora debe tener una prueba adecuada.
- No afirmes que IAO está en producción.

ESTADO ACTUAL:
""" + json.dumps(state, ensure_ascii=False)[:42000]

    answer = model.chat([
        {"role": "system", "content":
         "Eres un ingeniero de software conservador. La seguridad y la evidencia prevalecen."},
        {"role": "user", "content": prompt},
    ])
    if not isinstance(answer, str):
        raise RuntimeError("Respuesta de IA inválida.")
    answer = answer.strip()
    if answer.startswith("```"):
        answer = answer.split("\n", 1)[-1]
        if answer.endswith("```"):
            answer = answer[:-3]
    return answer.strip()

def validate_patch(patch):
    if patch == "NO_CHANGE":
        return []
    if len(patch.encode()) > MAX_PATCH:
        raise RuntimeError("Diff excede el límite.")
    if not patch.startswith("diff --git "):
        raise RuntimeError("La IA no devolvió un diff Git.")

    paths = []
    for line in patch.splitlines():
        if not line.startswith("diff --git "):
            continue
        parts = line.split()
        if len(parts) != 4:
            raise RuntimeError("Cabecera diff inválida.")
        a, b = parts[2][2:], parts[3][2:]
        for name in (a, b):
            if name.startswith("/") or ".." in Path(name).parts:
                raise RuntimeError("Ruta insegura.")
            if not name.startswith(ALLOWED):
                raise RuntimeError(f"Ruta fuera de alcance: {name}")
            if any(x in name.lower() for x in BLOCKED_PARTS):
                raise RuntimeError(f"Ruta sensible bloqueada: {name}")
        paths.append(b)

    if not paths or len(paths) > MAX_FILES:
        raise RuntimeError("Cantidad de archivos inválida.")
    return paths

def run_quality_gates(candidate, stamp):
    checks = []
    commands = [
        ("pytest", [sys.executable, "-m", "pytest", "-q"]),
        ("ruff", [sys.executable, "-m", "ruff", "check", "."]),
    ]
    for name, command in commands:
        available = run(
            [sys.executable, "-c",
             "import importlib.util,sys;sys.exit(0 if importlib.util.find_spec(sys.argv[1]) else 1)",
             name],
            cwd=candidate, check=False
        ).returncode == 0
        if not available:
            checks.append({"name": name, "status": "NOT_INSTALLED"})
            continue

        result = run(command, cwd=candidate, timeout=2400, check=False)
        (REPORTS / f"{stamp}-{name}.log").write_text(result.stdout)
        checks.append({
            "name": name,
            "status": "PASS" if result.returncode == 0 else "FAIL",
            "returncode": result.returncode,
            "log": str(REPORTS / f"{stamp}-{name}.log"),
        })
        if result.returncode:
            break
    return checks

def cycle():
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    emit("INICIO: inspección del estado completo de IAO.")
    candidate = make_candidate(stamp)

    state = inspect(candidate)
    (candidate / "IAO_BUILD_BASELINE.json").write_text(
        json.dumps(state, ensure_ascii=False, indent=2)
    )
    emit(
        f"BASELINE: archivos={state['file_count']}; "
        f"cambios locales incluidos en instantánea."
    )

    model = load_model()
    patch = request_improvement(model, state)
    paths = validate_patch(patch)

    if not paths:
        emit("SIN CAMBIOS: no se propuso una mejora segura.")
        return

    patchfile = BASE / f"{stamp}.patch"
    patchfile.write_text(patch)
    run(["git", "apply", "--check", str(patchfile)], cwd=candidate)
    run(["git", "apply", str(patchfile)], cwd=candidate)
    run(["git", "diff", "--check"], cwd=candidate)

    changed = run(
        ["git", "diff", "--name-only"], cwd=candidate
    ).stdout.splitlines()
    if not changed or any(
        not x.startswith(ALLOWED) or
        any(k in x.lower() for k in BLOCKED_PARTS)
        for x in changed
    ):
        raise RuntimeError("El diff final contiene rutas no autorizadas.")

    emit("MEJORA APLICADA EN CANDIDATO AISLADO. Ejecutando controles.")
    checks = run_quality_gates(candidate, stamp)
    all_pass = bool(checks) and all(
        x["status"] == "PASS" for x in checks
    )

    report = {
        "timestamp": stamp,
        "candidate": str(candidate),
        "changed_files": changed,
        "checks": checks,
        "all_checks_passed": all_pass,
        "promotion": "NOT_PERFORMED",
        "production_status": "NOT_CERTIFIED",
    }
    report_path = REPORTS / f"{stamp}-report.json"
    report_path.write_text(json.dumps(report, indent=2))

    if all_pass:
        run(["git", "add", "--"] + changed, cwd=candidate)
        run([
            "git", "-c", "user.name=IAO Production Engine",
            "-c", "user.email=iao-engine@localhost",
            "commit", "-m", "IAO: validated production improvement"
        ], cwd=candidate)
        emit(f"CANDIDATO VALIDADO. No promovido. Informe: {report_path}")
    else:
        emit(f"CANDIDATO NO VALIDADO. No promovido. Informe: {report_path}")

    digest = hashlib.sha256(report_path.read_bytes()).hexdigest()
    emit(f"SHA256 INFORME: {digest}")

def main():
    BASE.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    run(["git", "rev-parse", "--show-toplevel"])
    if "--loop" in sys.argv:
        emit("CICLO CONTINUO cada 6 horas. Sin despliegues ni promociones.")
        while True:
            try:
                cycle()
            except Exception:
                emit("ERROR DE CICLO:\n" + traceback.format_exc()[-8000:])
            time.sleep(INTERVAL)
    else:
        cycle()

if __name__ == "__main__":
    main()
