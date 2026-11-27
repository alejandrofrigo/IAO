from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".state" / "padge"
WORK = STATE / "work"
VERSIONS = STATE / "versions"
REPORTS = STATE / "reports"

for directory in (STATE, WORK, VERSIONS, REPORTS):
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)

ALLOWED = ("omega/", "tools/", "docs/")
PROTECTED = {
    "server.py", "service.py", "store.py", "policy_gate.py",
    "audit.py", "release.py", "evolution.py", "llm_router.py",
    "padge.py", "config.py",
    # Componentes críticos protegidos también por la política central.
    "auth.py", "iao_router.py", "padge_autonomy_policy.py",
    "autonomous_authority.py", "iao_autonomy.py",
}
MAX_FILES = 15
MAX_BYTES = 100_000
TEST_TIMEOUT = 900


def utc():
    return datetime.now(timezone.utc).isoformat()


def log(event, **data):
    from omega.operational_log import append_private_jsonl

    entry = append_private_jsonl(
        STATE / "events.jsonl",
        {"time": utc(), "event": event, **data},
    )
    print(json.dumps(entry, ensure_ascii=False), flush=True)


def run(args, cwd=ROOT, timeout=TEST_TIMEOUT):
    return subprocess.run(
        args, cwd=cwd, text=True, capture_output=True,
        timeout=timeout, check=False,
    )


def inspect():
    result = run(["git", "status", "--short"])
    tracked = run(["git", "ls-files"])
    sources = []

    for name in tracked.stdout.splitlines():
        if not name.endswith(".py"):
            continue
        if not name.startswith(("omega/", "tools/")):
            continue
        if Path(name).name in PROTECTED:
            continue
        path = ROOT / name
        if not path.is_file():
            continue
        try:
            content = path.read_text(encoding="utf-8")
            sources.append({
                "path": name,
                "sha256": hashlib.sha256(content.encode()).hexdigest(),
                "source": content[:5000],
            })
        except (OSError, UnicodeError):
            pass

    return {
        "branch": run(["git", "branch", "--show-current"]).stdout.strip(),
        "commit": run(["git", "rev-parse", "HEAD"]).stdout.strip(),
        "working_changes": result.stdout[:10000],
        "files": sources[:50],
    }



# PADGE_EVENT_MEMORY_V1
def recent_padge_history(limit=30):
    """Memoria combinada de informes y eventos operativos de PADGE."""
    history = []

    # Informes persistentes de candidatos.
    if REPORTS.is_dir():
        files = sorted(
            REPORTS.glob("*.json"),
            key=lambda item: item.stat().st_mtime_ns,
            reverse=True,
        )[:limit]

        for path in files:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(data, dict):
                    continue

                item = {
                    "report": path.name,
                    "status": str(data.get("status", ""))[:80],
                    "goal": str(data.get("goal", ""))[:300],
                    "reason": str(data.get("reason", ""))[:300],
                    "paths": [],
                }

                for key in ("changed_files", "promoted_files", "files", "paths"):
                    value = data.get(key)
                    if isinstance(value, list):
                        item["paths"] = [
                            str(x.get("path", "")) if isinstance(x, dict)
                            else str(x)
                            for x in value[:15]
                        ]
                        break

                history.append(item)
            except (OSError, ValueError, TypeError):
                continue

    # Eventos recientes: incluye bloqueos que nunca llegaron a generar informe.
    events_path = STATE / "events.jsonl"
    if events_path.is_file():
        try:
            lines = events_path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()[-500:]
        except OSError:
            lines = []

        event_status = {
            "policy_blocked": "POLICY_BLOCKED",
            "proposal_deferred": "PROPOSAL_DEFERRED",
            "candidate_rejected": "CANDIDATE_REJECTED",
            "autonomous_promotion_rejected": "POLICY_REJECTED",
            "central_authority_rejected": "AUTHORITY_REJECTED",
            "candidate_promoted_to_worktree": "PROMOTED_TO_WORKTREE",
        }

        for line in reversed(lines):
            try:
                event = json.loads(line)
                if not isinstance(event, dict):
                    continue

                event_name = event.get("event")
                status = event_status.get(event_name)
                if not status:
                    continue

                paths = event.get("paths") or event.get("files") or []
                if not isinstance(paths, list):
                    paths = []

                # Recuperación de la ruta de los bloqueos antiguos.
                reason = str(event.get("reason", ""))
                if not paths:
                    match = re.search(
                        r"Archivo protegido:\s*([A-Za-z0-9_./-]+)",
                        reason,
                    )
                    if match:
                        paths = [match.group(1)]

                history.append({
                    "report": "events.jsonl",
                    "time": str(event.get("time", "")),
                    "status": status,
                    "goal": str(event.get("goal", ""))[:300],
                    "reason": reason[:300],
                    "paths": [str(x) for x in paths[:15]],
                })
            except (ValueError, TypeError):
                continue

    return history[:max(1, limit)]


def _parse_model_plan(response):
    """Parsea y valida una propuesta JSON sin reparar contenido defectuoso."""
    if not isinstance(response, str):
        raise TypeError("La respuesta del modelo no es texto")

    if len(response.encode("utf-8")) > 2_000_000:
        raise ValueError("Respuesta del modelo demasiado grande")

    decoder = json.JSONDecoder()
    plan = None

    # Permite texto introductorio o bloques Markdown, pero exige
    # encontrar un objeto JSON completo y válido.
    for position, char in enumerate(response):
        if char != "{":
            continue
        try:
            candidate, _ = decoder.raw_decode(response[position:])
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict):
            plan = candidate
            break

    if not isinstance(plan, dict):
        raise ValueError("No se encontró un objeto JSON completo")

    goal = plan.get("goal")
    reason = plan.get("reason")
    changes = plan.get("changes")

    if not isinstance(goal, str) or not goal.strip() or len(goal) > 500:
        raise ValueError("Objetivo ausente o inválido")

    if not isinstance(reason, str) or len(reason) > 4000:
        raise ValueError("Justificación ausente o inválida")

    if not isinstance(changes, list) or len(changes) > 15:
        raise ValueError("Lista de cambios inválida o demasiado extensa")

    normalized = []
    seen = set()

    for item in changes:
        if not isinstance(item, dict):
            raise ValueError("Elemento de cambio inválido")

        path = item.get("path")
        content = item.get("content")

        if not isinstance(path, str) or not path or len(path) > 512:
            raise ValueError("Ruta de cambio inválida")

        if not isinstance(content, str):
            raise ValueError("Contenido de archivo no textual")

        if len(content.encode("utf-8")) > 100_000:
            raise ValueError("Archivo propuesto supera 100000 bytes")

        if path in seen:
            raise ValueError("Ruta duplicada en la propuesta")

        seen.add(path)
        normalized.append({"path": path, "content": content})

    return {
        "goal": goal.strip(),
        "reason": reason.strip(),
        "changes": normalized,
    }


def ask_iao(snapshot):
    from omega.llm_router import chat_with_metadata

    prompt = """
[PADGE_MISSION_FEDERATED_EVOLUTION_V1]

MISIÓN PRIORITARIA: CONSTRUIR LAS CAPACIDADES REALES DE LA RED FEDERADA DE IAO.

Esta misión tiene prioridad sobre mejoras cosméticas, documentación repetitiva
y diagnósticos que no produzcan una capacidad técnica nueva.

OBJETIVO:
Construir progresivamente una infraestructura federada verificable, modular,
segura y preparada para incorporar participantes externos autorizados.

TRABAJO TÉCNICO QUE DEBES PRIORIZAR:
1. Inspeccionar las interfaces reales de omega/federation.py,
   omega/federation_proposals.py y omega/federation_assimilation.py.
2. Identificar capacidades ausentes y contratos existentes antes de proponer código.
3. Construir módulos nuevos para descubrimiento controlado de candidatos,
   validación de capacidades, comprobación de conectividad y seguimiento de estado.
4. Crear pruebas automatizadas para identidad, autorización, revocación,
   transporte HTTPS, validación de DNS/IP, límites de recursos y fallos de red.
5. Mejorar la generación y seguimiento de propuestas federadas firmadas.
6. Preparar pruebas de intercambio real únicamente cuando exista un participante
   externo identificable, autorizado y verificable.
7. Priorizar implementaciones pequeñas, integrables, probadas y con evidencia.
8. Si una capacidad ya existe, comprobarla y avanzar al siguiente vacío real.
   No repetir una implementación equivalente ni presentar una inspección como avance.

LÍMITES OBLIGATORIOS:
- No inventes nodos, direcciones, endpoints, claves, respuestas ni intercambios.
- No registres ni incorpores automáticamente participantes externos.
- No generes confianza a partir de una respuesta del propio modelo.
- No sustituyas ni debilites la identidad Ed25519 fijada y verificada.
- No elimines la autorización explícita del operador ni la revocación.
- No desactives autenticación, auditoría, políticas, protección de secretos,
  aislamiento, backups, rollback ni controles de egreso.
- No modifiques ni renombres archivos protegidos para eludir restricciones.
- No conviertas una propuesta, candidato descubierto o prueba local en
  participante federado autorizado.
- No realices conexiones externas si no están permitidas por la política vigente.
- Respeta los directorios, límites de tamaño y permisos que ya impone PADGE.
- Si una tarea requiere autorización humana, prepara la propuesta y detente
  exactamente en ese límite.

CRITERIO DE AVANCE:
Un avance debe producir código nuevo o una mejora concreta, pruebas reproducibles,
un informe de evidencia o una propuesta técnica revisable.
Toda modificación debe superar las pruebas aplicables y conservar rollback.
Si no puedes realizar una mejora segura, informa el bloqueo concreto y propone
una misión alternativa admisible; no repitas indefinidamente la misma propuesta.

FORMATO DE RESPUESTA:
Devuelve exclusivamente el objeto JSON que exige el contrato actual de PADGE,
con goal, reason y changes. Cada cambio debe incluir una ruta admisible y su
contenido completo. No incluyas Markdown, explicaciones fuera del JSON ni
afirmaciones de ejecución que no hayas comprobado.

Eres PADGE, el componente de autoprogramación de IAO.
Tu responsabilidad es mejorar el sistema IAO mediante cambios reales
de código, pequeños, coherentes y verificables.

Analiza el estado del repositorio y produce una mejora concreta.
Devuelve exclusivamente JSON con esta estructura:
{
 "goal": "objetivo",
 "reason": "justificación técnica",
 "changes": [
   {"path": "omega/modulo.py", "content": "contenido COMPLETO del archivo"}
 ]
}

REGLAS:
- Solo puedes proponer archivos dentro de omega/, tools/ y docs/.
- No cambies pruebas para ocultar fallos.
- No cambies servidores, servicios, almacenamiento, auditoría,
  políticas, seguridad, router de IA, PADGE, secretos ni configuración.
- No inventes resultados de ejecución.
- No incluyas marcadores de posición ni código ficticio.
- Máximo 15 archivos y 100000 bytes por archivo.
- Si no hay una mejora justificada, devuelve changes vacío.
- No repitas objetivos ni cambios recientemente promovidos por PADGE.
- Compara cada propuesta con el historial reciente.
- Si una propuesta fue promovida, busca una mejora distinta y verificable.
- Si fue rechazada, no la repitas sin resolver la causa del rechazo.
- Los estados POLICY_BLOCKED y PROPOSAL_DEFERRED son memoria operativa: no propongas de nuevo esas rutas.
- Si una ruta está bloqueada, selecciona otra capacidad admisible y verificable; no intentes eludir la protección cambiando el nombre o dividiendo el archivo.
- No te detengas por una propuesta rechazada: busca una misión distinta dentro de las rutas permitidas.
- Prioriza completar capacidades reales de IAO, no documentación vacía.

ESTADO ACTUAL:
""" + json.dumps({
        "branch": snapshot.get("branch"),
        "commit": snapshot.get("commit"),
        "working_changes": snapshot.get("working_changes", "")[:3000],
        "recent_padge_history": recent_padge_history(),
        "files": [
            {
                "path": item.get("path"),
                "sha256": item.get("sha256"),
                "source": item.get("source", "")[:1200],
            }
            for item in snapshot.get("files", [])[:12]
        ],
    }, ensure_ascii=False)[:24000]

    result = chat_with_metadata([
        {"role": "user", "content": prompt}
    ], timeout=90)

    if isinstance(result, dict):
        response = result.get("reply", "")
    else:
        response = result

    if not isinstance(response, str):
        raise TypeError("El router no devolvió texto")

    response = re.sub(
        r"^```(?:json)?\s*|\s*```$", "", response.strip(),
        flags=re.IGNORECASE,
    )
    return _parse_model_plan(response)




def reject_recent_duplicate(plan):
    """Evita repetir promociones y propuestas recientemente bloqueadas."""
    import re
    from difflib import SequenceMatcher

    def normalize(value):
        value = str(value or "").lower()
        value = re.sub(r"`[^`]*`", " ", value)
        value = re.sub(r"[^a-z0-9áéíóúñü]+", " ", value)
        return " ".join(value.split())

    if not isinstance(plan, dict):
        return

    goal = normalize(plan.get("goal", ""))
    changes = plan.get("changes", [])

    if not goal or not isinstance(changes, list):
        return

    paths = {
        str(item.get("path", "")).strip()
        for item in changes
        if isinstance(item, dict) and item.get("path")
    }
    paths.discard("")

    if not paths:
        return

    for previous in recent_padge_history(limit=60):
        status = str(previous.get("status", "")).upper()
        old_paths = set(previous.get("paths", []))
        old_paths.discard("")

        # Una ruta bloqueada no debe volver a consumir ciclos.
        if status in {"POLICY_BLOCKED", "PROPOSAL_DEFERRED"}:
            blocked = paths & old_paths
            if blocked:
                raise ValueError(
                    "Propuesta bloqueada recientemente: "
                    + ", ".join(sorted(blocked))
                )

        # Conserva la protección contra repetir mejoras ya promovidas.
        if status not in {
            "PROMOTED_TO_WORKTREE",
            "PROMOTED",
            "PROMOTED_SUCCESS",
        }:
            continue

        old_goal = normalize(previous.get("goal", ""))
        if not old_goal or not old_paths:
            continue

        overlap = len(paths & old_paths) / max(1, len(paths | old_paths))
        similarity = SequenceMatcher(None, goal, old_goal).ratio()

        if overlap >= 0.8 and similarity >= 0.82:
            raise ValueError(
                "Propuesta redundante: objetivo y archivos ya promovidos "
                f"(similitud={similarity:.2f}, solapamiento={overlap:.2f})"
            )


def validate(plan):
    reject_recent_duplicate(plan)
    if not isinstance(plan, dict):
        raise ValueError("Propuesta inválida")
    changes = plan.get("changes")
    if not isinstance(changes, list) or len(changes) > MAX_FILES:
        raise ValueError("Lista de cambios inválida")

    clean = {}
    for item in changes:
        if not isinstance(item, dict):
            raise ValueError("Cambio mal formado")
        name, content = item.get("path"), item.get("content")
        if not isinstance(name, str) or not isinstance(content, str):
            raise ValueError("Ruta o contenido inválido")

        path = Path(name)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("Ruta fuera del repositorio")
        if not name.startswith(ALLOWED):
            raise ValueError("Ruta no permitida: " + name)
        if path.name in PROTECTED:
            raise ValueError("Archivo protegido: " + name)
        if len(content.encode("utf-8")) > MAX_BYTES:
            raise ValueError("Archivo demasiado grande")
        if name in clean:
            raise ValueError("Ruta duplicada")
        clean[name] = content

    return clean


def pytest_result(directory):
    result = run(
        [sys.executable, "-m", "pytest", "-q"],
        cwd=directory,
        timeout=TEST_TIMEOUT,
    )
    output = result.stdout + "\n" + result.stderr
    failed = sum(
        int(n) for n in re.findall(r"(\d+) failed", output)
    )
    errors = sum(
        int(n) for n in re.findall(r"(\d+) error", output)
    )
    passed = sum(
        int(n) for n in re.findall(r"(\d+) passed", output)
    )
    skipped = sum(
        int(n) for n in re.findall(r"(\d+) skipped", output)
    )
    return {
        "exit": result.returncode,
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "skipped": skipped,
        "output": output[-12000:],
    }


def make_workspace(identifier):
    stage = WORK / identifier
    ignored = shutil.ignore_patterns(
        ".git", ".state", "__pycache__", ".pytest_cache",
        ".venv", "venv", "node_modules", "*.pyc",
        ".env", "*.db", "*.sqlite", "*.sqlite3",
    )
    shutil.copytree(ROOT, stage, ignore=ignored)
    return stage



def _promote_transactionally(
    changes,
    candidate_root,
    backup_dir,
    root=ROOT,
    replace_fn=None,
):
    """Promueve un conjunto completo o restaura todos sus originales."""

    import os
    import tempfile

    if replace_fn is None:
        replace_fn = os.replace

    root = Path(root).resolve()
    candidate_root = Path(candidate_root)
    backup_dir = Path(backup_dir)
    backup_dir.mkdir(parents=True, exist_ok=True)

    snapshots = {}
    prepared = {}

    try:
        if not isinstance(changes, dict) or not changes:
            raise ValueError("EMPTY_CHANGESET")

        for name in changes:
            if not isinstance(name, str):
                raise ValueError("INVALID_PATH")

            relative = Path(name)

            if relative.is_absolute() or ".." in relative.parts:
                raise PermissionError("PATH_TRAVERSAL")

            # Defensa en profundidad: la promoción nunca modifica
            # componentes protegidos, aunque una barrera superior falle.
            if relative.name in PROTECTED:
                raise PermissionError("PROTECTED_COMPONENT")

            if not name.startswith(("omega/", "tools/", "docs/")):
                raise PermissionError("PATH_OUTSIDE_ALLOWED_ROOTS")

            target = root / relative

            current = target
            while current != root:
                if current.is_symlink():
                    raise PermissionError("SYMLINK_NOT_ALLOWED")
                current = current.parent

            resolved = target.resolve(strict=False)
            resolved.relative_to(root)

            candidate = candidate_root / relative

            if candidate.is_symlink() or not candidate.is_file():
                raise ValueError("INVALID_CANDIDATE_FILE: " + name)

            if target.exists():
                if not target.is_file():
                    raise ValueError("TARGET_NOT_REGULAR_FILE: " + name)
                original = target.read_bytes()
                mode = target.stat().st_mode & 0o7777
            else:
                original = None
                mode = 0o644

            snapshots[target] = (original, mode)
            prepared[target] = (candidate.read_bytes(), mode)

            if original is not None:
                saved = backup_dir / relative
                saved.parent.mkdir(parents=True, exist_ok=True)
                saved.write_bytes(original)
                os.chmod(saved, mode)

        absent = [
            str(path.relative_to(root))
            for path, (original, _) in snapshots.items()
            if original is None
        ]

        (backup_dir / "new_files.json").write_text(
            json.dumps(absent, indent=2),
            encoding="utf-8",
        )

    except Exception as error:
        return {
            "success": False,
            "rolled_back": True,
            "rollback_status": "NOT_NEEDED",
            "error": str(error),
        }

    try:
        for target, (content, mode) in prepared.items():
            target.parent.mkdir(parents=True, exist_ok=True)

            fd, temp_name = tempfile.mkstemp(
                prefix=".iao-padge-",
                dir=str(target.parent),
            )

            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(content)

                os.chmod(temp_name, mode)
                replace_fn(temp_name, target)

            finally:
                if os.path.exists(temp_name):
                    os.unlink(temp_name)

        for target, (content, _) in prepared.items():
            if target.read_bytes() != content:
                raise RuntimeError(
                    "POST_PROMOTION_CONTENT_MISMATCH: " + str(target)
                )

        return {
            "success": True,
            "rolled_back": False,
            "rollback_status": "NOT_REQUIRED",
            "files": len(prepared),
            "backup": str(backup_dir),
        }

    except Exception as error:
        restore_errors = []

        for target, (original, mode) in snapshots.items():
            try:
                if original is None:
                    target.unlink(missing_ok=True)
                    if target.exists():
                        raise RuntimeError("NEW_FILE_NOT_REMOVED")
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)

                    fd, temp_name = tempfile.mkstemp(
                        prefix=".iao-restore-",
                        dir=str(target.parent),
                    )

                    try:
                        with os.fdopen(fd, "wb") as handle:
                            handle.write(original)

                        os.chmod(temp_name, mode)
                        os.replace(temp_name, target)

                    finally:
                        if os.path.exists(temp_name):
                            os.unlink(temp_name)

                    if target.read_bytes() != original:
                        raise RuntimeError("RESTORE_CONTENT_MISMATCH")

                    if (target.stat().st_mode & 0o7777) != mode:
                        raise RuntimeError("RESTORE_MODE_MISMATCH")

            except Exception as restore_error:
                restore_errors.append({
                    "file": str(target),
                    "error": str(restore_error),
                })

        return {
            "success": False,
            "rolled_back": not restore_errors,
            "rollback_status": (
                "VERIFIED" if not restore_errors else "FAILED"
            ),
            "error": str(error),
            "restore_errors": restore_errors,
            "backup": str(backup_dir),
        }


def build(plan):
    changes = validate(plan)
    if not changes:
        log("no_change", reason=plan.get("reason", "Sin mejora"))
        return "NO_CHANGE"

    identifier = datetime.now(timezone.utc).strftime(
        "%Y%m%dT%H%M%S%fZ"
    )
    stage = make_workspace(identifier)

    for name, content in changes.items():
        target = stage / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    # IAO V12: inspeccion estatica obligatoria antes de compilar.
    # Solo se examinan los archivos Python incluidos en este candidato.
    python_candidates = [
        str(stage / name)
        for name in changes
        if str(name).endswith(".py")
    ]

    if python_candidates:
        try:
            stage.resolve().relative_to(ROOT.resolve())
            if not (ROOT / "tools/iao_v12_preflight.py").is_file():
                raise RuntimeError("PREFLIGHT_COMPONENT_MISSING")

            preflight_result = run(
                [
                    sys.executable,
                    str(ROOT / "tools/iao_v12_preflight.py"),
                    *python_candidates,
                ],
                cwd=ROOT,
            )
        except Exception as exc:
            log(
                "candidate_preflight_error",
                version=identifier,
                error=repr(exc),
                files=[str(name) for name in changes],
            )
            return "PREFLIGHT_ERROR"

        preflight_output = (preflight_result.stdout or "")[-12000:]
        preflight_error = (preflight_result.stderr or "")[-6000:]

        if preflight_result.returncode != 0:
            log(
                "candidate_preflight_rejected",
                version=identifier,
                exit=preflight_result.returncode,
                output=preflight_output,
                error=preflight_error,
                files=[str(name) for name in changes],
            )
            return "PREFLIGHT_REJECTED"

        log(
            "candidate_preflight_passed",
            version=identifier,
            files=python_candidates,
            output=preflight_output,
        )
    else:
        log(
            "candidate_preflight_not_applicable",
            version=identifier,
            reason="NO_PYTHON_FILES_IN_CANDIDATE",
        )

    compile_result = run(
        [sys.executable, "-m", "compileall", "-q", "omega", "tools"],
        cwd=stage,
    )
    if compile_result.returncode:
        log("candidate_compile_rejected",
            error=compile_result.stderr[-6000:])
        return "COMPILE_REJECTED"

    log("baseline_tests_started")
    baseline = pytest_result(ROOT)
    log("baseline_tests_finished",
        exit=baseline["exit"],
        failed=baseline["failed"],
        errors=baseline["errors"],
        passed=baseline["passed"])

    log("candidate_tests_started")
    candidate = pytest_result(stage)
    log("candidate_tests_finished",
        exit=candidate["exit"],
        failed=candidate["failed"],
        errors=candidate["errors"],
        passed=candidate["passed"])

    # Gate determinista: el candidato debe terminar pytest correctamente.
    # No se promueven resultados incompletos ni pruebas omitidas adicionales.
    rejection_reasons = []

    if candidate["exit"] != 0:
        rejection_reasons.append("CANDIDATE_PYTEST_EXIT_NONZERO")

    if candidate["failed"] > baseline["failed"]:
        rejection_reasons.append("FAILED_TESTS_INCREASED")

    if candidate["errors"] > baseline["errors"]:
        rejection_reasons.append("TEST_ERRORS_INCREASED")

    if candidate["passed"] < baseline["passed"]:
        rejection_reasons.append("PASSED_TESTS_DECREASED")

    if candidate["skipped"] > baseline["skipped"]:
        rejection_reasons.append("SKIPPED_TESTS_INCREASED")

    if rejection_reasons:
        log(
            "candidate_rejected",
            reason=";".join(rejection_reasons),
            baseline={
                k: baseline[k]
                for k in ("exit", "passed", "failed", "errors", "skipped")
            },
            candidate={
                k: candidate[k]
                for k in ("exit", "passed", "failed", "errors", "skipped")
            },
        )
        return "TESTS_REJECTED"

    # Guardar la versión candidata y respaldar los archivos originales.
    version = VERSIONS / identifier
    version.mkdir(parents=True)
    backup_dir = version / "previous"
    backup_dir.mkdir()

    for name in changes:
        original = ROOT / name
        if original.exists():
            old = backup_dir / name
            old.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(original, old)

    manifest = {
        "id": identifier,
        "time": utc(),
        "goal": plan.get("goal"),
        "reason": plan.get("reason"),
        "files": list(changes),
        "baseline": {k: baseline[k] for k in
                     ("passed", "failed", "errors", "skipped")},
        "candidate": {k: candidate[k] for k in
                      ("passed", "failed", "errors", "skipped")},
        "status": "VALIDATED_CANDIDATE",
        "promotion": "PENDING_AUTHORITY_AND_POLICY",
    }

    for name in changes:
        source = stage / name
        target = version / "candidate" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)

    (version / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False)
    )
    (REPORTS / f"{identifier}.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False)
    )

    # Primera barrera: autorización central por componente.
    from omega.autonomous_authority import authorize

    authority = authorize(
        "PADGE",
        "CODE_IMPROVEMENT",
        "CODE_IMPROVEMENT",
    )

    if not isinstance(authority, dict) or authority.get("approved") is not True:
        manifest["status"] = "AUTHORITY_REJECTED"
        manifest["promotion"] = "DENIED"
        manifest["authority"] = authority
        (version / "manifest.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False)
        )
        (REPORTS / f"{identifier}.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False)
        )
        log(
            "central_authority_rejected",
            version=identifier,
            decision=authority,
        )
        return "AUTHORITY_REJECTED"

    log(
        "central_authority_approved",
        version=identifier,
        reason=authority.get("reason"),
    )

    # Segunda barrera: política determinista independiente de PADGE.
    from omega.padge_autonomy_policy import evaluate_candidate

    decision = evaluate_candidate(changes, candidate)

    if not decision.get("approved"):
        manifest["status"] = "POLICY_REJECTED"
        manifest["promotion"] = "DENIED"
        manifest["policy"] = decision
        (version / "manifest.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False)
        )
        (REPORTS / f"{identifier}.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False)
        )
        log(
            "autonomous_promotion_rejected",
            version=identifier,
            reason=decision.get("reason"),
            details=decision,
        )
        return "AUTONOMOUS_POLICY_REJECTED"

    # La suite debe estar completamente limpia.
    if (
        candidate["exit"] != 0
        or candidate["failed"] != 0
        or candidate["errors"] != 0
    ):
        manifest["status"] = "TESTS_REJECTED"
        manifest["promotion"] = "DENIED"
        log(
            "candidate_promotion_blocked_tests",
            version=identifier,
            failed=candidate["failed"],
            errors=candidate["errors"],
        )
        return "PROMOTION_BLOCKED_TESTS_NOT_CLEAN"

    # Tercera etapa: promoción transaccional con restauración verificable.
    promotion = _promote_transactionally(
        changes,
        version / "candidate",
        backup_dir,
        root=ROOT,
    )

    manifest["authority"] = authority
    manifest["policy"] = decision
    manifest["promotion_result"] = promotion

    if promotion["success"]:
        # Verificacion posterior sobre el repositorio ya modificado.
        post_error = None
        try:
            post = pytest_result(ROOT)
        except Exception as exc:
            post_error = repr(exc)
            post = {
                "exit": -1,
                "failed": 0,
                "errors": 1,
                "passed": 0,
                "skipped": 0,
            }

        manifest["post_promotion_tests"] = post
        manifest["post_promotion_test_error"] = post_error

        post_ok = (
            post["exit"] == 0
            and post["failed"] == 0
            and post["errors"] == 0
            and post["passed"] >= candidate["passed"]
            and post["skipped"] <= candidate["skipped"]
        )

        if post_ok:
            manifest["status"] = "PROMOTED_AND_POST_VERIFIED"
            manifest["promotion"] = "APPLIED_POST_TESTS_PASSED"

            log(
                "post_promotion_tests_passed",
                version=identifier,
                results=post,
            )
            log(
                "candidate_promoted_to_worktree",
                version=identifier,
                files=list(changes),
                backup=promotion.get("backup"),
            )
            result = "APPLIED_AND_POST_VERIFIED"

        else:
            log(
                "post_promotion_tests_failed",
                version=identifier,
                results=post,
                action="RESTORE_PREVIOUS_FILES",
            )

            restore_errors = []

            # Restaurar los originales; eliminar archivos que antes no existían.
            for name in changes:
                target = ROOT / name
                saved = backup_dir / name

                try:
                    if saved.is_file():
                        target.parent.mkdir(parents=True, exist_ok=True)

                        fd, temp_name = tempfile.mkstemp(
                            prefix=".iao-post-restore-",
                            dir=str(target.parent),
                        )
                        os.close(fd)

                        try:
                            shutil.copy2(saved, temp_name)
                            os.replace(temp_name, target)
                        finally:
                            if os.path.exists(temp_name):
                                os.unlink(temp_name)

                        if target.read_bytes() != saved.read_bytes():
                            raise RuntimeError("RESTORE_CONTENT_MISMATCH")

                        expected_mode = saved.stat().st_mode & 0o7777
                        actual_mode = target.stat().st_mode & 0o7777

                        if actual_mode != expected_mode:
                            raise RuntimeError("RESTORE_MODE_MISMATCH")

                    else:
                        target.unlink(missing_ok=True)

                        if target.exists():
                            raise RuntimeError("NEW_FILE_NOT_REMOVED")

                except Exception as exc:
                    restore_errors.append({
                        "file": name,
                        "error": repr(exc),
                    })

            rollback_tests = None

            if not restore_errors:
                try:
                    rollback_tests = pytest_result(ROOT)

                    baseline_restored = (
                        rollback_tests["exit"] == baseline["exit"]
                        and rollback_tests["failed"] <= baseline["failed"]
                        and rollback_tests["errors"] <= baseline["errors"]
                        and rollback_tests["passed"] >= baseline["passed"]
                        and rollback_tests["skipped"] <= baseline["skipped"]
                    )

                    if not baseline_restored:
                        restore_errors.append({
                            "error": "POST_ROLLBACK_TESTS_DID_NOT_MATCH_BASELINE",
                        })

                except Exception as exc:
                    restore_errors.append({
                        "error": "POST_ROLLBACK_TEST_EXECUTION_FAILED",
                        "details": repr(exc),
                    })

            rollback_verified = not restore_errors

            manifest["post_promotion_rollback"] = {
                "verified": rollback_verified,
                "restore_errors": restore_errors,
                "tests": rollback_tests,
            }

            if rollback_verified:
                manifest["status"] = "POST_PROMOTION_FAILED_ROLLED_BACK"
                manifest["promotion"] = "ROLLED_BACK_AND_POST_VERIFIED"

                log(
                    "candidate_post_promotion_rolled_back",
                    version=identifier,
                    post_tests=post,
                    rollback_tests=rollback_tests,
                )
                result = "POST_PROMOTION_FAILED_ROLLED_BACK"

            else:
                manifest["status"] = "CRITICAL_ROLLBACK_FAILURE"
                manifest["promotion"] = "ROLLBACK_FAILED"

                log(
                    "candidate_rollback_failed",
                    version=identifier,
                    errors=restore_errors,
                    post_tests=post,
                )
                result = "CRITICAL_ROLLBACK_FAILURE"

    elif promotion["rollback_status"] == "NOT_NEEDED":
        manifest["status"] = "PROMOTION_REJECTED_NO_MUTATION"
        manifest["promotion"] = "NOT_APPLIED_NO_MUTATION"
        log(
            "candidate_promotion_rejected_before_mutation",
            version=identifier,
            error=promotion.get("error"),
            rollback_status="NOT_NEEDED",
        )
        result = "PROMOTION_REJECTED_NO_MUTATION"
    elif promotion["rollback_status"] == "VERIFIED":
        manifest["status"] = "PROMOTION_FAILED_ROLLED_BACK"
        manifest["promotion"] = "ROLLED_BACK_AND_VERIFIED"
        log(
            "candidate_promotion_rolled_back",
            version=identifier,
            error=promotion.get("error"),
        )
        result = "PROMOTION_FAILED_ROLLED_BACK"

    else:
        manifest["status"] = "CRITICAL_ROLLBACK_FAILURE"
        manifest["promotion"] = "ROLLBACK_FAILED"
        log(
            "candidate_rollback_failed",
            version=identifier,
            details=promotion,
        )
        result = "CRITICAL_ROLLBACK_FAILURE"

    (version / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False)
    )
    (REPORTS / f"{identifier}.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False)
    )

    return result



def cycle():
    snapshot = inspect()
    (STATE / "last-inspection.json").write_text(
        json.dumps(snapshot, indent=2, ensure_ascii=False)
    )
    log(
        "inspection_complete",
        branch=snapshot["branch"],
        commit=snapshot["commit"],
        files=len(snapshot["files"]),
    )

    plan = ask_iao(snapshot)
    (STATE / "last-plan.json").write_text(
        json.dumps(plan, indent=2, ensure_ascii=False)
    )
    log("plan_received", goal=plan.get("goal"))

    try:
        return build(plan)
    except ValueError as exc:
        reason = str(exc)
        if reason.startswith("Archivo protegido:"):
            match = re.search(
                r"Archivo protegido:\s*([A-Za-z0-9_./-]+)",
                reason,
            )
            paths = [match.group(1)] if match else []
            log(
                "policy_blocked",
                goal=plan.get("goal", "sin objetivo"),
                reason=reason,
                paths=paths,
                action="SELECT_DIFFERENT_MISSION",
            )
            return {
                "status": "POLICY_BLOCKED",
                "goal": plan.get("goal"),
                "reason": reason,
            }

        if reason.startswith("Propuesta bloqueada recientemente:"):
            paths = [
                item.strip()
                for item in reason.split(":", 1)[1].split(",")
                if item.strip()
            ]
            log(
                "proposal_deferred",
                goal=plan.get("goal", "sin objetivo"),
                reason=reason,
                paths=paths,
                action="SELECT_DIFFERENT_MISSION",
            )
            return {
                "status": "PROPOSAL_DEFERRED",
                "goal": plan.get("goal"),
                "reason": reason,
            }

        raise


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "once"

    if mode == "status":
        reports = sorted(REPORTS.glob("*.json"))
        print(json.dumps({
            "component": "PADGE",
            "responsibility": "IAO autonomous programming",
            "candidate_reports": len(reports),
            "latest": [p.name for p in reports[-10:]],
            "state": str(STATE),
        }, indent=2))
        return 0

    if mode not in ("once", "loop"):
        raise SystemExit("Uso: python -m omega.padge once|loop|status")

    # PADGE_SINGLETON_LOCK_V1
    lock_file = (STATE / "instance.lock").open("a+")
    try:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        log("duplicate_instance_blocked", pid=__import__("os").getpid())
        return 0

    exit_code = 0
    while True:
        try:
            result = cycle()
            log("cycle_completed", result=result)
            exit_code = 0
        except KeyboardInterrupt:
            log("stopped_by_operator")
            break
        except Exception as exc:
            log("cycle_error", error=repr(exc),
                traceback=traceback.format_exc()[-5000:])
            exit_code = 1

        if mode == "once":
            break
        time.sleep(300)

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
