"""Autoridad autónoma central de IAO.

Autoriza automáticamente operaciones internas reversibles.
Las operaciones críticas permanecen protegidas.
"""

import os
import json
import time
import hashlib
import pathlib
import subprocess
import uuid
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
STATE = ROOT / ".state" / "iao-authority"
BACKUPS = STATE / "backups"
AUDIT = STATE / "audit" / "authority.jsonl"

STATE.mkdir(parents=True, exist_ok=True)
BACKUPS.mkdir(parents=True, exist_ok=True)

# Permisos internos de IAO.
AUTO_APPROVE = {
    "READ_ONLY",
    "REVERSIBLE",
    "CODE_IMPROVEMENT",
    "TESTING",
    "INTERNAL_COORDINATION",
    "TASK_CREATION",
    "RECOVERY",
    "LLM_REQUEST",
    "INTERNAL_INTEGRATION",
}

# Nunca conceder autoridad automática sobre estas operaciones.
PROTECTED = {
    "SECURITY_CRITICAL",
    "CREDENTIAL_ACCESS",
    "SECRET_EXPORT",
    "ADMIN_AUTHORITY",
    "EXTERNAL_DEPLOYMENT",
    "DESTRUCTIVE",
    "IRREVERSIBLE",
}

PROTECTED_PATHS = (
    ".env",
    ".git/",
    ".github/workflows/",
    "secrets/",
    "credentials/",
    "keys/",
    "certificates/",
    "omega/policy_gate.py",
    "omega/autonomous_authority.py",
)

def audit(event, **details):
    record = {
        "timestamp": time.time(),
        "event": event,
        **details
    }
    with AUDIT.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


COMPONENT_POLICY = {
 "PADGE":{"CODE_IMPROVEMENT":{"CODE_IMPROVEMENT"},"TESTING":{"TESTING"},"READ_ONLY":{"READ_ONLY"}},
 "AUTOBUILDER":{"TESTING":{"TESTING"},"READ_ONLY":{"READ_ONLY"}},
 "AUTOCONSTRUCTION":{"TESTING":{"TESTING"},"READ_ONLY":{"READ_ONLY"}},
 "AUTONOMY":{"READ_ONLY":{"READ_ONLY"},"TESTING":{"TESTING"},"INTERNAL_COORDINATION":{"INTERNAL_COORDINATION"},"TASK_CREATION":{"TASK_CREATION"},"RECOVERY":{"RECOVERY"}},
 "WORKERS":{"READ_ONLY":{"READ_ONLY"},"TESTING":{"TESTING"},"INTERNAL_COORDINATION":{"INTERNAL_COORDINATION"},"TASK_CREATION":{"TASK_CREATION"},"RECOVERY":{"RECOVERY"}},
 "MULTI_LLM":{"LLM_REQUEST":{"LLM_REQUEST"}},
 "GUARDIAN":{"READ_ONLY":{"READ_ONLY"},"RECOVERY":{"RECOVERY"}},
 "FEDERATION":{"READ_ONLY":{"READ_ONLY"},"INTERNAL_COORDINATION":{"INTERNAL_COORDINATION"}},
 "RUNTIME":{"READ_ONLY":{"READ_ONLY"},"INTERNAL_COORDINATION":{"INTERNAL_COORDINATION"}},
 "CONTROL_PLANE":{"READ_ONLY":{"READ_ONLY"},"TESTING":{"TESTING"},"INTERNAL_COORDINATION":{"INTERNAL_COORDINATION"}},
}
def authorize(component, operation, risk="REVERSIBLE"):
    component = str(component).strip().upper()
    operation = str(operation).strip().upper()
    risk = str(risk).strip().upper()
    if risk in PROTECTED or operation in PROTECTED:
        audit("AUTHORIZATION_DENIED", component=component, operation=operation, risk=risk)
        return {"approved":False,"reason":"PROTECTED_OPERATION","administrator_required":True}
    permitted = COMPONENT_POLICY.get(component, {}).get(operation, set())
    if risk in permitted:
        audit("AUTO_APPROVED", component=component, operation=operation, risk=risk)
        return {"approved":True,"mode":"AUTOMATIC","reason":"EXPLICIT_COMPONENT_POLICY"}
    audit("AUTHORIZATION_DENIED", component=component, operation=operation, risk=risk)
    return {"approved":False,"reason":"COMPONENT_POLICY_DENIED","administrator_required":False}

def safe_path(name):
    p = pathlib.PurePosixPath(str(name))

    if p.is_absolute() or ".." in p.parts:
        raise PermissionError("Ruta no permitida")

    if not p.parts or p.parts[0] not in ("omega", "tools"):
        raise PermissionError("Solo código interno omega/ y tools/")

    normalized = p.as_posix()

    for protected in PROTECTED_PATHS:
        if normalized == protected or normalized.startswith(protected):
            raise PermissionError("Archivo protegido")

    target = ROOT / normalized

    if target.is_symlink():
        raise PermissionError("No se permiten enlaces simbólicos")

    parent = target.parent
    while parent != ROOT and parent != parent.parent:
        if parent.is_symlink():
            raise PermissionError("Directorio con enlace simbólico")
        parent = parent.parent

    return target

def apply_code(component, changes):
    """Aplica un conjunto de archivos Python con validación y rollback.

    changes = {"omega/modulo.py": "contenido Python"}
    """

    if not isinstance(changes, dict) or not changes:
        raise ValueError("No hay cambios de código")

    decision = authorize(
        component,
        "CODE_IMPROVEMENT",
        "CODE_IMPROVEMENT"
    )

    if not decision["approved"]:
        raise PermissionError("Mejora no autorizada")

    if len(changes) > 20:
        raise ValueError("Máximo 20 archivos por ciclo")

    prepared = {}
    total_size = 0

    for name, content in changes.items():
        target = safe_path(name)

        if target.suffix != ".py":
            raise PermissionError("Solo archivos Python")

        if not isinstance(content, str):
            raise ValueError("Contenido inválido")

        total_size += len(content.encode("utf-8"))

        if total_size > 500_000:
            raise ValueError("Límite de tamaño excedido")

        prepared[target] = content

    backup_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
    backup_dir = BACKUPS / backup_id
    backup_dir.mkdir(parents=True)

    originals = {}
    modes = {}

    for target in prepared:
        relative = target.relative_to(ROOT)
        if target.exists():
            originals[target] = target.read_bytes()
            modes[target] = target.stat().st_mode
            dest = backup_dir / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(originals[target])
        else:
            originals[target] = None
            modes[target] = 0o644

    audit(
        "CODE_CHANGE_STARTED",
        component=component,
        files=[str(p.relative_to(ROOT)) for p in prepared],
        backup=backup_id
    )

    try:
        for target, content in prepared.items():
            target.parent.mkdir(parents=True, exist_ok=True)

            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=target.parent,
                delete=False
            ) as tmp:
                tmp.write(content)
                temp_name = tmp.name

            os.chmod(temp_name, modes[target])
            os.replace(temp_name, target)

        result = subprocess.run(
            [os.sys.executable, "-m", "compileall", "-q",
             "omega", "tools"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=180
        )

        if result.returncode != 0:
            raise RuntimeError("Falló compilación: " + result.stderr[-2000:])

        # Validación de pruebas.
        tests = ROOT / "tests"
        if tests.is_dir():
            result = subprocess.run(
                [os.sys.executable, "-m", "pytest", "-q", "tests"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=900
            )

            if result.returncode != 0:
                raise RuntimeError(
                    "Fallaron pruebas: " +
                    (result.stdout + result.stderr)[-3000:]
                )

        audit(
            "CODE_CHANGE_APPROVED_AND_APPLIED",
            component=component,
            backup=backup_id
        )

        return {
            "success": True,
            "backup": backup_id,
            "files": len(prepared),
            "validation": "PASSED"
        }

    except Exception as error:
        restore_errors = []

        for target, original in originals.items():
            try:
                if original is None:
                    target.unlink(missing_ok=True)
                    if target.exists():
                        raise RuntimeError("El archivo nuevo sigue existiendo")
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)

                    with tempfile.NamedTemporaryFile(
                        mode="wb",
                        dir=target.parent,
                        delete=False
                    ) as tmp:
                        tmp.write(original)
                        temp_name = tmp.name

                    os.chmod(temp_name, modes[target])
                    os.replace(temp_name, target)

                    restored = target.read_bytes()
                    restored_mode = target.stat().st_mode

                    if restored != original:
                        raise RuntimeError("El contenido restaurado no coincide")

                    if (restored_mode & 0o7777) != (modes[target] & 0o7777):
                        raise RuntimeError("Los permisos restaurados no coinciden")

            except Exception as restore_error:
                restore_errors.append({
                    "file": str(target),
                    "error": str(restore_error)
                })
                audit(
                    "ROLLBACK_ERROR",
                    file=str(target),
                    error=str(restore_error)
                )

        rollback_ok = not restore_errors

        audit(
            "CODE_CHANGE_ROLLED_BACK" if rollback_ok
            else "CODE_CHANGE_ROLLBACK_FAILED",
            component=component,
            backup=backup_id,
            error=str(error),
            restore_errors=restore_errors
        )

        return {
            "success": False,
            "rolled_back": rollback_ok,
            "rollback_status": "VERIFIED" if rollback_ok else "FAILED",
            "backup": backup_id,
            "error": str(error),
            "restore_errors": restore_errors
        }

def request_task(component, kind, description, payload=None):
    decision = authorize(component, kind, "INTERNAL_COORDINATION")

    if not decision["approved"]:
        raise PermissionError("Tarea no autorizada")

    try:
        from omega.continuous_autonomy import submit_task
        task_id = submit_task(
            component,
            kind,
            description,
            payload or {},
            priority=7
        )
        audit(
            "TASK_SUBMITTED",
            component=component,
            task_id=task_id,
            kind=kind
        )
        return task_id

    except ImportError:
        audit("TASK_API_UNAVAILABLE", component=component)
        raise

def request_llm(component, prompt, payload=None):
    """Solicita generación al enrutador mediante la cola compartida."""
    return request_task(
        component,
        "llm_request",
        prompt,
        payload
    )

def component_permissions():
    return {
        name: sorted(AUTO_APPROVE)
        for name in (
            "RUNTIME", "PADGE", "AUTOBUILDER",
            "AUTOCONSTRUCTION", "AUTONOMY",
            "WORKERS", "FEDERATION", "GUARDIAN",
            "MULTI_LLM", "CONTROL_PLANE"
        )
    }

def status():
    return {
        "authority": "ACTIVE",
        "automatic_approval": sorted(AUTO_APPROVE),
        "protected_operations": sorted(PROTECTED),
        "components": component_permissions()
    }
def component_permissions():
    return {
        component: {
            operation: sorted(risks)
            for operation, risks in operations.items()
        }
        for component, operations in COMPONENT_POLICY.items()
    }


# IAO_PADGE_AUTONOMY_EXPANSION_V1
# Permisos internos automáticos para el ciclo autónomo de PADGE.
# No amplía permisos de seguridad, credenciales ni administración.
_iao_padge_internal_operations = (
    "INTERNAL_COORDINATION",
    "TASK_CREATION",
    "RECOVERY",
    "LLM_REQUEST",
    "INTERNAL_INTEGRATION",
)

_iao_padge_permissions = COMPONENT_POLICY.setdefault("PADGE", {})
for _iao_operation in _iao_padge_internal_operations:
    _iao_existing_risks = _iao_padge_permissions.get(_iao_operation, ())
    _iao_padge_permissions[_iao_operation] = (
        set(_iao_existing_risks or ()) | {_iao_operation}
    )
del _iao_operation, _iao_existing_risks, _iao_padge_permissions
