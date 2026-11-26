#!/usr/bin/env python3
"""Build a sanitized, reproducible IAO source bundle for an independent node."""
import os, sys, json, tarfile, hashlib
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / ".state" / "releases"
STAMP = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
NAME = f"iao-external-node-{STAMP}"
STAGE = OUT / NAME
ARCHIVE = OUT / f"{NAME}.tar.gz"

EXCLUDED_DIRS = {
    ".git", ".state", ".venv", "venv", "__pycache__", "node_modules",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", "backups", "logs",
    "dist", "build"
}
EXCLUDED_SUFFIXES = {
    ".pem", ".key", ".p12", ".pfx", ".db", ".sqlite", ".sqlite3",
    ".pyc", ".log", ".sock"
}
EXCLUDED_NAMES = {
    ".env", ".env.local", ".env.production", "id_rsa", "id_ed25519",
    "authorized_keys", "known_hosts"
}
ROOT_FILES = {
    "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt",
    "requirements-prod.txt", "Pipfile", "Pipfile.lock", "Dockerfile",
    "README.md", "LICENSE", "Makefile"
}
SOURCE_DIRS = ("omega", "tools", "docs")

def safe_file(path):
    rel = path.relative_to(ROOT)
    parts = rel.parts
    if any(p in EXCLUDED_DIRS or p.startswith(".") for p in parts):
        return False
    if path.name in EXCLUDED_NAMES or path.suffix.lower() in EXCLUDED_SUFFIXES:
        return False
    low = str(rel).lower()
    if any(x in low for x in ("secret", "credential", "private-key", "token-store")):
        return False
    if path.is_symlink() or not path.is_file():
        return False
    return True

files = []
for dirname in SOURCE_DIRS:
    base = ROOT / dirname
    if not base.is_dir():
        continue
    for parent, dirs, names in os.walk(base):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED_DIRS and not d.startswith("."))
        for name in sorted(names):
            p = Path(parent) / name
            if safe_file(p):
                files.append(p)

for name in ROOT_FILES:
    p = ROOT / name
    if p.exists() and safe_file(p):
        files.append(p)

files = sorted(set(files))
if not files:
    raise SystemExit("ERROR: no se encontraron fuentes para empaquetar")
if len(files) > 12000:
    raise SystemExit("ERROR: límite de archivos superado")
total = sum(p.stat().st_size for p in files)
if total > 150 * 1024 * 1024:
    raise SystemExit("ERROR: fuentes superan 150 MiB")

STAGE.mkdir(parents=True, exist_ok=False)
manifest = []
for src in files:
    rel = src.relative_to(ROOT)
    dst = STAGE / rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    data = src.read_bytes()
    dst.write_bytes(data)
    try:
        dst.chmod(src.stat().st_mode & 0o755)
    except OSError:
        pass
    manifest.append({
        "path": str(rel),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest()
    })

meta = {
    "bundle": NAME,
    "created_at": datetime.now(timezone.utc).isoformat(),
    "source_files": len(manifest),
    "source_bytes": total,
    "identity_policy": "A new external node MUST generate its own identity",
    "runtime_state_included": False,
    "secrets_included": False,
    "peer_authorization_included": False,
    "files": manifest
}
(STAGE / "BUNDLE-MANIFEST.json").write_text(
    json.dumps(meta, indent=2) + "\n", encoding="utf-8"
)
(STAGE / "EXTERNAL-NODE-NOTES.txt").write_text(
"""IAO — DISTRIBUCIÓN DE CÓDIGO PARA NODO EXTERNO

Este paquete contiene código fuente; NO es todavía un nodo federado activo.

Antes de producción:
1. Instalar Python y dependencias según los archivos de proyecto incluidos.
2. Crear un directorio de estado NUEVO para esta instancia.
3. Generar una identidad criptográfica NUEVA en el nodo externo.
4. Configurar su propio almacén de peers y claves; nunca copiar los del teléfono.
5. Publicar el FedServer mediante HTTPS o un relay P2P.
6. Verificar identidad, handshake y mensajes desde ambos extremos.
7. Autorizar capacidades explícitamente y limitar recursos.

No contiene .env, claves privadas, bases de datos, tokens, almacenes de peers
ni el estado runtime del teléfono. Revisar el manifiesto antes de desplegar.
No ejecutar como root si no es imprescindible.
""", encoding="utf-8"
)

with tarfile.open(ARCHIVE, "w:gz") as tar:
    tar.add(STAGE, arcname=NAME)

digest = hashlib.sha256(ARCHIVE.read_bytes()).hexdigest()
print("BUNDLE_CREATED=" + str(ARCHIVE.relative_to(ROOT)))
print("BUNDLE_SHA256=" + digest)
print("SOURCE_FILES=" + str(len(files)))
print("SOURCE_BYTES=" + str(total))
print("RUNTIME_STATE_INCLUDED=NO")
print("SECRETS_INCLUDED=NO")
print("PEER_AUTHORIZATION_INCLUDED=NO")
print("NEXT_STEP=VERIFY_EXTERNAL_DEPLOYMENT_CONTRACT")
