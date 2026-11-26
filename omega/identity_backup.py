"""Fail-closed paired snapshots for the operator identity SQLite databases.

This module creates and verifies offline backup pairs. It deliberately does not
install snapshots over live databases: rollback protection requires an
independent monotonic trust anchor and an operator-controlled restore procedure.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import sqlite3
import stat
import tempfile
from pathlib import Path
from typing import Any


FORMAT_VERSION = 1
IDENTITY_BACKUP_NAME = "operator-identity.sqlite3"
DEVICE_BACKUP_NAME = "device-authority.sqlite3"
MANIFEST_NAME = "manifest.json"


class IdentityBackupError(RuntimeError):
    """Stable error code for a rejected backup operation."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _integrity_check(path: Path) -> None:
    try:
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10) as db:
            result = db.execute("PRAGMA integrity_check").fetchone()
        if result != ("ok",):
            raise IdentityBackupError("IDENTITY_BACKUP_INTEGRITY_FAILED")
    except sqlite3.DatabaseError:
        raise IdentityBackupError("IDENTITY_BACKUP_INTEGRITY_FAILED") from None


def _snapshot(source: Path, destination: Path) -> None:
    if source.is_symlink() or not source.is_file():
        raise IdentityBackupError("IDENTITY_BACKUP_SOURCE_INVALID")
    try:
        with sqlite3.connect(f"file:{source}?mode=ro", uri=True, timeout=10) as src:
            with sqlite3.connect(destination, timeout=10) as dst:
                src.backup(dst, pages=256, sleep=0.05)
                dst.execute("PRAGMA journal_mode=DELETE")
                dst.commit()
        os.chmod(destination, 0o600)
        _integrity_check(destination)
    except sqlite3.DatabaseError:
        raise IdentityBackupError("IDENTITY_BACKUP_SNAPSHOT_FAILED") from None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _paired_state(identity_path: Path, device_path: Path) -> dict[str, Any]:
    _integrity_check(identity_path)
    _integrity_check(device_path)
    try:
        with sqlite3.connect(f"file:{identity_path}?mode=ro", uri=True) as identity:
            identity.row_factory = sqlite3.Row
            roots = identity.execute(
                "SELECT identity_id,root_public_key_pem,key_version FROM operator_identities WHERE status='ACTIVE'"
            ).fetchall()
            if len(roots) != 1:
                raise IdentityBackupError("IDENTITY_BACKUP_AUTHORITY_STATE_INVALID")
            root = roots[0]
            bindings = identity.execute(
                "SELECT device_id,device_public_key_pem,key_version FROM primary_device_bindings WHERE identity_id=?",
                (root["identity_id"],),
            ).fetchall()
            if len(bindings) != 1 or bindings[0]["key_version"] != root["key_version"]:
                raise IdentityBackupError("IDENTITY_BACKUP_AUTHORITY_STATE_INVALID")
        with sqlite3.connect(f"file:{device_path}?mode=ro", uri=True) as device:
            device.row_factory = sqlite3.Row
            active = device.execute(
                "SELECT public_key_pem FROM devices WHERE active=1"
            ).fetchall()
            if len(active) != 1 or active[0]["public_key_pem"] != bindings[0]["device_public_key_pem"]:
                raise IdentityBackupError("IDENTITY_BACKUP_PAIR_MISMATCH")
        return {"root_key_version": int(root["key_version"]), "paired": True}
    except IdentityBackupError:
        raise
    except (sqlite3.DatabaseError, KeyError, TypeError):
        raise IdentityBackupError("IDENTITY_BACKUP_AUTHORITY_STATE_INVALID") from None


def create_identity_backup(
    identity_database: str | Path,
    device_database: str | Path,
    destination: str | Path,
) -> dict[str, Any]:
    """Create a private, integrity-checked pair; refuse overwrite and mismatched states."""
    identity_source, device_source = Path(identity_database), Path(device_database)
    target = Path(destination)
    if target.exists() or target.is_symlink():
        raise IdentityBackupError("IDENTITY_BACKUP_DESTINATION_EXISTS")
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if parent.is_symlink():
        raise IdentityBackupError("IDENTITY_BACKUP_PATH_INVALID")
    os.chmod(parent, 0o700)
    staging = Path(tempfile.mkdtemp(prefix=".iao-identity-backup-", dir=parent))
    os.chmod(staging, 0o700)
    try:
        identity_copy = staging / IDENTITY_BACKUP_NAME
        device_copy = staging / DEVICE_BACKUP_NAME
        _snapshot(identity_source, identity_copy)
        _snapshot(device_source, device_copy)
        state = _paired_state(identity_copy, device_copy)
        manifest = {
            "format_version": FORMAT_VERSION,
            "identity_database": {"file": IDENTITY_BACKUP_NAME, "sha256": _sha256(identity_copy)},
            "device_database": {"file": DEVICE_BACKUP_NAME, "sha256": _sha256(device_copy)},
            "state": state,
        }
        manifest_path = staging / MANIFEST_NAME
        manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        os.chmod(manifest_path, 0o600)
        os.replace(staging, target)
        return {"created": True, "format_version": FORMAT_VERSION, "root_key_version": state["root_key_version"]}
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def verify_identity_backup(backup_directory: str | Path) -> dict[str, Any]:
    """Verify checksums, SQLite integrity and cross-database primary-key agreement."""
    root = Path(backup_directory)
    if root.is_symlink() or not root.is_dir():
        raise IdentityBackupError("IDENTITY_BACKUP_PATH_INVALID")
    manifest_path = root / MANIFEST_NAME
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise IdentityBackupError("IDENTITY_BACKUP_MANIFEST_INVALID")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("format_version") != FORMAT_VERSION:
            raise IdentityBackupError("IDENTITY_BACKUP_FORMAT_UNSUPPORTED")
        files = (
            (IDENTITY_BACKUP_NAME, manifest["identity_database"]["sha256"]),
            (DEVICE_BACKUP_NAME, manifest["device_database"]["sha256"]),
        )
        for filename, expected in files:
            path = root / filename
            if path.is_symlink() or not path.is_file() or not isinstance(expected, str):
                raise IdentityBackupError("IDENTITY_BACKUP_MANIFEST_INVALID")
            if not hmac.compare_digest(_sha256(path), expected):
                raise IdentityBackupError("IDENTITY_BACKUP_CHECKSUM_MISMATCH")
        state = _paired_state(root / IDENTITY_BACKUP_NAME, root / DEVICE_BACKUP_NAME)
        if manifest.get("state") != state:
            raise IdentityBackupError("IDENTITY_BACKUP_MANIFEST_STATE_MISMATCH")
        return {"valid": True, "root_key_version": state["root_key_version"], "paired": True}
    except IdentityBackupError:
        raise
    except (OSError, ValueError, KeyError, TypeError):
        raise IdentityBackupError("IDENTITY_BACKUP_MANIFEST_INVALID") from None
