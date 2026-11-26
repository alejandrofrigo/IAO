"""Authenticated monotonic anchor for operator-identity backup rollback detection.

The anchor and its HMAC key must live outside both restorable SQLite databases
and outside every backup set. This primitive is deliberately not wired into
request authorization yet: callers must coordinate every identity mutation
with anchor advancement before claiming rollback enforcement.
"""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import stat
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any

ANCHOR_FORMAT_VERSION = 1
STATE_SCHEMA_VERSION = 1
MAC_DOMAIN = b"IAO-IDENTITY-ROLLBACK-ANCHOR-V1\x00"
STATE_DOMAIN = b"IAO-IDENTITY-ROLLBACK-STATE-V1\x00"
_KEY_BYTES = 32
_process_lock = threading.RLock()


class IdentityRollbackAnchorError(RuntimeError):
    """Stable, non-sensitive error code for anchor failures."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")


def _key_fingerprint(pem: str) -> str:
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_public_key(pem.encode("ascii"))
    der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def capture_identity_state(
    identity_database: str | Path, device_database: str | Path,
) -> dict[str, Any]:
    """Return a privacy-minimized digest of the complete identity/device ledger."""
    identity_path, device_path = Path(identity_database), Path(device_database)
    for path in (identity_path, device_path):
        if path.is_symlink() or not path.is_file():
            raise IdentityRollbackAnchorError("IDENTITY_ANCHOR_DATABASE_INVALID")
    try:
        with sqlite3.connect(f"file:{identity_path}?mode=ro", uri=True, timeout=10) as db:
            db.row_factory = sqlite3.Row
            roots = db.execute(
                "SELECT identity_id,root_public_key_pem,key_version,status "
                "FROM operator_identities ORDER BY identity_id"
            ).fetchall()
            bindings = db.execute(
                "SELECT identity_id,device_id,device_public_key_pem,key_version "
                "FROM primary_device_bindings ORDER BY identity_id"
            ).fetchall()
        with sqlite3.connect(f"file:{device_path}?mode=ro", uri=True, timeout=10) as db:
            db.row_factory = sqlite3.Row
            devices = db.execute(
                "SELECT device_id,public_key_pem,active FROM devices ORDER BY device_id"
            ).fetchall()
    except sqlite3.DatabaseError:
        raise IdentityRollbackAnchorError("IDENTITY_ANCHOR_DATABASE_INVALID") from None

    root_by_id = {row["identity_id"]: row for row in roots}
    binding_by_id = {row["identity_id"]: row for row in bindings}
    device_by_id = {row["device_id"]: row for row in devices}
    ledger_roots = []
    for row in roots:
        ledger_roots.append({
            "identity_tag": hashlib.sha256(row["identity_id"].encode("utf-8")).hexdigest(),
            "key_fingerprint": _key_fingerprint(row["root_public_key_pem"]),
            "key_version": int(row["key_version"]),
            "status": row["status"],
        })
    ledger_bindings = []
    for row in bindings:
        ledger_bindings.append({
            "identity_tag": hashlib.sha256(row["identity_id"].encode("utf-8")).hexdigest(),
            "device_tag": hashlib.sha256(row["device_id"].encode("utf-8")).hexdigest(),
            "key_fingerprint": _key_fingerprint(row["device_public_key_pem"]),
            "key_version": int(row["key_version"]),
        })
    ledger_devices = []
    for row in devices:
        ledger_devices.append({
            "device_tag": hashlib.sha256(row["device_id"].encode("utf-8")).hexdigest(),
            "key_fingerprint": _key_fingerprint(row["public_key_pem"]),
            "active": int(row["active"]),
        })

    active_roots = [row for row in roots if row["status"] == "ACTIVE"]
    active_devices = [row for row in devices if row["active"] == 1]
    if len(active_roots) > 1 or len(active_devices) > 1:
        raise IdentityRollbackAnchorError("IDENTITY_ANCHOR_AUTHORITY_STATE_INVALID")
    active_root = active_roots[0] if active_roots else None
    active_binding = binding_by_id.get(active_root["identity_id"]) if active_root else None
    active_device = active_devices[0] if active_devices else None
    if active_root and active_binding:
        if active_binding["key_version"] != active_root["key_version"]:
            raise IdentityRollbackAnchorError("IDENTITY_ANCHOR_AUTHORITY_STATE_INVALID")
        if active_device is None or active_device["device_id"] != active_binding["device_id"]:
            raise IdentityRollbackAnchorError("IDENTITY_ANCHOR_AUTHORITY_STATE_INVALID")
        if active_device["public_key_pem"] != active_binding["device_public_key_pem"]:
            raise IdentityRollbackAnchorError("IDENTITY_ANCHOR_AUTHORITY_STATE_INVALID")
    # A revoked/no-root state may retain an active device row because the
    # current revocation flow updates the root database only. Preserve that
    # orphaned device in the ledger; it is not paired with an active root and
    # must never be interpreted as an authorized primary device.

    ledger = {
        "roots": ledger_roots,
        "bindings": ledger_bindings,
        "devices": ledger_devices,
    }
    ledger_digest = hashlib.sha256(STATE_DOMAIN + _canonical(ledger)).hexdigest()
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "root_key_version": int(active_root["key_version"]) if active_root else 0,
        "root_fingerprint": _key_fingerprint(active_root["root_public_key_pem"]) if active_root else None,
        "primary_device_fingerprint": _key_fingerprint(active_binding["device_public_key_pem"]) if active_binding else None,
        "active_root_count": len(active_roots),
        "active_device_count": len(active_devices),
        "revoked_root_count": sum(row["status"] == "REVOKED" for row in roots),
        "inactive_device_count": sum(row["active"] == 0 for row in devices),
        "ledger_digest": ledger_digest,
    }


class IdentityRollbackAnchor:
    """HMAC-authenticated sequence stored separately from the SQLite pair."""

    def __init__(self, anchor_path: str | Path, key_path: str | Path) -> None:
        self.anchor_path = Path(anchor_path)
        self.key_path = Path(key_path)
        if self.anchor_path.resolve(strict=False) == self.key_path.resolve(strict=False):
            raise IdentityRollbackAnchorError("IDENTITY_ANCHOR_PATH_INVALID")
        if self.anchor_path.parent.resolve(strict=False) != self.key_path.parent.resolve(strict=False):
            # Keeping both in one private state directory simplifies durable
            # atomicity; they remain distinct files and outside backup sets.
            raise IdentityRollbackAnchorError("IDENTITY_ANCHOR_PATH_INVALID")
        self.parent = self.anchor_path.parent
        self.lock_path = self.parent / (self.anchor_path.name + ".lock")
        self._ensure_parent()

    def _ensure_parent(self) -> None:
        self.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.parent.is_symlink() or not self.parent.is_dir():
            raise IdentityRollbackAnchorError("IDENTITY_ANCHOR_PATH_INVALID")
        os.chmod(self.parent, 0o700)

    @contextmanager
    def _locked(self):
        with _process_lock:
            flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
            try:
                fd = os.open(self.lock_path, flags, 0o600)
            except OSError:
                raise IdentityRollbackAnchorError("IDENTITY_ANCHOR_LOCK_FAILED") from None
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise IdentityRollbackAnchorError("IDENTITY_ANCHOR_PATH_INVALID")
                os.fchmod(fd, 0o600)
                fcntl.flock(fd, fcntl.LOCK_EX)
                yield
            finally:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)

    def _read_key(self) -> bytes:
        if self.key_path.is_symlink() or not self.key_path.is_file():
            raise IdentityRollbackAnchorError("IDENTITY_ANCHOR_KEY_UNAVAILABLE")
        info = self.key_path.stat()
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise IdentityRollbackAnchorError("IDENTITY_ANCHOR_KEY_PERMISSIONS_INVALID")
        try:
            key = self.key_path.read_bytes()
        except OSError:
            raise IdentityRollbackAnchorError("IDENTITY_ANCHOR_KEY_UNAVAILABLE") from None
        if len(key) != _KEY_BYTES:
            raise IdentityRollbackAnchorError("IDENTITY_ANCHOR_KEY_INVALID")
        return key

    def _create_key(self) -> None:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.key_path, flags, 0o600)
        except FileExistsError:
            raise IdentityRollbackAnchorError("IDENTITY_ANCHOR_ALREADY_INITIALIZED") from None
        except OSError:
            raise IdentityRollbackAnchorError("IDENTITY_ANCHOR_KEY_CREATE_FAILED") from None
        try:
            os.write(fd, secrets.token_bytes(_KEY_BYTES))
            os.fsync(fd)
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        self._fsync_parent()

    def _fsync_parent(self) -> None:
        fd = os.open(self.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @staticmethod
    def _mac_payload(sequence: int, state: dict[str, Any]) -> bytes:
        return MAC_DOMAIN + _canonical({
            "format_version": ANCHOR_FORMAT_VERSION,
            "sequence": sequence,
            "state": state,
        })

    def _read_record(self) -> dict[str, Any]:
        if self.anchor_path.is_symlink() or not self.anchor_path.is_file():
            raise IdentityRollbackAnchorError("IDENTITY_ANCHOR_UNAVAILABLE")
        try:
            record = json.loads(self.anchor_path.read_text(encoding="ascii"))
        except (OSError, ValueError, UnicodeDecodeError):
            raise IdentityRollbackAnchorError("IDENTITY_ANCHOR_INVALID") from None
        if (
            not isinstance(record, dict)
            or record.get("format_version") != ANCHOR_FORMAT_VERSION
            or isinstance(record.get("sequence"), bool)
            or not isinstance(record.get("sequence"), int)
            or record["sequence"] < 1
            or not isinstance(record.get("state"), dict)
            or not isinstance(record.get("mac"), str)
        ):
            raise IdentityRollbackAnchorError("IDENTITY_ANCHOR_INVALID")
        expected = hmac.new(
            self._read_key(), self._mac_payload(record["sequence"], record["state"]),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, record["mac"]):
            raise IdentityRollbackAnchorError("IDENTITY_ANCHOR_MAC_INVALID")
        return record

    def _write_record(self, sequence: int, state: dict[str, Any], key: bytes) -> None:
        mac = hmac.new(key, self._mac_payload(sequence, state), hashlib.sha256).hexdigest()
        payload = _canonical({
            "format_version": ANCHOR_FORMAT_VERSION,
            "sequence": sequence,
            "state": state,
            "mac": mac,
        }) + b"\n"
        fd, temp_name = tempfile.mkstemp(prefix=".identity-anchor-", dir=self.parent)
        temp_path = Path(temp_name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_path, self.anchor_path)
            self._fsync_parent()
        except Exception:
            try:
                temp_path.unlink()
            except OSError:
                pass
            raise

    def initialize(self, state: dict[str, Any]) -> dict[str, Any]:
        """Create the first anchor explicitly; never silently recreate a missing anchor."""
        if not isinstance(state, dict) or state.get("schema_version") != STATE_SCHEMA_VERSION:
            raise IdentityRollbackAnchorError("IDENTITY_ANCHOR_STATE_INVALID")
        with self._locked():
            if self.anchor_path.exists() or self.anchor_path.is_symlink() or self.key_path.exists() or self.key_path.is_symlink():
                raise IdentityRollbackAnchorError("IDENTITY_ANCHOR_ALREADY_INITIALIZED")
            self._create_key()
            key = self._read_key()
            self._write_record(1, state, key)
        return {"initialized": True, "sequence": 1}

    def verify(self, state: dict[str, Any]) -> dict[str, Any]:
        """Fail closed unless the external anchor exactly matches the live DB pair."""
        with self._locked():
            record = self._read_record()
            if not hmac.compare_digest(_canonical(record["state"]), _canonical(state)):
                raise IdentityRollbackAnchorError("IDENTITY_ANCHOR_STATE_MISMATCH")
            return {"valid": True, "sequence": record["sequence"]}

    def advance(
        self, state: dict[str, Any], *, expected_sequence: int,
    ) -> dict[str, Any]:
        """Advance exactly one step using compare-and-swap; never permit sequence rollback."""
        if (
            not isinstance(state, dict) or state.get("schema_version") != STATE_SCHEMA_VERSION
            or isinstance(expected_sequence, bool) or not isinstance(expected_sequence, int)
            or expected_sequence < 1
        ):
            raise IdentityRollbackAnchorError("IDENTITY_ANCHOR_STATE_INVALID")
        with self._locked():
            record = self._read_record()
            if record["sequence"] != expected_sequence:
                raise IdentityRollbackAnchorError("IDENTITY_ANCHOR_SEQUENCE_CONFLICT")
            if hmac.compare_digest(_canonical(record["state"]), _canonical(state)):
                raise IdentityRollbackAnchorError("IDENTITY_ANCHOR_NO_STATE_CHANGE")
            next_sequence = expected_sequence + 1
            self._write_record(next_sequence, state, self._read_key())
        return {"advanced": True, "sequence": next_sequence}
