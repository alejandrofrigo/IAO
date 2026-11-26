"""Durable operator root-key registry.

This module is intentionally not wired to API authorization yet. It provides
an independently testable, fail-closed persistence primitive for the staged
root-identity protocol. A registered root key does not grant API capabilities.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import stat
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT_SIGNATURE_DOMAIN = b"IAO-OPERATOR-ROOT-V1\x00"
MAX_PUBLIC_KEY_BYTES = 4096
MAX_SIGNED_PAYLOAD_BYTES = 8192


class OperatorIdentityError(RuntimeError):
    def __init__(self, code: str, status: int = 400) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


class OperatorIdentityAuthority:
    """Stores only root public keys; bootstrap secrets are consumed once."""

    def __init__(self, database: str | Path, bootstrap_code: str = "") -> None:
        self.database = Path(database)
        parent = self.database.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if parent.is_symlink() or self.database.is_symlink():
            raise RuntimeError("OPERATOR_IDENTITY_SYMLINK_REFUSED")
        if self.database.exists() and not self.database.is_file():
            raise RuntimeError("OPERATOR_IDENTITY_PATH_NOT_REGULAR_FILE")
        os.chmod(parent, 0o700)
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(self.database), flags, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise RuntimeError("OPERATOR_IDENTITY_PATH_NOT_REGULAR_FILE")
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        self.bootstrap_code = bootstrap_code
        self.lock = threading.RLock()
        with self._database() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS operator_identities (
                    identity_id TEXT PRIMARY KEY,
                    root_public_key_pem TEXT NOT NULL,
                    key_version INTEGER NOT NULL CHECK(key_version >= 1),
                    status TEXT NOT NULL CHECK(status IN ('ACTIVE','REVOKED')),
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    revoked_at REAL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS one_active_operator_root
                    ON operator_identities(status) WHERE status='ACTIVE';
                CREATE TABLE IF NOT EXISTS consumed_bootstrap_codes (
                    code_digest TEXT PRIMARY KEY,
                    consumed_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS primary_device_bindings (
                    identity_id TEXT PRIMARY KEY REFERENCES operator_identities(identity_id),
                    device_id TEXT NOT NULL UNIQUE,
                    device_public_key_pem TEXT NOT NULL,
                    key_version INTEGER NOT NULL CHECK(key_version >= 1),
                    bound_at REAL NOT NULL
                );
                """
            )
        os.chmod(self.database, 0o600)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.database, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA journal_mode=WAL")
        return db

    @contextmanager
    def _database(self):
        db = self._connect()
        try:
            yield db
        finally:
            db.close()

    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _public_key(value: Any):
        if not isinstance(value, str) or not value or len(value) > MAX_PUBLIC_KEY_BYTES:
            raise OperatorIdentityError("INVALID_ROOT_PUBLIC_KEY")
        try:
            key = serialization.load_pem_public_key(value.encode("ascii"))
        except (ValueError, TypeError, UnicodeEncodeError):
            raise OperatorIdentityError("INVALID_ROOT_PUBLIC_KEY") from None
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
            key.curve, ec.SECP256R1
        ):
            raise OperatorIdentityError("UNSUPPORTED_ROOT_KEY")
        canonical = key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        return key, canonical

    def bootstrap(self, code: Any, root_public_key_pem: Any) -> dict[str, Any]:
        """Create the sole active root identity using an out-of-band secret."""
        configured = self.bootstrap_code
        if not isinstance(configured, str) or len(configured) < 32:
            raise OperatorIdentityError("OPERATOR_BOOTSTRAP_DISABLED", 503)
        if not isinstance(code, str) or len(code) < 32 or not hmac.compare_digest(
            self._digest(code), self._digest(configured)
        ):
            raise OperatorIdentityError("INVALID_OPERATOR_BOOTSTRAP", 403)
        _, public_pem = self._public_key(root_public_key_pem)
        code_digest = self._digest(code)
        identity_id = uuid.uuid4().hex
        now = time.time()
        with self.lock, self._database() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                if db.execute(
                    "SELECT 1 FROM consumed_bootstrap_codes WHERE code_digest=?",
                    (code_digest,),
                ).fetchone():
                    raise OperatorIdentityError("OPERATOR_BOOTSTRAP_ALREADY_USED", 409)
                if db.execute(
                    "SELECT 1 FROM operator_identities WHERE status='ACTIVE'"
                ).fetchone():
                    raise OperatorIdentityError("OPERATOR_ROOT_ALREADY_ENROLLED", 409)
                db.execute(
                    "INSERT INTO consumed_bootstrap_codes(code_digest,consumed_at) VALUES(?,?)",
                    (code_digest, now),
                )
                db.execute(
                    """INSERT INTO operator_identities
                    (identity_id,root_public_key_pem,key_version,status,created_at,updated_at)
                    VALUES(?,?,1,'ACTIVE',?,?)""",
                    (identity_id, public_pem, now, now),
                )
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise
        # The opaque identifier is for trusted internal orchestration only;
        # public API responses must not expose it.
        return {"identity_id": identity_id, "key_version": 1}

    @staticmethod
    def _signed_message(payload: bytes) -> bytes:
        if not isinstance(payload, bytes) or not payload or len(payload) > MAX_SIGNED_PAYLOAD_BYTES:
            raise OperatorIdentityError("INVALID_ROOT_SIGNED_PAYLOAD")
        return ROOT_SIGNATURE_DOMAIN + payload

    def verify_root_signature(
        self, identity_id: str, payload: bytes, signature: bytes, *,
        expected_key_version: int,
    ) -> bool:
        """Verify domain-separated bytes against the currently active root."""
        if not isinstance(identity_id, str) or len(identity_id) != 32:
            raise OperatorIdentityError("OPERATOR_IDENTITY_NOT_FOUND", 404)
        if isinstance(expected_key_version, bool) or not isinstance(expected_key_version, int):
            raise OperatorIdentityError("INVALID_ROOT_KEY_VERSION")
        if not isinstance(signature, bytes) or not 64 <= len(signature) <= 80:
            raise OperatorIdentityError("INVALID_ROOT_SIGNATURE")
        message = self._signed_message(payload)
        with self._database() as db:
            row = db.execute(
                """SELECT root_public_key_pem,key_version,status
                FROM operator_identities WHERE identity_id=?""",
                (identity_id,),
            ).fetchone()
        if row is None or row["status"] != "ACTIVE":
            raise OperatorIdentityError("OPERATOR_IDENTITY_NOT_ACTIVE", 403)
        if row["key_version"] != expected_key_version:
            raise OperatorIdentityError("OPERATOR_ROOT_KEY_VERSION_MISMATCH", 409)
        try:
            key = serialization.load_pem_public_key(row["root_public_key_pem"].encode("ascii"))
            key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        except (InvalidSignature, ValueError, TypeError):
            raise OperatorIdentityError("INVALID_ROOT_SIGNATURE", 401) from None
        return True

    def rotate_root(
        self, identity_id: str, new_root_public_key_pem: Any,
        old_root_signature: bytes,
    ) -> dict[str, int]:
        """Rotate root key only with proof from the current root key."""
        _, new_pem = self._public_key(new_root_public_key_pem)
        with self._database() as db:
            row = db.execute(
                "SELECT key_version,status FROM operator_identities WHERE identity_id=?",
                (identity_id,),
            ).fetchone()
        if row is None or row["status"] != "ACTIVE":
            raise OperatorIdentityError("OPERATOR_IDENTITY_NOT_ACTIVE", 403)
        next_version = row["key_version"] + 1
        payload = (
            b"rotate-root-v1\n" + identity_id.encode("ascii") + b"\n"
            + str(next_version).encode("ascii") + b"\n"
            + hashlib.sha256(new_pem.encode("ascii")).hexdigest().encode("ascii")
        )
        self.verify_root_signature(
            identity_id, payload, old_root_signature,
            expected_key_version=row["key_version"],
        )
        now = time.time()
        with self.lock, self._database() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                current = db.execute(
                    "SELECT key_version,status FROM operator_identities WHERE identity_id=?",
                    (identity_id,),
                ).fetchone()
                if current is None or current["status"] != "ACTIVE" or current["key_version"] != row["key_version"]:
                    raise OperatorIdentityError("OPERATOR_ROOT_CHANGED_CONCURRENTLY", 409)
                db.execute(
                    """UPDATE operator_identities SET root_public_key_pem=?,
                    key_version=?,updated_at=? WHERE identity_id=?""",
                    (new_pem, next_version, now, identity_id),
                )
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise
        return {"key_version": next_version}


    @staticmethod
    def device_binding_payload(device_public_key_pem: Any, *, key_version: int) -> tuple[str, bytes]:
        """Return the canonical device identifier and root-signed binding payload."""
        _, canonical_pem = OperatorIdentityAuthority._public_key(device_public_key_pem)
        key = serialization.load_pem_public_key(canonical_pem.encode("ascii"))
        der = key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        device_id = hashlib.sha256(der).hexdigest()
        document = {
            "device_id": device_id,
            "key_version": key_version,
            "protocol": "IAO-DEVICE-BINDING-V1",
            "public_key_sha256": hashlib.sha256(der).hexdigest(),
            "role": "PRIMARY",
        }
        payload = json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        return device_id, payload

    def bind_primary_device(
        self, identity_id: str, device_public_key_pem: Any,
        root_signature: bytes, *, expected_key_version: int,
    ) -> dict[str, int]:
        """Persist exactly one device binding authorized by the active root."""
        device_id, payload = self.device_binding_payload(
            device_public_key_pem, key_version=expected_key_version
        )
        self.verify_root_signature(
            identity_id, payload, root_signature,
            expected_key_version=expected_key_version,
        )
        _, canonical_pem = self._public_key(device_public_key_pem)
        now = time.time()
        with self.lock, self._database() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute(
                    "SELECT key_version,status FROM operator_identities WHERE identity_id=?",
                    (identity_id,),
                ).fetchone()
                if row is None or row["status"] != "ACTIVE":
                    raise OperatorIdentityError("OPERATOR_IDENTITY_NOT_ACTIVE", 403)
                if row["key_version"] != expected_key_version:
                    raise OperatorIdentityError("OPERATOR_ROOT_KEY_VERSION_MISMATCH", 409)
                existing = db.execute(
                    """SELECT identity_id,device_id,key_version
                    FROM primary_device_bindings"""
                ).fetchone()
                if existing is not None:
                    if existing["identity_id"] != identity_id:
                        raise OperatorIdentityError("PRIMARY_DEVICE_ALREADY_BOUND", 409)
                    if expected_key_version <= existing["key_version"]:
                        if (
                            existing["device_id"] == device_id
                            and expected_key_version == existing["key_version"]
                        ):
                            db.execute("COMMIT")
                            return {"key_version": expected_key_version}
                        raise OperatorIdentityError("PRIMARY_DEVICE_ALREADY_BOUND", 409)
                db.execute(
                    """INSERT INTO primary_device_bindings
                    (identity_id,device_id,device_public_key_pem,key_version,bound_at)
                    VALUES(?,?,?,?,?)
                    ON CONFLICT(identity_id) DO UPDATE SET
                    device_id=excluded.device_id,
                    device_public_key_pem=excluded.device_public_key_pem,
                    key_version=excluded.key_version,
                    bound_at=excluded.bound_at""",
                    (identity_id, device_id, canonical_pem, expected_key_version, now),
                )
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise
        return {"key_version": expected_key_version}

    def verify_primary_device(self, identity_id: str, device_public_key_pem: Any) -> bool:
        """Check a binding is still current, active, and bound to this exact key."""
        device_id, _ = self.device_binding_payload(device_public_key_pem, key_version=1)
        with self._database() as db:
            row = db.execute(
                """SELECT b.device_id,b.device_public_key_pem,
                b.key_version AS binding_key_version,
                i.status,i.key_version AS root_key_version
                FROM primary_device_bindings b
                JOIN operator_identities i ON i.identity_id=b.identity_id
                WHERE b.identity_id=?""",
                (identity_id,),
            ).fetchone()
        if row is None or row["status"] != "ACTIVE":
            raise OperatorIdentityError("PRIMARY_DEVICE_NOT_AUTHORIZED", 403)
        if row["device_id"] != device_id:
            raise OperatorIdentityError("PRIMARY_DEVICE_KEY_MISMATCH", 403)
        if row["binding_key_version"] != row["root_key_version"]:
            raise OperatorIdentityError("OPERATOR_ROOT_KEY_VERSION_MISMATCH", 409)
        _, canonical_pem = self._public_key(device_public_key_pem)
        if not hmac.compare_digest(row["device_public_key_pem"], canonical_pem):
            raise OperatorIdentityError("PRIMARY_DEVICE_KEY_MISMATCH", 403)
        return True

    def revoke(self, identity_id: str, signature: bytes, *, expected_key_version: int) -> None:
        payload = b"revoke-root-v1\n" + identity_id.encode("ascii")
        self.verify_root_signature(
            identity_id, payload, signature,
            expected_key_version=expected_key_version,
        )
        now = time.time()
        with self.lock, self._database() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                changed = db.execute(
                    """UPDATE operator_identities SET status='REVOKED',
                    revoked_at=?,updated_at=? WHERE identity_id=?
                    AND status='ACTIVE' AND key_version=?""",
                    (now, now, identity_id, expected_key_version),
                ).rowcount
                if changed != 1:
                    raise OperatorIdentityError("OPERATOR_ROOT_CHANGED_CONCURRENTLY", 409)
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise

