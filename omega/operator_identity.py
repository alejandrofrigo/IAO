"""Durable operator root-key registry and read-only session association.

Root enrollment and session association do not grant API capabilities.
Protected device/task routes must independently enforce the full identity,
device, request-proof and policy chain before any future command authority.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import re
import secrets
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

    def __init__(
        self, database: str | Path, bootstrap_code: str = "",
        *, bootstrap_expires_at: float | None = None,
        subject_digest_key: bytes | str | None = None,
    ) -> None:
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
        self.bootstrap_expires_at = bootstrap_expires_at
        if isinstance(subject_digest_key, str):
            subject_digest_key = subject_digest_key.encode("utf-8")
        self.subject_digest_key = subject_digest_key
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
                CREATE TABLE IF NOT EXISTS operator_login_challenges (
                    challenge_digest TEXT PRIMARY KEY,
                    identity_id TEXT NOT NULL REFERENCES operator_identities(identity_id),
                    device_id TEXT NOT NULL,
                    signing_payload BLOB NOT NULL,
                    key_version INTEGER NOT NULL CHECK(key_version >= 1),
                    expires_at REAL NOT NULL,
                    consumed_at REAL
                );
                CREATE INDEX IF NOT EXISTS operator_login_challenge_expiry
                    ON operator_login_challenges(expires_at);
                CREATE TABLE IF NOT EXISTS operator_session_challenges (
                    challenge_digest TEXT PRIMARY KEY,
                    identity_id TEXT NOT NULL REFERENCES operator_identities(identity_id),
                    subject_digest TEXT NOT NULL,
                    session_digest TEXT,
                    signing_payload BLOB NOT NULL,
                    key_version INTEGER NOT NULL CHECK(key_version >= 1),
                    expires_at REAL NOT NULL,
                    consumed_at REAL
                );
                CREATE INDEX IF NOT EXISTS operator_session_challenge_expiry
                    ON operator_session_challenges(expires_at);
                CREATE TABLE IF NOT EXISTS operator_session_bindings (
                    identity_id TEXT PRIMARY KEY REFERENCES operator_identities(identity_id),
                    subject_digest TEXT NOT NULL UNIQUE,
                    session_digest TEXT,
                    key_version INTEGER NOT NULL CHECK(key_version >= 1),
                    bound_at REAL NOT NULL
                );
                """
            )
            for table in ("operator_session_challenges", "operator_session_bindings"):
                columns = {
                    row["name"] for row in db.execute(f"PRAGMA table_info({table})")
                }
                if "session_digest" not in columns:
                    db.execute(f"ALTER TABLE {table} ADD COLUMN session_digest TEXT")
            db.execute(
                """CREATE UNIQUE INDEX IF NOT EXISTS one_operator_session_digest
                ON operator_session_bindings(session_digest)
                WHERE session_digest IS NOT NULL"""
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
        expiry = self.bootstrap_expires_at
        if (
            not isinstance(configured, str) or len(configured) < 32
            or isinstance(expiry, bool) or not isinstance(expiry, (int, float))
            or not math.isfinite(expiry) or expiry <= time.time()
        ):
            raise OperatorIdentityError("OPERATOR_BOOTSTRAP_DISABLED", 503)
        if not isinstance(code, str) or len(code) < 32 or not hmac.compare_digest(
            self._digest(code), self._digest(configured)
        ):
            raise OperatorIdentityError("INVALID_OPERATOR_BOOTSTRAP", 403)
        _, public_pem = self._public_key(root_public_key_pem)
        code_digest = self._digest(code)
        identity_id = uuid.uuid4().hex
        with self.lock, self._database() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                # Re-check the expiry after acquiring the write transaction.
                # A bootstrap that waited on SQLite must not become valid
                # after its configured authorization window has elapsed.
                now = time.time()
                if now >= expiry:
                    raise OperatorIdentityError("OPERATOR_BOOTSTRAP_DISABLED", 503)
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
        # Do not retain the one-time capability after successful enrollment.
        self.bootstrap_code = ""
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
                # A session association is tied to the old root version.
                # Require a fresh challenge and signature from the new root.
                db.execute(
                    "DELETE FROM operator_session_bindings WHERE identity_id=?",
                    (identity_id,),
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
                # A revoked identity must release the single-primary slot.
                # The historical identity remains REVOKED; its device binding
                # is no longer an active authorization and cannot block recovery.
                db.execute(
                    "DELETE FROM primary_device_bindings WHERE identity_id=?",
                    (identity_id,),
                )
                db.execute(
                    "DELETE FROM operator_session_bindings WHERE identity_id=?",
                    (identity_id,),
                )
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise



    def primary_device_public_key(self) -> str:
        """Return the enrolled primary public key for internal verification only."""
        with self._database() as db:
            row = db.execute(
                """SELECT b.device_public_key_pem
                FROM primary_device_bindings b
                JOIN operator_identities i ON i.identity_id=b.identity_id
                WHERE i.status='ACTIVE' AND b.key_version=i.key_version"""
            ).fetchone()
        if row is None:
            raise OperatorIdentityError("PRIMARY_DEVICE_NOT_AUTHORIZED", 403)
        return row["device_public_key_pem"]

    def create_operator_login_challenge(self, *, ttl_seconds: int = 90) -> dict[str, Any]:
        """Create a short-lived challenge bound to the current root and primary device."""
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not 30 <= ttl_seconds <= 90:
            raise OperatorIdentityError("INVALID_OPERATOR_LOGIN_TTL")
        now = time.time()
        expires_at = now + ttl_seconds
        handle = secrets.token_urlsafe(32)
        nonce = secrets.token_hex(32)
        with self.lock, self._database() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute(
                    """SELECT i.identity_id,i.key_version,b.device_id,
                    b.device_public_key_pem
                    FROM operator_identities i
                    JOIN primary_device_bindings b ON b.identity_id=i.identity_id
                    WHERE i.status='ACTIVE' AND b.key_version=i.key_version"""
                ).fetchone()
                if row is None:
                    raise OperatorIdentityError("PRIMARY_DEVICE_NOT_AUTHORIZED", 403)
                device_key = serialization.load_pem_public_key(
                    row["device_public_key_pem"].encode("ascii")
                )
                device_der = device_key.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                payload = json.dumps({
                    "device_key_digest": hashlib.sha256(device_der).hexdigest(),
                    "expires_at": int(expires_at),
                    "key_version": row["key_version"],
                    "nonce": nonce,
                    "protocol": "IAO-OPERATOR-LOGIN-V1",
                    "purpose": "OPERATOR_LOGIN",
                }, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
                db.execute(
                    """INSERT INTO operator_login_challenges
                    (challenge_digest,identity_id,device_id,signing_payload,
                     key_version,expires_at)
                    VALUES(?,?,?,?,?,?)""",
                    (self._digest(handle), row["identity_id"], row["device_id"],
                     payload, row["key_version"], expires_at),
                )
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise
        return {
            "challenge": handle,
            "signing_payload": base64.urlsafe_b64encode(payload).decode("ascii").rstrip("="),
            "expires_at": int(expires_at),
            "protocol": "IAO-OPERATOR-LOGIN-V1",
        }

    def complete_operator_login(
        self, challenge: Any, root_signature: bytes, device_signature: bytes,
        token_key: str, *, ttl_seconds: int = 900,
    ) -> dict[str, Any]:
        """Atomically consume a dual-signed challenge and bind a read-only session."""
        if not isinstance(challenge, str) or not 32 <= len(challenge) <= 128:
            raise OperatorIdentityError("INVALID_OPERATOR_LOGIN_CHALLENGE")
        if (
            not isinstance(root_signature, bytes) or not 64 <= len(root_signature) <= 80
            or not isinstance(device_signature, bytes) or not 64 <= len(device_signature) <= 80
        ):
            raise OperatorIdentityError("INVALID_OPERATOR_LOGIN_SIGNATURE", 401)
        if not isinstance(token_key, str) or not token_key:
            raise OperatorIdentityError("OPERATOR_LOGIN_UNAVAILABLE", 503)
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not 60 <= ttl_seconds <= 900:
            raise OperatorIdentityError("INVALID_OPERATOR_LOGIN_TTL")
        now = time.time()
        with self.lock, self._database() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute(
                    """SELECT c.identity_id,c.device_id,c.signing_payload,
                    c.key_version,c.expires_at,c.consumed_at,
                    i.root_public_key_pem,i.key_version AS active_key_version,i.status,
                    b.device_public_key_pem,b.device_id AS active_device_id,
                    b.key_version AS device_key_version
                    FROM operator_login_challenges c
                    JOIN operator_identities i ON i.identity_id=c.identity_id
                    JOIN primary_device_bindings b ON b.identity_id=i.identity_id
                    WHERE c.challenge_digest=?""",
                    (self._digest(challenge),),
                ).fetchone()
                if row is None:
                    raise OperatorIdentityError("INVALID_OPERATOR_LOGIN_CHALLENGE", 404)
                if row["consumed_at"] is not None:
                    raise OperatorIdentityError("OPERATOR_LOGIN_REPLAYED", 409)
                if row["expires_at"] <= now:
                    raise OperatorIdentityError("OPERATOR_LOGIN_EXPIRED", 401)
                if (
                    row["status"] != "ACTIVE"
                    or row["key_version"] != row["active_key_version"]
                    or row["key_version"] != row["device_key_version"]
                    or row["device_id"] != row["active_device_id"]
                ):
                    raise OperatorIdentityError("OPERATOR_LOGIN_AUTHORITY_CHANGED", 403)
                message = ROOT_SIGNATURE_DOMAIN + row["signing_payload"]
                device_message = b"IAO-OPERATOR-DEVICE-LOGIN-V1\x00" + row["signing_payload"]
                try:
                    root_key = serialization.load_pem_public_key(
                        row["root_public_key_pem"].encode("ascii")
                    )
                    device_key = serialization.load_pem_public_key(
                        row["device_public_key_pem"].encode("ascii")
                    )
                    root_key.verify(root_signature, message, ec.ECDSA(hashes.SHA256()))
                    device_key.verify(device_signature, device_message, ec.ECDSA(hashes.SHA256()))
                except (InvalidSignature, ValueError, TypeError):
                    raise OperatorIdentityError("INVALID_OPERATOR_LOGIN_SIGNATURE", 401) from None
                changed = db.execute(
                    """UPDATE operator_login_challenges SET consumed_at=?
                    WHERE challenge_digest=? AND consumed_at IS NULL AND expires_at>?""",
                    (now, self._digest(challenge), now),
                ).rowcount
                if changed != 1:
                    raise OperatorIdentityError("OPERATOR_LOGIN_REPLAYED", 409)
                subject = "operator:" + row["identity_id"]
                token = __import__("omega.auth", fromlist=["issue_token"]).issue_token(
                    token_key, subject, [], ttl=ttl_seconds, now=now
                )
                subject_digest = hmac.new(
                    self.subject_digest_key,
                    subject.encode("utf-8"), hashlib.sha256
                ).hexdigest() if isinstance(self.subject_digest_key, bytes) and len(self.subject_digest_key) >= 32 else None
                session_digest = self._session_credential_digest(token)
                if subject_digest is None:
                    raise OperatorIdentityError("OPERATOR_SESSION_BINDING_UNAVAILABLE", 503)
                db.execute(
                    """INSERT INTO operator_session_bindings
                    (identity_id,subject_digest,session_digest,key_version,bound_at)
                    VALUES(?,?,?,?,?)
                    ON CONFLICT(identity_id) DO UPDATE SET
                    subject_digest=excluded.subject_digest,
                    session_digest=excluded.session_digest,
                    key_version=excluded.key_version,bound_at=excluded.bound_at""",
                    (row["identity_id"], subject_digest, session_digest,
                     row["key_version"], now),
                )
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise
        return {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": ttl_seconds,
            "authority": "OPERATOR_AUTHENTICATED_READ_ONLY",
            "scopes": [],
            "key_version": row["key_version"],
        }

    def _session_subject_digest(self, subject: Any) -> str:
        if (
            not isinstance(subject, str) or not subject
            or len(subject) > 512 or subject.startswith("guest:")
        ):
            raise OperatorIdentityError("OPERATOR_SESSION_REQUIRED", 403)
        if not isinstance(self.subject_digest_key, bytes) or len(self.subject_digest_key) < 32:
            raise OperatorIdentityError("OPERATOR_SESSION_BINDING_UNAVAILABLE", 503)
        return hmac.new(
            self.subject_digest_key, subject.encode("utf-8"), hashlib.sha256
        ).hexdigest()

    def _session_credential_digest(self, token: Any) -> str:
        if not isinstance(token, str) or not 32 <= len(token) <= 8192:
            raise OperatorIdentityError("OPERATOR_SESSION_REQUIRED", 403)
        if not isinstance(self.subject_digest_key, bytes) or len(self.subject_digest_key) < 32:
            raise OperatorIdentityError("OPERATOR_SESSION_BINDING_UNAVAILABLE", 503)
        return hmac.new(
            self.subject_digest_key,
            b"IAO-OPERATOR-SESSION-TOKEN-V1\x00" + token.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def create_session_challenge(
        self, authenticated_subject: Any, authenticated_session_token: Any,
        *, ttl_seconds: int = 90,
    ) -> dict[str, Any]:
        """Issue a one-time root-signing challenge for one verified bearer session."""
        subject_digest = self._session_subject_digest(authenticated_subject)
        session_digest = self._session_credential_digest(authenticated_session_token)
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not 30 <= ttl_seconds <= 180:
            raise OperatorIdentityError("INVALID_SESSION_CHALLENGE_TTL")
        now = time.time()
        expires_at = now + ttl_seconds
        challenge_id = secrets.token_urlsafe(32)
        nonce = secrets.token_hex(32)
        with self.lock, self._database() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                root = db.execute(
                    """SELECT identity_id,key_version,status FROM operator_identities
                    WHERE status='ACTIVE'"""
                ).fetchone()
                if root is None:
                    raise OperatorIdentityError("OPERATOR_IDENTITY_NOT_ACTIVE", 403)
                identity_digest = hashlib.sha256(
                    root["identity_id"].encode("ascii")
                ).hexdigest()
                statement = {
                    "expires_at": int(expires_at),
                    "identity_digest": identity_digest,
                    "key_version": root["key_version"],
                    "nonce": nonce,
                    "protocol": "IAO-OPERATOR-SESSION-BINDING-V1",
                    "purpose": "ASSOCIATE_AUTHENTICATED_SESSION",
                    "subject_digest": subject_digest,
                    "session_digest": session_digest,
                }
                payload = json.dumps(
                    statement, sort_keys=True, separators=(",", ":"),
                    ensure_ascii=True,
                ).encode("ascii")
                db.execute(
                    """INSERT INTO operator_session_challenges
                    (challenge_digest,identity_id,subject_digest,session_digest,
                     signing_payload,key_version,expires_at)
                    VALUES(?,?,?,?,?,?,?)""",
                    (
                        self._digest(challenge_id), root["identity_id"],
                        subject_digest, session_digest, payload,
                        root["key_version"], expires_at,
                    ),
                )
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise
        return {
            "challenge": challenge_id,
            "signing_payload": base64.urlsafe_b64encode(payload).decode("ascii").rstrip("="),
            "expires_at": int(expires_at),
            "key_version": root["key_version"],
            "protocol": "IAO-OPERATOR-SESSION-BINDING-V1",
        }

    def bind_authenticated_session(
        self, challenge: Any, authenticated_subject: Any,
        authenticated_session_token: Any, signature: bytes,
    ) -> dict[str, int]:
        """Atomically consume a challenge bound to one exact bearer session."""
        subject_digest = self._session_subject_digest(authenticated_subject)
        session_digest = self._session_credential_digest(authenticated_session_token)
        if not isinstance(challenge, str) or not 32 <= len(challenge) <= 128:
            raise OperatorIdentityError("INVALID_SESSION_CHALLENGE")
        if not isinstance(signature, bytes) or not 64 <= len(signature) <= 80:
            raise OperatorIdentityError("INVALID_ROOT_SIGNATURE", 401)
        now = time.time()
        with self.lock, self._database() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute(
                    """SELECT c.identity_id,c.subject_digest,c.session_digest,
                    c.signing_payload,c.key_version,c.expires_at,c.consumed_at,
                    i.root_public_key_pem,i.key_version AS active_key_version,i.status
                    FROM operator_session_challenges c
                    JOIN operator_identities i ON i.identity_id=c.identity_id
                    WHERE c.challenge_digest=?""",
                    (self._digest(challenge),),
                ).fetchone()
                if row is None:
                    raise OperatorIdentityError("INVALID_SESSION_CHALLENGE", 404)
                if row["consumed_at"] is not None:
                    raise OperatorIdentityError("SESSION_CHALLENGE_REPLAYED", 409)
                if row["expires_at"] <= now:
                    raise OperatorIdentityError("SESSION_CHALLENGE_EXPIRED", 401)
                if row["status"] != "ACTIVE":
                    raise OperatorIdentityError("OPERATOR_IDENTITY_NOT_ACTIVE", 403)
                if row["active_key_version"] != row["key_version"]:
                    raise OperatorIdentityError("OPERATOR_ROOT_KEY_VERSION_MISMATCH", 409)
                if (
                    not hmac.compare_digest(row["subject_digest"], subject_digest)
                    or not isinstance(row["session_digest"], str)
                    or not hmac.compare_digest(row["session_digest"], session_digest)
                ):
                    raise OperatorIdentityError("OPERATOR_SESSION_MISMATCH", 403)
                try:
                    key = serialization.load_pem_public_key(
                        row["root_public_key_pem"].encode("ascii")
                    )
                    key.verify(
                        signature, self._signed_message(row["signing_payload"]),
                        ec.ECDSA(hashes.SHA256()),
                    )
                except (InvalidSignature, ValueError, TypeError):
                    raise OperatorIdentityError("INVALID_ROOT_SIGNATURE", 401) from None
                existing = db.execute(
                    """SELECT subject_digest,session_digest,key_version
                    FROM operator_session_bindings WHERE identity_id=?""",
                    (row["identity_id"],),
                ).fetchone()
                if existing is not None and (
                    existing["subject_digest"] != subject_digest
                    or existing["key_version"] != row["key_version"]
                ):
                    raise OperatorIdentityError("OPERATOR_SESSION_ALREADY_BOUND", 409)
                changed = db.execute(
                    """UPDATE operator_session_challenges SET consumed_at=?
                    WHERE challenge_digest=? AND consumed_at IS NULL
                    AND expires_at>?""",
                    (now, self._digest(challenge), now),
                ).rowcount
                if changed != 1:
                    raise OperatorIdentityError("SESSION_CHALLENGE_REPLAYED", 409)
                db.execute(
                    """INSERT INTO operator_session_bindings
                    (identity_id,subject_digest,session_digest,key_version,bound_at)
                    VALUES(?,?,?,?,?)
                    ON CONFLICT(identity_id) DO UPDATE SET
                    session_digest=excluded.session_digest,bound_at=excluded.bound_at""",
                    (
                        row["identity_id"], subject_digest, session_digest,
                        row["key_version"], now,
                    ),
                )
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise
        return {"key_version": row["key_version"]}

    def bind_primary_device_for_session(
        self, authenticated_subject: Any, authenticated_session_token: Any,
        device_public_key_pem: Any, root_signature: bytes,
    ) -> dict[str, int]:
        """Bind a device only through the exact root-associated bearer session."""
        subject_digest = self._session_subject_digest(authenticated_subject)
        session_digest = self._session_credential_digest(authenticated_session_token)
        with self._database() as db:
            row = db.execute(
                """SELECT i.identity_id,i.key_version,i.status,b.subject_digest,
                b.session_digest,b.key_version AS binding_key_version
                FROM operator_session_bindings b
                JOIN operator_identities i ON i.identity_id=b.identity_id
                WHERE i.status='ACTIVE'"""
            ).fetchone()
        if (
            row is None or row["key_version"] != row["binding_key_version"]
            or not hmac.compare_digest(row["subject_digest"], subject_digest)
            or not isinstance(row["session_digest"], str)
            or not hmac.compare_digest(row["session_digest"], session_digest)
        ):
            raise OperatorIdentityError("OPERATOR_SESSION_MISMATCH", 403)
        return self.bind_primary_device(
            row["identity_id"], device_public_key_pem, root_signature,
            expected_key_version=row["key_version"],
        )

    def session_credential_digest(self, authenticated_session_token: Any) -> str:
        """Return the server-keyed digest for durable internal task binding only."""
        return self._session_credential_digest(authenticated_session_token)

    def verify_primary_device_for_session_digest(
        self, authenticated_subject: Any, session_digest: Any, device_id: Any,
    ) -> bool:
        """Revalidate current root, exact session digest and primary device without storing a bearer token."""
        subject_digest = self._session_subject_digest(authenticated_subject)
        if not isinstance(session_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", session_digest):
            raise OperatorIdentityError("PRIMARY_DEVICE_NOT_AUTHORIZED", 403)
        if not isinstance(device_id, str) or not re.fullmatch(r"[0-9a-f]{64}", device_id):
            raise OperatorIdentityError("PRIMARY_DEVICE_NOT_AUTHORIZED", 403)
        with self._database() as db:
            row = db.execute(
                """SELECT b.subject_digest,b.session_digest,b.key_version,
                i.key_version AS active_key_version,p.device_id,
                p.key_version AS device_key_version
                FROM operator_session_bindings b
                JOIN operator_identities i ON i.identity_id=b.identity_id
                JOIN primary_device_bindings p ON p.identity_id=i.identity_id
                WHERE i.status='ACTIVE'"""
            ).fetchone()
        if (
            row is None or row["key_version"] != row["active_key_version"]
            or row["device_key_version"] != row["active_key_version"]
            or not hmac.compare_digest(row["subject_digest"], subject_digest)
            or not isinstance(row["session_digest"], str)
            or not hmac.compare_digest(row["session_digest"], session_digest)
            or not hmac.compare_digest(row["device_id"], device_id)
        ):
            raise OperatorIdentityError("PRIMARY_DEVICE_NOT_AUTHORIZED", 403)
        return True

    def verify_primary_device_for_session(
        self, authenticated_subject: Any, authenticated_session_token: Any,
        device_id: Any,
    ) -> bool:
        """Require the exact active session and its single root-bound primary device."""
        return self.verify_primary_device_for_session_digest(
            authenticated_subject,
            self._session_credential_digest(authenticated_session_token),
            device_id,
        )

    def verify_authenticated_session(
        self, authenticated_subject: Any, authenticated_session_token: Any,
    ) -> bool:
        """Return true only for the exact currently bound bearer token."""
        subject_digest = self._session_subject_digest(authenticated_subject)
        session_digest = self._session_credential_digest(authenticated_session_token)
        with self._database() as db:
            row = db.execute(
                """SELECT b.subject_digest,b.session_digest,b.key_version,
                i.key_version AS active_key_version
                FROM operator_session_bindings b
                JOIN operator_identities i ON i.identity_id=b.identity_id
                WHERE i.status='ACTIVE'"""
            ).fetchone()
        if row is None or row["key_version"] != row["active_key_version"]:
            return False
        return (
            hmac.compare_digest(row["subject_digest"], subject_digest)
            and isinstance(row["session_digest"], str)
            and hmac.compare_digest(row["session_digest"], session_digest)
        )
