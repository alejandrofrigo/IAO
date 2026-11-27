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
from contextlib import contextmanager, nullcontext
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
        # Validate the existing SQLite file before schema migration or writes.
        # Corrupt/non-database files must fail closed with a stable, non-sensitive error.
        try:
            with sqlite3.connect(self.database, timeout=10) as integrity_db:
                integrity_result = integrity_db.execute("PRAGMA quick_check").fetchone()
            if integrity_result != ("ok",):
                raise RuntimeError("OPERATOR_IDENTITY_DATABASE_INTEGRITY_FAILED")
        except sqlite3.DatabaseError:
            raise RuntimeError("OPERATOR_IDENTITY_DATABASE_INTEGRITY_FAILED") from None
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
                CREATE TABLE IF NOT EXISTS operator_recovery_challenges (
                    challenge_digest TEXT PRIMARY KEY,
                    identity_id TEXT NOT NULL REFERENCES operator_identities(identity_id),
                    recovery_digest TEXT NOT NULL,
                    new_recovery_digest TEXT NOT NULL,
                    root_public_key_pem TEXT NOT NULL,
                    device_public_key_pem TEXT NOT NULL,
                    signing_payload BLOB NOT NULL,
                    expires_at REAL NOT NULL,
                    consumed_at REAL
                );
                CREATE INDEX IF NOT EXISTS operator_recovery_challenge_expiry
                    ON operator_recovery_challenges(expires_at);
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
                CREATE TABLE IF NOT EXISTS operator_capability_challenges (
                    challenge_digest TEXT PRIMARY KEY,
                    identity_id TEXT NOT NULL REFERENCES operator_identities(identity_id),
                    subject_digest TEXT NOT NULL, session_digest TEXT NOT NULL,
                    device_id TEXT NOT NULL, capability TEXT NOT NULL,
                    policy_version TEXT NOT NULL, purpose TEXT NOT NULL,
                    grant_id TEXT, signing_payload BLOB NOT NULL,
                    key_version INTEGER NOT NULL, expires_at REAL NOT NULL,
                    consumed_at REAL
                );
                CREATE INDEX IF NOT EXISTS operator_capability_challenge_expiry
                    ON operator_capability_challenges(expires_at);
                CREATE TABLE IF NOT EXISTS operator_capability_grants (
                    grant_id TEXT PRIMARY KEY,
                    identity_id TEXT NOT NULL REFERENCES operator_identities(identity_id),
                    subject_digest TEXT NOT NULL, session_digest TEXT NOT NULL,
                    device_id TEXT NOT NULL, capability TEXT NOT NULL,
                    policy_version TEXT NOT NULL, key_version INTEGER NOT NULL,
                    created_at REAL NOT NULL, expires_at REAL NOT NULL,
                    revoked_at REAL, challenge_digest TEXT NOT NULL UNIQUE
                );
                CREATE INDEX IF NOT EXISTS operator_capability_grants_active
                    ON operator_capability_grants(identity_id, session_digest, revoked_at, expires_at);
                """
            )
            recovery_columns = {
                row["name"] for row in db.execute("PRAGMA table_info(operator_recovery_challenges)")
            }
            if "new_recovery_digest" not in recovery_columns:
                db.execute("ALTER TABLE operator_recovery_challenges ADD COLUMN new_recovery_digest TEXT")
            identity_columns = {
                row["name"] for row in db.execute("PRAGMA table_info(operator_identities)")
            }
            if "recovery_code_digest" not in identity_columns:
                db.execute("ALTER TABLE operator_identities ADD COLUMN recovery_code_digest TEXT")
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
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
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

    def _recovery_digest(self, value: str) -> str:
        key = self.subject_digest_key
        if not isinstance(key, bytes) or len(key) < 32:
            raise OperatorIdentityError("OPERATOR_RECOVERY_UNAVAILABLE", 503)
        message = b"IAO-OPERATOR-RECOVERY-CODE-V1\x00" + value.encode("utf-8")
        return hmac.new(key, message, hashlib.sha256).hexdigest()

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

    def bootstrap(
        self, code: Any, root_public_key_pem: Any, *, recovery_code: Any = None,
    ) -> dict[str, Any]:
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
        if recovery_code is not None and (
            not isinstance(recovery_code, str) or not 32 <= len(recovery_code) <= 512
            or hmac.compare_digest(self._digest(recovery_code), self._digest(code))
        ):
            raise OperatorIdentityError("INVALID_OPERATOR_RECOVERY_CODE")
        recovery_digest = self._recovery_digest(recovery_code) if recovery_code is not None else None
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
                if recovery_digest is not None and (
                    db.execute(
                        "SELECT 1 FROM consumed_bootstrap_codes WHERE code_digest=?",
                        (self._digest(recovery_code),),
                    ).fetchone()
                    or db.execute(
                        "SELECT 1 FROM operator_identities WHERE recovery_code_digest=?",
                        (recovery_digest,),
                    ).fetchone()
                ):
                    raise OperatorIdentityError("OPERATOR_RECOVERY_CODE_ALREADY_USED", 409)
                db.execute(
                    "INSERT INTO consumed_bootstrap_codes(code_digest,consumed_at) VALUES(?,?)",
                    (code_digest, now),
                )
                db.execute(
                    """INSERT INTO operator_identities
                    (identity_id,root_public_key_pem,key_version,status,created_at,updated_at,recovery_code_digest)
                    VALUES(?,?,1,'ACTIVE',?,?,?)""",
                    (identity_id, public_pem, now, now, recovery_digest),
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


    def create_operator_recovery_challenge(
        self, recovery_code: Any, new_root_public_key_pem: Any,
        new_device_public_key_pem: Any, new_recovery_code: Any, *, ttl_seconds: int = 90,
    ) -> dict[str, Any]:
        """Authorize a short-lived replacement challenge with the offline recovery secret."""
        if not isinstance(recovery_code, str) or not 32 <= len(recovery_code) <= 512:
            raise OperatorIdentityError("INVALID_OPERATOR_RECOVERY_CODE", 403)
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not 30 <= ttl_seconds <= 90:
            raise OperatorIdentityError("INVALID_OPERATOR_RECOVERY_TTL")
        if (
            not isinstance(new_recovery_code, str) or not 32 <= len(new_recovery_code) <= 512
            or hmac.compare_digest(self._digest(new_recovery_code), self._digest(recovery_code))
        ):
            raise OperatorIdentityError("INVALID_NEW_OPERATOR_RECOVERY_CODE")
        new_recovery_digest = self._recovery_digest(new_recovery_code)
        _, root_pem = self._public_key(new_root_public_key_pem)
        _, device_pem = self._public_key(new_device_public_key_pem)
        recovery_digest = self._recovery_digest(recovery_code)
        now = time.time()
        expires_at = now + ttl_seconds
        handle = secrets.token_urlsafe(32)
        nonce = secrets.token_hex(32)
        with self.lock, self._database() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute(
                    "DELETE FROM operator_recovery_challenges WHERE expires_at<=?",
                    (now,),
                )
                row = db.execute(
                    """SELECT i.identity_id,i.key_version,i.status,i.recovery_code_digest,
                    i.root_public_key_pem,b.device_public_key_pem AS old_device_public_key_pem
                    FROM operator_identities i
                    LEFT JOIN primary_device_bindings b ON b.identity_id=i.identity_id
                    WHERE i.recovery_code_digest=?""",
                    (recovery_digest,),
                ).fetchone()
                if row is None or row["status"] not in ("ACTIVE", "REVOKED"):
                    raise OperatorIdentityError("INVALID_OPERATOR_RECOVERY_CODE", 403)
                if (
                    db.execute(
                        "SELECT 1 FROM consumed_bootstrap_codes WHERE code_digest=?",
                        (self._digest(new_recovery_code),),
                    ).fetchone()
                    or db.execute(
                        "SELECT 1 FROM operator_identities WHERE recovery_code_digest=?",
                        (new_recovery_digest,),
                    ).fetchone()
                ):
                    raise OperatorIdentityError("OPERATOR_RECOVERY_CODE_ALREADY_USED", 409)
                if db.execute(
                    "SELECT 1 FROM operator_identities WHERE status='ACTIVE' AND identity_id<>?",
                    (row["identity_id"],),
                ).fetchone():
                    raise OperatorIdentityError("ANOTHER_OPERATOR_IDENTITY_ACTIVE", 409)
                active = db.execute(
                    "SELECT COUNT(*) FROM operator_recovery_challenges WHERE consumed_at IS NULL AND expires_at>?",
                    (now,),
                ).fetchone()[0]
                if active >= 10:
                    raise OperatorIdentityError("OPERATOR_RECOVERY_CHALLENGE_LIMIT", 429)
                root_key = serialization.load_pem_public_key(root_pem.encode("ascii"))
                device_key = serialization.load_pem_public_key(device_pem.encode("ascii"))
                root_der = root_key.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                device_der = device_key.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                old_root_key = serialization.load_pem_public_key(
                    row["root_public_key_pem"].encode("ascii")
                )
                old_root_der = old_root_key.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                if hmac.compare_digest(hashlib.sha256(root_der).digest(), hashlib.sha256(old_root_der).digest()):
                    raise OperatorIdentityError("OPERATOR_RECOVERY_ROOT_KEY_MUST_ROTATE", 400)
                if hmac.compare_digest(hashlib.sha256(root_der).digest(), hashlib.sha256(device_der).digest()):
                    raise OperatorIdentityError("OPERATOR_RECOVERY_KEYS_MUST_BE_DISTINCT", 400)
                if row["old_device_public_key_pem"] is not None:
                    old_device_key = serialization.load_pem_public_key(
                        row["old_device_public_key_pem"].encode("ascii")
                    )
                    old_device_der = old_device_key.public_bytes(
                        serialization.Encoding.DER,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                    if hmac.compare_digest(hashlib.sha256(device_der).digest(), hashlib.sha256(old_device_der).digest()):
                        raise OperatorIdentityError("OPERATOR_RECOVERY_DEVICE_KEY_MUST_ROTATE", 400)
                payload = json.dumps({
                    "device_key_sha256": hashlib.sha256(device_der).hexdigest(),
                    "expires_at": int(expires_at),
                    "identity_tag": hashlib.sha256(row["identity_id"].encode("ascii")).hexdigest(),
                    "next_key_version": row["key_version"] + 1,
                    "new_recovery_code_hmac_sha256": new_recovery_digest,
                    "nonce": nonce,
                    "protocol": "IAO-OPERATOR-RECOVERY-V1",
                    "purpose": "REPLACE_ROOT_AND_PRIMARY_DEVICE",
                    "root_key_sha256": hashlib.sha256(root_der).hexdigest(),
                }, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
                db.execute(
                    """INSERT INTO operator_recovery_challenges
                    (challenge_digest,identity_id,recovery_digest,new_recovery_digest,
                     root_public_key_pem,device_public_key_pem,signing_payload,expires_at)
                    VALUES(?,?,?,?,?,?,?,?)""",
                    (self._digest(handle), row["identity_id"], recovery_digest,
                     new_recovery_digest, root_pem, device_pem, payload, expires_at),
                )
                db.execute("COMMIT")
            except Exception:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
        return {
            "challenge": handle,
            "signing_payload": base64.urlsafe_b64encode(payload).decode("ascii").rstrip("="),
            "expires_at": int(expires_at),
            "protocol": "IAO-OPERATOR-RECOVERY-V1",
        }

    def verify_recovered_keypair(
        self, root_public_key_pem: Any, device_public_key_pem: Any,
    ) -> dict[str, Any]:
        """Reconcile an ambiguous recovery response without revealing identity metadata."""
        _, root_pem = self._public_key(root_public_key_pem)
        _, device_pem = self._public_key(device_public_key_pem)
        with self._database() as db:
            row = db.execute(
                """SELECT i.identity_id,i.root_public_key_pem,i.key_version,b.device_public_key_pem,
                b.key_version AS device_key_version
                FROM operator_identities i
                JOIN primary_device_bindings b ON b.identity_id=i.identity_id
                WHERE i.status='ACTIVE'"""
            ).fetchone()
        if (
            row is None
            or row["key_version"] != row["device_key_version"]
            or not hmac.compare_digest(row["root_public_key_pem"], root_pem)
            or not hmac.compare_digest(row["device_public_key_pem"], device_pem)
        ):
            return {"committed": False}
        return {
            "committed": True,
            "identity_id": row["identity_id"],
            "key_version": row["key_version"],
        }

    def complete_operator_recovery(
        self, challenge: Any, root_signature: bytes, device_signature: bytes,
        *, device_replacement=None,
    ) -> dict[str, Any]:
        """Consume recovery proof once, replace both keys, and invalidate all old sessions."""
        if not isinstance(challenge, str) or not 32 <= len(challenge) <= 128:
            raise OperatorIdentityError("INVALID_OPERATOR_RECOVERY_CHALLENGE")
        if (
            not isinstance(root_signature, bytes) or not 64 <= len(root_signature) <= 80
            or not isinstance(device_signature, bytes) or not 64 <= len(device_signature) <= 80
        ):
            raise OperatorIdentityError("INVALID_OPERATOR_RECOVERY_SIGNATURE", 401)
        now = time.time()
        with self.lock, self._database() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute(
                    """SELECT c.*,i.root_public_key_pem AS old_root_key,
                    i.key_version AS old_key_version,i.status AS identity_status,
                    i.recovery_code_digest AS active_recovery_digest,
                    b.device_public_key_pem AS old_device_public_key_pem
                    FROM operator_recovery_challenges c
                    JOIN operator_identities i ON i.identity_id=c.identity_id
                    LEFT JOIN primary_device_bindings b ON b.identity_id=i.identity_id
                    WHERE c.challenge_digest=?""",
                    (self._digest(challenge),),
                ).fetchone()
                if row is None:
                    raise OperatorIdentityError("INVALID_OPERATOR_RECOVERY_CHALLENGE", 404)
                if row["consumed_at"] is not None:
                    raise OperatorIdentityError("OPERATOR_RECOVERY_REPLAYED", 409)
                if row["expires_at"] <= now:
                    raise OperatorIdentityError("OPERATOR_RECOVERY_EXPIRED", 401)
                if (
                    row["active_recovery_digest"] is None
                    or not hmac.compare_digest(row["active_recovery_digest"], row["recovery_digest"])
                    or row["identity_status"] not in ("ACTIVE", "REVOKED")
                ):
                    raise OperatorIdentityError("OPERATOR_RECOVERY_AUTHORITY_CHANGED", 403)
                if db.execute(
                    "SELECT 1 FROM operator_identities WHERE status='ACTIVE' AND identity_id<>?",
                    (row["identity_id"],),
                ).fetchone():
                    raise OperatorIdentityError("ANOTHER_OPERATOR_IDENTITY_ACTIVE", 409)
                root_key = serialization.load_pem_public_key(row["root_public_key_pem"].encode("ascii"))
                device_key = serialization.load_pem_public_key(row["device_public_key_pem"].encode("ascii"))
                device_der = device_key.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                if not hmac.compare_digest(
                    hashlib.sha256(device_der).hexdigest(), row["device_id"],
                ):
                    raise OperatorIdentityError("PRIMARY_DEVICE_NOT_AUTHORIZED", 403)
                if row["purpose"] == "REVOKE" and obj.get("grant_expires_at") is not None:
                    raise OperatorIdentityError("CAPABILITY_PAYLOAD_MISMATCH", 409)
                try:
                    root_key.verify(
                        root_signature, b"IAO-OPERATOR-RECOVERY-V1\x00" + row["signing_payload"],
                        ec.ECDSA(hashes.SHA256()),
                    )
                    device_key.verify(
                        device_signature, b"IAO-OPERATOR-RECOVERY-DEVICE-V1\x00" + row["signing_payload"],
                        ec.ECDSA(hashes.SHA256()),
                    )
                except (InvalidSignature, ValueError, TypeError):
                    raise OperatorIdentityError("INVALID_OPERATOR_RECOVERY_SIGNATURE", 401) from None
                next_version = row["old_key_version"] + 1
                payload_obj = json.loads(row["signing_payload"])
                root_der = root_key.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                device_der = device_key.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                if (
                    payload_obj.get("next_key_version") != next_version
                    or payload_obj.get("new_recovery_code_hmac_sha256") != row["new_recovery_digest"]
                    or payload_obj.get("root_key_sha256") != hashlib.sha256(root_der).hexdigest()
                    or payload_obj.get("device_key_sha256") != hashlib.sha256(device_der).hexdigest()
                    or payload_obj.get("identity_tag") != hashlib.sha256(row["identity_id"].encode("ascii")).hexdigest()
                    or payload_obj.get("expires_at") != int(row["expires_at"])
                    or not isinstance(payload_obj.get("nonce"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", payload_obj["nonce"])
                ):
                    raise OperatorIdentityError("OPERATOR_RECOVERY_AUTHORITY_CHANGED", 409)
                subject = "operator:" + row["identity_id"]
                if device_replacement is None:
                    raise OperatorIdentityError("OPERATOR_RECOVERY_DEVICE_AUTHORITY_UNAVAILABLE", 503)
                # DeviceAuthority commits first. If this DB transaction later
                # fails, the device is orphaned but cannot authenticate; the
                # one-time recovery code remains available for a retry.
                device_replacement(
                    row["device_public_key_pem"], subject,
                    row["old_device_public_key_pem"],
                )
                changed = db.execute(
                    """UPDATE operator_identities SET root_public_key_pem=?,
                    key_version=?,status='ACTIVE',revoked_at=NULL,recovery_code_digest=?,
                    updated_at=? WHERE identity_id=? AND key_version=?""",
                    (row["root_public_key_pem"], next_version, row["new_recovery_digest"], now,
                     row["identity_id"], row["old_key_version"]),
                ).rowcount
                if changed != 1:
                    raise OperatorIdentityError("OPERATOR_RECOVERY_AUTHORITY_CHANGED", 409)
                device_key_obj = serialization.load_pem_public_key(
                    row["device_public_key_pem"].encode("ascii")
                )
                device_der = device_key_obj.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                device_id = hashlib.sha256(device_der).hexdigest()
                db.execute(
                    """INSERT INTO primary_device_bindings
                    (identity_id,device_id,device_public_key_pem,key_version,bound_at)
                    VALUES(?,?,?,?,?) ON CONFLICT(identity_id) DO UPDATE SET
                    device_id=excluded.device_id,
                    device_public_key_pem=excluded.device_public_key_pem,
                    key_version=excluded.key_version,bound_at=excluded.bound_at""",
                    (row["identity_id"], device_id, row["device_public_key_pem"], next_version, now),
                )
                db.execute(
                    "DELETE FROM operator_session_bindings WHERE identity_id=?",
                    (row["identity_id"],),
                )
                db.execute(
                    "DELETE FROM operator_session_challenges WHERE identity_id=?",
                    (row["identity_id"],),
                )
                db.execute(
                    "DELETE FROM operator_login_challenges WHERE identity_id=?",
                    (row["identity_id"],),
                )
                db.execute(
                    "UPDATE operator_recovery_challenges SET consumed_at=? WHERE challenge_digest=? AND consumed_at IS NULL",
                    (now, self._digest(challenge)),
                )
                db.execute("COMMIT")
            except Exception:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
        return {
            "authority": "OPERATOR_RECOVERED_READ_ONLY",
            "key_version": next_version,
            "device_replaced": True,
            "recovery_code_rotated": True,
        }

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
    def verify_bootstrap_root_signature(
        root_public_key_pem: Any, device_public_key_pem: Any, signature: bytes,
    ) -> bool:
        """Verify root possession before consuming the one-time bootstrap capability."""
        if not isinstance(signature, bytes) or not 64 <= len(signature) <= 80:
            raise OperatorIdentityError("INVALID_OPERATOR_BOOTSTRAP_SIGNATURE", 401)
        root_key, root_pem = OperatorIdentityAuthority._public_key(root_public_key_pem)
        device_key, device_pem = OperatorIdentityAuthority._public_key(device_public_key_pem)
        root_der = root_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        device_der = device_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if hmac.compare_digest(
            hashlib.sha256(root_der).digest(), hashlib.sha256(device_der).digest(),
        ):
            raise OperatorIdentityError("OPERATOR_BOOTSTRAP_KEYS_MUST_BE_DISTINCT", 400)
        _, payload = OperatorIdentityAuthority.device_binding_payload(
            device_pem, key_version=1,
        )
        try:
            root_key.verify(
                signature, ROOT_SIGNATURE_DOMAIN + payload,
                ec.ECDSA(hashes.SHA256()),
            )
        except (InvalidSignature, ValueError, TypeError):
            raise OperatorIdentityError("INVALID_OPERATOR_BOOTSTRAP_SIGNATURE", 401) from None
        return True

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

    def revoke(
        self, identity_id: str, signature: bytes, *, expected_key_version: int,
        device_revocation=None,
    ) -> None:
        payload = b"revoke-root-v1\n" + identity_id.encode("ascii")
        self.verify_root_signature(
            identity_id, payload, signature,
            expected_key_version=expected_key_version,
        )
        now = time.time()
        with self.lock, self._database() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                if device_revocation is not None:
                    binding = db.execute(
                        "SELECT device_public_key_pem FROM primary_device_bindings WHERE identity_id=?",
                        (identity_id,),
                    ).fetchone()
                    if binding is not None:
                        # Deactivate the device first. If the root transaction
                        # subsequently fails, the result is fail-closed.
                        with device_revocation(binding["device_public_key_pem"]):
                            pass
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
                db.execute(
                    "DELETE FROM operator_login_challenges WHERE expires_at <= ?",
                    (now,),
                )
                active_challenges = db.execute(
                    """SELECT COUNT(*) FROM operator_login_challenges
                    WHERE consumed_at IS NULL AND expires_at > ?""",
                    (now,),
                ).fetchone()[0]
                if active_challenges >= 100:
                    raise OperatorIdentityError("OPERATOR_LOGIN_CHALLENGE_LIMIT", 429)
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
        token_key: str, *, ttl_seconds: int = 900, device_owner_binding=None,
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
                subject = "operator:" + row["identity_id"]
                owner_context = (
                    device_owner_binding(subject, row["device_public_key_pem"])
                    if device_owner_binding is not None else nullcontext()
                )
                with owner_context:
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
                if db.in_transaction:
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

    # ---- explicit operator capability grants ----
    def create_capability_challenge(
        self, subject: Any, session_token: Any, device_id: Any,
        capability: Any, policy_version: Any, *, purpose: str = "GRANT",
        grant_id: Any = None, ttl_seconds: int = 90,
        grant_ttl_seconds: int = 900,
    ) -> dict[str, Any]:
        grantable = {"knowledge.search"}
        if purpose not in {"GRANT", "REVOKE"}:
            raise OperatorIdentityError("INVALID_CAPABILITY_PURPOSE")
        if not isinstance(capability, str) or capability not in grantable:
            raise OperatorIdentityError("CAPABILITY_NOT_GRANTABLE", 403)
        if not isinstance(policy_version, str) or not 1 <= len(policy_version) <= 128:
            raise OperatorIdentityError("INVALID_POLICY_VERSION")
        if not isinstance(device_id, str) or not re.fullmatch(r"[0-9a-f]{64}", device_id):
            raise OperatorIdentityError("PRIMARY_DEVICE_NOT_AUTHORIZED", 403)
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not 30 <= ttl_seconds <= 120:
            raise OperatorIdentityError("INVALID_CAPABILITY_CHALLENGE_TTL")
        if purpose == "REVOKE" and (
            not isinstance(grant_id, str) or not re.fullmatch(r"[0-9a-f]{32}", grant_id)
        ):
            raise OperatorIdentityError("INVALID_CAPABILITY_GRANT_ID")
        if purpose == "GRANT" and grant_id is not None:
            raise OperatorIdentityError("INVALID_CAPABILITY_GRANT_ID")
        subject_digest = self._session_subject_digest(subject)
        session_digest = self._session_credential_digest(session_token)
        if not self.verify_authenticated_session(subject, session_token):
            raise OperatorIdentityError("OPERATOR_SESSION_NOT_BOUND", 403)
        self.verify_primary_device_for_session(subject, session_token, device_id)
        now = time.time()
        expires_at = int(now + ttl_seconds)
        handle, nonce = secrets.token_urlsafe(32), secrets.token_hex(32)
        with self.lock, self._database() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                root = db.execute(
                    """SELECT i.identity_id,i.key_version,i.status,
                    p.device_id,p.key_version AS device_key_version,
                    s.subject_digest,s.session_digest
                    FROM operator_identities i
                    JOIN primary_device_bindings p ON p.identity_id=i.identity_id
                    JOIN operator_session_bindings s ON s.identity_id=i.identity_id
                    WHERE i.status='ACTIVE'"""
                ).fetchone()
                if (
                    root is None or root["key_version"] != root["device_key_version"]
                    or not hmac.compare_digest(root["device_id"], device_id)
                    or not hmac.compare_digest(root["subject_digest"], subject_digest)
                    or not isinstance(root["session_digest"], str)
                    or not hmac.compare_digest(root["session_digest"], session_digest)
                ):
                    raise OperatorIdentityError("PRIMARY_DEVICE_NOT_AUTHORIZED", 403)
                if purpose == "REVOKE":
                    grant = db.execute(
                        """SELECT capability FROM operator_capability_grants
                        WHERE grant_id=? AND identity_id=? AND subject_digest=?
                        AND session_digest=? AND device_id=? AND revoked_at IS NULL
                        AND expires_at>?""",
                        (grant_id, root["identity_id"], subject_digest, session_digest, device_id, now),
                    ).fetchone()
                    if grant is None or grant["capability"] != capability:
                        raise OperatorIdentityError("CAPABILITY_GRANT_NOT_ACTIVE", 404)
                active = db.execute(
                    """SELECT COUNT(*) FROM operator_capability_challenges
                    WHERE identity_id=? AND consumed_at IS NULL AND expires_at>?""",
                    (root["identity_id"], now),
                ).fetchone()[0]
                if active >= 5:
                    raise OperatorIdentityError("CAPABILITY_CHALLENGE_LIMIT", 429)
                payload_obj = {
                    "capability": capability,
                    "device_id": device_id,
                    "expires_at": expires_at,
                    "grant_expires_at": int(now + grant_ttl_seconds) if purpose == "GRANT" else None,
                    "grant_id": grant_id,
                    "identity_tag": hashlib.sha256(root["identity_id"].encode("ascii")).hexdigest(),
                    "key_version": root["key_version"],
                    "nonce": nonce,
                    "policy_version": policy_version,
                    "protocol": "IAO-OPERATOR-CAPABILITY-GRANT-V1",
                    "purpose": purpose,
                    "session_digest": session_digest,
                    "subject_digest": subject_digest,
                }
                payload = json.dumps(
                    payload_obj, sort_keys=True, separators=(",", ":"),
                    ensure_ascii=True,
                ).encode("ascii")
                db.execute(
                    """INSERT INTO operator_capability_challenges
                    (challenge_digest,identity_id,subject_digest,session_digest,device_id,
                     capability,policy_version,purpose,grant_id,signing_payload,key_version,expires_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        self._digest(handle), root["identity_id"], subject_digest,
                        session_digest, device_id, capability, policy_version,
                        purpose, grant_id, payload, root["key_version"], expires_at,
                    ),
                )
                db.execute("COMMIT")
            except Exception:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
        return {
            "challenge": handle,
            "signing_payload": base64.urlsafe_b64encode(payload).decode("ascii").rstrip("="),
            "expires_at": expires_at,
            "grant_expires_at": payload_obj["grant_expires_at"],
            "key_version": root["key_version"],
            "capability": capability,
            "purpose": purpose,
            "policy_version": policy_version,
            "protocol": "IAO-OPERATOR-CAPABILITY-GRANT-V1",
        }

    def complete_capability_challenge(
        self, subject: Any, session_token: Any, challenge: Any,
        root_signature: bytes, device_signature: bytes, *,
        policy_version: str,
    ) -> dict[str, Any]:
        if not isinstance(challenge, str) or not 32 <= len(challenge) <= 128:
            raise OperatorIdentityError("INVALID_CAPABILITY_CHALLENGE")
        if (
            not isinstance(root_signature, bytes) or not 64 <= len(root_signature) <= 80
            or not isinstance(device_signature, bytes) or not 64 <= len(device_signature) <= 80
        ):
            raise OperatorIdentityError("INVALID_CAPABILITY_SIGNATURE", 401)
        if not isinstance(policy_version, str) or not 1 <= len(policy_version) <= 128:
            raise OperatorIdentityError("INVALID_POLICY_VERSION")
        if isinstance(grant_ttl_seconds, bool) or not isinstance(grant_ttl_seconds, int) or not 60 <= grant_ttl_seconds <= 900:
            raise OperatorIdentityError("INVALID_CAPABILITY_GRANT_TTL")
        subject_digest = self._session_subject_digest(subject)
        session_digest = self._session_credential_digest(session_token)
        now = time.time()
        new_grant_id = uuid.uuid4().hex
        with self.lock, self._database() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute(
                    """SELECT c.*,i.root_public_key_pem,i.key_version AS active_key_version,
                    i.status,p.device_public_key_pem,p.device_id AS active_device_id,
                    p.key_version AS device_key_version,s.subject_digest AS active_subject_digest,
                    s.session_digest AS active_session_digest
                    FROM operator_capability_challenges c
                    JOIN operator_identities i ON i.identity_id=c.identity_id
                    JOIN primary_device_bindings p ON p.identity_id=i.identity_id
                    JOIN operator_session_bindings s ON s.identity_id=i.identity_id
                    WHERE c.challenge_digest=?""",
                    (self._digest(challenge),),
                ).fetchone()
                if row is None or row["consumed_at"] is not None:
                    raise OperatorIdentityError("INVALID_CAPABILITY_CHALLENGE", 404)
                if row["expires_at"] <= now:
                    raise OperatorIdentityError("CAPABILITY_CHALLENGE_EXPIRED", 401)
                if (
                    row["status"] != "ACTIVE"
                    or row["key_version"] != row["active_key_version"]
                    or row["key_version"] != row["device_key_version"]
                    or row["policy_version"] != policy_version
                    or not hmac.compare_digest(row["device_id"], row["active_device_id"])
                    or not hmac.compare_digest(row["subject_digest"], subject_digest)
                    or not hmac.compare_digest(row["session_digest"], session_digest)
                    or not hmac.compare_digest(row["active_subject_digest"], subject_digest)
                    or not isinstance(row["active_session_digest"], str)
                    or not hmac.compare_digest(row["active_session_digest"], session_digest)
                ):
                    raise OperatorIdentityError("CAPABILITY_AUTHORITY_CHANGED", 409)
                payload = bytes(row["signing_payload"])
                obj = json.loads(payload.decode("ascii"))
                if (
                    obj.get("capability") != row["capability"]
                    or obj.get("device_id") != row["device_id"]
                    or obj.get("expires_at") != int(row["expires_at"])
                    or obj.get("grant_id") != row["grant_id"]
                    or obj.get("key_version") != row["key_version"]
                    or obj.get("policy_version") != row["policy_version"]
                    or obj.get("purpose") != row["purpose"]
                    or obj.get("session_digest") != session_digest
                    or obj.get("subject_digest") != subject_digest
                    or obj.get("identity_tag") != hashlib.sha256(row["identity_id"].encode("ascii")).hexdigest()
                ):
                    raise OperatorIdentityError("CAPABILITY_PAYLOAD_MISMATCH", 409)
                root_key = serialization.load_pem_public_key(row["root_public_key_pem"].encode("ascii"))
                device_key = serialization.load_pem_public_key(row["device_public_key_pem"].encode("ascii"))
                try:
                    root_key.verify(root_signature, ROOT_SIGNATURE_DOMAIN + payload, ec.ECDSA(hashes.SHA256()))
                    device_key.verify(
                        device_signature,
                        b"IAO-OPERATOR-CAPABILITY-GRANT-DEVICE-V1\x00" + payload,
                        ec.ECDSA(hashes.SHA256()),
                    )
                except (InvalidSignature, ValueError, TypeError):
                    raise OperatorIdentityError("INVALID_CAPABILITY_SIGNATURE", 401) from None
                changed = db.execute(
                    """UPDATE operator_capability_challenges SET consumed_at=?
                    WHERE challenge_digest=? AND consumed_at IS NULL AND expires_at>?""",
                    (now, self._digest(challenge), now),
                ).rowcount
                if changed != 1:
                    raise OperatorIdentityError("CAPABILITY_CHALLENGE_REPLAYED", 409)
                if row["purpose"] == "GRANT":
                    grant_expires = obj.get("grant_expires_at")
                    if (
                        isinstance(grant_expires, bool) or not isinstance(grant_expires, int)
                        or not now < grant_expires <= now + 900
                    ):
                        raise OperatorIdentityError("INVALID_CAPABILITY_GRANT_EXPIRY")
                    db.execute(
                        """INSERT INTO operator_capability_grants
                        (grant_id,identity_id,subject_digest,session_digest,device_id,
                         capability,policy_version,key_version,created_at,expires_at,
                         revoked_at,challenge_digest)
                        VALUES(?,?,?,?,?,?,?,?,?,?,NULL,?)""",
                        (
                            new_grant_id, row["identity_id"], subject_digest, session_digest,
                            row["device_id"], row["capability"], row["policy_version"],
                            row["key_version"], now, grant_expires, self._digest(challenge),
                        ),
                    )
                elif row["purpose"] == "REVOKE":
                    changed = db.execute(
                        """UPDATE operator_capability_grants SET revoked_at=?
                        WHERE grant_id=? AND identity_id=? AND session_digest=?
                        AND subject_digest=? AND device_id=? AND capability=?
                        AND key_version=? AND policy_version=? AND revoked_at IS NULL
                        AND expires_at>?""",
                        (
                            now, row["grant_id"], row["identity_id"],
                            row["session_digest"], row["subject_digest"],
                            row["device_id"], row["capability"], row["key_version"],
                            row["policy_version"], now,
                        ),
                    ).rowcount
                    if changed != 1:
                        raise OperatorIdentityError("CAPABILITY_GRANT_NOT_ACTIVE", 409)
                else:
                    raise OperatorIdentityError("INVALID_CAPABILITY_PURPOSE")
                db.execute("COMMIT")
            except Exception:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
        if row["purpose"] == "REVOKE":
            return {
                "authority": "OPERATOR_CAPABILITY_REVOKED",
                "capability": row["capability"],
                "revoked": True,
            }
        return {
            "authority": "OPERATOR_CAPABILITY_GRANTED",
            "capability": row["capability"],
            "expires_at": grant_expires,
            "grant_id": new_grant_id,
            "key_version": row["key_version"],
        }

    def active_capabilities_for_session(
        self, subject: Any, session_token: Any, *, policy_version: str,
    ) -> frozenset[str]:
        subject_digest = self._session_subject_digest(subject)
        session_digest = self._session_credential_digest(session_token)
        if not self.verify_authenticated_session(subject, session_token):
            return frozenset()
        with self._database() as db:
            rows = db.execute(
                """SELECT g.capability FROM operator_capability_grants g
                JOIN operator_identities i ON i.identity_id=g.identity_id
                JOIN primary_device_bindings p ON p.identity_id=i.identity_id
                JOIN operator_session_bindings s ON s.identity_id=i.identity_id
                WHERE i.status='ACTIVE' AND g.subject_digest=? AND g.session_digest=?
                AND g.device_id=p.device_id AND g.key_version=i.key_version
                AND p.key_version=i.key_version AND s.subject_digest=?
                AND s.session_digest=? AND g.policy_version=? AND g.revoked_at IS NULL
                AND g.expires_at>?""",
                (subject_digest, session_digest, subject_digest, session_digest,
                 policy_version, time.time()),
            ).fetchall()
        return frozenset(row["capability"] for row in rows)

    def active_capabilities_for_session_digest(
        self, subject: Any, session_digest: Any, device_id: Any, *,
        policy_version: str,
    ) -> frozenset[str]:
        subject_digest = self._session_subject_digest(subject)
        if (
            not isinstance(session_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", session_digest)
            or not isinstance(device_id, str) or not re.fullmatch(r"[0-9a-f]{64}", device_id)
        ):
            return frozenset()
        with self._database() as db:
            rows = db.execute(
                """SELECT g.capability FROM operator_capability_grants g
                JOIN operator_identities i ON i.identity_id=g.identity_id
                JOIN primary_device_bindings p ON p.identity_id=i.identity_id
                JOIN operator_session_bindings s ON s.identity_id=i.identity_id
                WHERE i.status='ACTIVE' AND g.subject_digest=? AND g.session_digest=?
                AND s.subject_digest=? AND s.session_digest=?
                AND g.device_id=? AND p.device_id=? AND g.key_version=i.key_version
                AND p.key_version=i.key_version AND g.policy_version=?
                AND g.revoked_at IS NULL AND g.expires_at>?""",
                (subject_digest, session_digest, subject_digest, session_digest,
                 device_id, device_id, policy_version, time.time()),
            ).fetchall()
        return frozenset(row["capability"] for row in rows)

    def list_capability_grants_for_session(
        self, subject: Any, session_token: Any, *, policy_version: str,
    ) -> list[dict[str, Any]]:
        subject_digest = self._session_subject_digest(subject)
        session_digest = self._session_credential_digest(session_token)
        with self._database() as db:
            rows = db.execute(
                """SELECT grant_id,capability,created_at,expires_at,revoked_at
                FROM operator_capability_grants WHERE subject_digest=?
                AND session_digest=? AND policy_version=? ORDER BY created_at DESC LIMIT 20""",
                (subject_digest, session_digest, policy_version),
            ).fetchall()
        return [
            {
                "grant_id": row["grant_id"], "capability": row["capability"],
                "created_at": int(row["created_at"]), "expires_at": int(row["expires_at"]),
                "revoked": row["revoked_at"] is not None,
                "active": row["revoked_at"] is None and row["expires_at"] > time.time(),
            }
            for row in rows
        ]

