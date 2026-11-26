"""Single-device, challenge-bound ECDSA authority for the public IAO client.

Enrollment is disabled unless an operator supplies a one-time secret through
IAO_DEVICE_ENROLLMENT_CODE. The server stores only the public key. This module
currently verifies READ-ONLY status proofs; it does not grant command execution.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class DeviceAuthorityError(RuntimeError):
    def __init__(self, code: str, status: int = 400) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


class DeviceAuthority:
    def __init__(self, database: str | Path, enrollment_code: str = "") -> None:
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.enrollment_code = enrollment_code
        self.lock = threading.RLock()
        with self._database() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    device_id TEXT PRIMARY KEY,
                    public_key_pem TEXT NOT NULL,
                    active INTEGER NOT NULL CHECK(active IN (0,1)),
                    created_at REAL NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS one_active_iao_device
                    ON devices(active) WHERE active=1;
                CREATE TABLE IF NOT EXISTS used_enrollment_codes (
                    code_digest TEXT PRIMARY KEY,
                    used_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS device_challenges (
                    nonce TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL REFERENCES devices(device_id),
                    expires_at REAL NOT NULL,
                    consumed_at REAL
                );
                CREATE INDEX IF NOT EXISTS device_challenges_expiry
                    ON device_challenges(expires_at);
                """
            )
        try:
            self.database.chmod(0o600)
        except OSError:
            pass

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
    def _code_digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def enroll(self, code: Any, public_key_pem: Any) -> dict[str, str]:
        if not isinstance(self.enrollment_code, str) or len(self.enrollment_code) < 32:
            raise DeviceAuthorityError("DEVICE_ENROLLMENT_DISABLED", 503)
        if not isinstance(code, str) or not hmac.compare_digest(
            self._code_digest(code), self._code_digest(self.enrollment_code)
        ):
            raise DeviceAuthorityError("INVALID_ENROLLMENT_CODE", 403)
        if not isinstance(public_key_pem, str) or len(public_key_pem) > 4096:
            raise DeviceAuthorityError("INVALID_PUBLIC_KEY")
        try:
            key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        except (ValueError, TypeError, UnicodeEncodeError):
            raise DeviceAuthorityError("INVALID_PUBLIC_KEY") from None
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
            key.curve, ec.SECP256R1
        ):
            raise DeviceAuthorityError("UNSUPPORTED_PUBLIC_KEY")
        der = key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        device_id = hashlib.sha256(der).hexdigest()
        digest = self._code_digest(code)
        with self.lock, self._database() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                if db.execute(
                    "SELECT 1 FROM used_enrollment_codes WHERE code_digest=?",
                    (digest,),
                ).fetchone():
                    raise DeviceAuthorityError("ENROLLMENT_CODE_ALREADY_USED", 409)
                if db.execute(
                    "SELECT 1 FROM devices WHERE active=1"
                ).fetchone():
                    raise DeviceAuthorityError("PRIMARY_DEVICE_ALREADY_ENROLLED", 409)
                now = time.time()
                db.execute(
                    "INSERT INTO used_enrollment_codes(code_digest,used_at) VALUES(?,?)",
                    (digest, now),
                )
                db.execute(
                    "INSERT INTO devices(device_id,public_key_pem,active,created_at) VALUES(?,?,1,?)",
                    (device_id, public_key_pem, now),
                )
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise
        return {"device_id": device_id, "algorithm": "ECDSA-P256-SHA256"}

    def challenge(self, device_id: Any) -> dict[str, str]:
        if not isinstance(device_id, str) or not re.fullmatch(r"[0-9a-f]{64}", device_id):
            raise DeviceAuthorityError("INVALID_DEVICE_ID")
        nonce = secrets.token_hex(32)
        now = time.time()
        with self.lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT active FROM devices WHERE device_id=?", (device_id,)
            ).fetchone()
            if row is None or row["active"] != 1:
                db.execute("ROLLBACK")
                raise DeviceAuthorityError("DEVICE_NOT_FOUND", 404)
            db.execute(
                "INSERT INTO device_challenges(nonce,device_id,expires_at) VALUES(?,?,?)",
                (nonce, device_id, now + 60),
            )
            db.execute(
                "DELETE FROM device_challenges WHERE expires_at < ?", (now - 300,)
            )
            db.execute("COMMIT")
        return {"nonce": nonce, "expires_in": 60}

    def verify_status(self, payload: Any) -> dict[str, str]:
        if not isinstance(payload, dict):
            raise DeviceAuthorityError("INVALID_REQUEST")
        device_id = payload.get("device_id")
        nonce = payload.get("nonce")
        timestamp = payload.get("timestamp")
        action = payload.get("action")
        signature = payload.get("signature")
        if (
            not isinstance(device_id, str)
            or not re.fullmatch(r"[0-9a-f]{64}", device_id)
            or not isinstance(nonce, str)
            or not re.fullmatch(r"[0-9a-f]{64}", nonce)
            or isinstance(timestamp, bool)
            or not isinstance(timestamp, int)
            or not isinstance(action, str)
            or action != "status"
            or not isinstance(signature, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{80,160}", signature)
        ):
            raise DeviceAuthorityError("INVALID_REQUEST")
        now = time.time()
        if abs(now - timestamp) > 60:
            raise DeviceAuthorityError("DEVICE_TIMESTAMP_EXPIRED", 401)
        try:
            raw_signature = base64.urlsafe_b64decode(
                signature + "=" * (-len(signature) % 4)
            )
        except (ValueError, TypeError):
            raise DeviceAuthorityError("INVALID_SIGNATURE", 401) from None

        canonical = json.dumps(
            {"action": action}, separators=(",", ":"), ensure_ascii=False
        )
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        signed_text = "\n".join(
            ["POST", "/v1/device/command", str(timestamp), nonce, digest]
        ).encode("utf-8")

        with self.lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """
                SELECT d.public_key_pem, d.active, c.expires_at, c.consumed_at
                FROM devices d JOIN device_challenges c ON c.device_id=d.device_id
                WHERE d.device_id=? AND c.nonce=?
                """,
                (device_id, nonce),
            ).fetchone()
            if row is None or row["active"] != 1:
                db.execute("ROLLBACK")
                raise DeviceAuthorityError("DEVICE_OR_CHALLENGE_NOT_FOUND", 404)
            if row["consumed_at"] is not None or row["expires_at"] < now:
                db.execute("ROLLBACK")
                raise DeviceAuthorityError("CHALLENGE_EXPIRED_OR_REPLAYED", 401)
            try:
                public_key = serialization.load_pem_public_key(
                    row["public_key_pem"].encode("ascii")
                )
                if not isinstance(public_key, ec.EllipticCurvePublicKey):
                    raise ValueError("wrong key type")
                public_key.verify(
                    raw_signature,
                    signed_text,
                    ec.ECDSA(hashes.SHA256()),
                )
            except (InvalidSignature, ValueError, TypeError):
                db.execute("ROLLBACK")
                raise DeviceAuthorityError("INVALID_DEVICE_SIGNATURE", 401) from None
            db.execute(
                "UPDATE device_challenges SET consumed_at=? WHERE nonce=? AND consumed_at IS NULL",
                (now, nonce),
            )
            db.execute("COMMIT")
        return {
            "action": "status",
            "authority": "READ_ONLY_DEVICE_VERIFIED",
            "device_id": device_id,
        }
