"""Single-device, challenge-bound ECDSA authority for the public IAO client.

Enrollment is disabled unless an operator supplies a one-time secret through
IAO_DEVICE_ENROLLMENT_CODE. The server stores only the public key. Request
proof verification authenticates exact requests but grants no capability.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import stat
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

MAX_ACTIVE_CHALLENGES_PER_DEVICE = 5
CHALLENGE_TTL_SECONDS = 60


class DeviceAuthorityError(RuntimeError):
    def __init__(self, code: str, status: int = 400) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


class DeviceAuthority:
    def __init__(self, database: str | Path, enrollment_code: str = "") -> None:
        self.database = Path(database)
        parent = self.database.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # The database contains the enrolled device's public identity and
        # replay-protection state. Refuse path substitution and keep both the
        # directory and SQLite files private before SQLite opens them.
        if parent.is_symlink() or self.database.is_symlink():
            raise RuntimeError("DEVICE_AUTHORITY_SYMLINK_REFUSED")
        if self.database.exists() and not self.database.is_file():
            raise RuntimeError("DEVICE_AUTHORITY_PATH_NOT_REGULAR_FILE")
        os.chmod(parent, 0o700)
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(str(self.database), flags, 0o600)
        except OSError as exc:
            raise RuntimeError("DEVICE_AUTHORITY_DATABASE_OPEN_FAILED") from exc
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise RuntimeError("DEVICE_AUTHORITY_PATH_NOT_REGULAR_FILE")
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        self.enrollment_code = enrollment_code
        self.lock = threading.RLock()
        with self._database() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    device_id TEXT PRIMARY KEY,
                    public_key_pem TEXT NOT NULL,
                    owner_subject TEXT,
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
                CREATE INDEX IF NOT EXISTS device_challenges_device_active
                    ON device_challenges(device_id, expires_at)
                    WHERE consumed_at IS NULL;
                """
            )
            columns = {row["name"] for row in db.execute("PRAGMA table_info(devices)")}
            if "owner_subject" not in columns:
                # Legacy devices without an owner binding fail closed.
                db.execute("ALTER TABLE devices ADD COLUMN owner_subject TEXT")
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
    def _code_digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def enroll(self, code: Any, public_key_pem: Any, *, owner_subject: str) -> dict[str, str]:
        if not isinstance(self.enrollment_code, str) or len(self.enrollment_code) < 32:
            raise DeviceAuthorityError("DEVICE_ENROLLMENT_DISABLED", 503)
        if not isinstance(code, str) or not hmac.compare_digest(
            self._code_digest(code), self._code_digest(self.enrollment_code)
        ):
            raise DeviceAuthorityError("INVALID_ENROLLMENT_CODE", 403)
        if (
            not isinstance(owner_subject, str)
            or not owner_subject
            or owner_subject.startswith("guest:")
            or len(owner_subject) > 256
        ):
            raise DeviceAuthorityError("OPERATOR_SESSION_REQUIRED", 403)
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
                    "INSERT INTO devices(device_id,public_key_pem,owner_subject,active,created_at) VALUES(?,?,?,1,?)",
                    (device_id, public_key_pem, owner_subject, now),
                )
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise
        return {"device_id": device_id, "algorithm": "ECDSA-P256-SHA256"}

    @staticmethod
    def verify_bootstrap_device_signature(public_key_pem: Any, signature: bytes) -> bool:
        """Verify possession of the device key over the canonical version-one binding statement."""
        if not isinstance(public_key_pem, str) or not 1 <= len(public_key_pem) <= 4096:
            raise DeviceAuthorityError("INVALID_PUBLIC_KEY")
        if not isinstance(signature, bytes) or not 64 <= len(signature) <= 80:
            raise DeviceAuthorityError("INVALID_BOOTSTRAP_DEVICE_SIGNATURE", 401)
        try:
            key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        except (ValueError, TypeError, UnicodeEncodeError):
            raise DeviceAuthorityError("INVALID_PUBLIC_KEY") from None
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise DeviceAuthorityError("UNSUPPORTED_PUBLIC_KEY")
        der = key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        device_id = hashlib.sha256(der).hexdigest()
        payload = json.dumps({
            "device_id": device_id,
            "key_version": 1,
            "protocol": "IAO-DEVICE-BINDING-V1",
            "public_key_sha256": device_id,
            "role": "PRIMARY",
        }, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        try:
            key.verify(
                signature,
                b"IAO-OPERATOR-BOOTSTRAP-DEVICE-V1\x00" + payload,
                ec.ECDSA(hashes.SHA256()),
            )
        except (InvalidSignature, ValueError, TypeError):
            raise DeviceAuthorityError("INVALID_BOOTSTRAP_DEVICE_SIGNATURE", 401) from None
        return True

    def preflight_bootstrap_device(
        self, public_key_pem: Any, signature: bytes,
    ) -> bool:
        """Validate device possession and ensure bootstrap can claim the sole device slot."""
        self.verify_bootstrap_device_signature(public_key_pem, signature)
        try:
            key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        except (ValueError, TypeError, UnicodeEncodeError):
            raise DeviceAuthorityError("INVALID_PUBLIC_KEY") from None
        der = key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        device_id = hashlib.sha256(der).hexdigest()
        with self._database() as db:
            if db.execute("SELECT 1 FROM devices WHERE active=1").fetchone():
                raise DeviceAuthorityError("PRIMARY_DEVICE_ALREADY_ENROLLED", 409)
            if db.execute(
                "SELECT 1 FROM devices WHERE device_id=?", (device_id,)
            ).fetchone():
                raise DeviceAuthorityError("DEVICE_KEY_PREVIOUSLY_ENROLLED", 409)
        return True

    def enroll_bootstrap_primary_device(
        self, public_key_pem: Any, *, owner_subject: str, signature: bytes,
    ) -> dict[str, str]:
        """Enroll the first device only with proof of its private key over the root binding statement."""
        if (
            not isinstance(owner_subject, str)
            or not re.fullmatch(r"operator:[0-9a-f]{32}", owner_subject)
        ):
            raise DeviceAuthorityError("INVALID_OPERATOR_SUBJECT", 403)
        if not isinstance(public_key_pem, str) or not 1 <= len(public_key_pem) <= 4096:
            raise DeviceAuthorityError("INVALID_PUBLIC_KEY")
        if not isinstance(signature, bytes) or not 64 <= len(signature) <= 80:
            raise DeviceAuthorityError("INVALID_BOOTSTRAP_DEVICE_SIGNATURE", 401)
        try:
            key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        except (ValueError, TypeError, UnicodeEncodeError):
            raise DeviceAuthorityError("INVALID_PUBLIC_KEY") from None
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise DeviceAuthorityError("UNSUPPORTED_PUBLIC_KEY")
        der = key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        device_id = hashlib.sha256(der).hexdigest()
        payload = json.dumps({
            "device_id": device_id,
            "key_version": 1,
            "protocol": "IAO-DEVICE-BINDING-V1",
            "public_key_sha256": device_id,
            "role": "PRIMARY",
        }, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        try:
            key.verify(
                signature,
                b"IAO-OPERATOR-BOOTSTRAP-DEVICE-V1\x00" + payload,
                ec.ECDSA(hashes.SHA256()),
            )
        except (InvalidSignature, ValueError, TypeError):
            raise DeviceAuthorityError("INVALID_BOOTSTRAP_DEVICE_SIGNATURE", 401) from None
        canonical = key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        now = time.time()
        with self.lock, self._database() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                if db.execute("SELECT 1 FROM devices WHERE active=1").fetchone():
                    raise DeviceAuthorityError("PRIMARY_DEVICE_ALREADY_ENROLLED", 409)
                if db.execute(
                    "SELECT 1 FROM devices WHERE device_id=?", (device_id,)
                ).fetchone():
                    raise DeviceAuthorityError("DEVICE_KEY_PREVIOUSLY_ENROLLED", 409)
                db.execute(
                    """INSERT INTO devices
                    (device_id,public_key_pem,owner_subject,active,created_at)
                    VALUES(?,?,?,1,?)""",
                    (device_id, canonical, owner_subject, now),
                )
                db.execute("COMMIT")
            except Exception:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
        return {"device_id": device_id, "algorithm": "ECDSA-P256-SHA256"}

    def verify_registered_public_key(
        self, public_key_pem: Any, *, owner_subject: str,
    ) -> bool:
        """Confirm this exact public key is the active key enrolled by this owner."""
        if not isinstance(public_key_pem, str) or not 1 <= len(public_key_pem) <= 4096:
            raise DeviceAuthorityError("INVALID_PUBLIC_KEY")
        try:
            key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        except (ValueError, TypeError, UnicodeEncodeError):
            raise DeviceAuthorityError("INVALID_PUBLIC_KEY") from None
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
            key.curve, ec.SECP256R1
        ):
            raise DeviceAuthorityError("UNSUPPORTED_PUBLIC_KEY")
        canonical = key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        with self._database() as db:
            rows = db.execute(
                "SELECT public_key_pem,owner_subject FROM devices WHERE active=1"
            ).fetchall()
        matches = [
            row for row in rows
            if isinstance(row["owner_subject"], str)
            and hmac.compare_digest(row["owner_subject"], owner_subject)
            and hmac.compare_digest(row["public_key_pem"], canonical)
        ]
        if len(matches) != 1:
            raise DeviceAuthorityError("DEVICE_KEY_NOT_ENROLLED_FOR_OWNER", 403)
        return True

    @contextmanager
    def bind_active_key_to_operator(self, public_key_pem: Any, *, owner_subject: str):
        """Atomically transfer the active enrolled key to its root-authenticated principal.

        The caller must invoke this only after verifying both root and device
        signatures. The write transaction remains open until the caller's
        operator-identity transaction has committed.
        """
        if (
            not isinstance(owner_subject, str)
            or not re.fullmatch(r"operator:[0-9a-f]{32}", owner_subject)
        ):
            raise DeviceAuthorityError("INVALID_OPERATOR_SUBJECT", 403)
        if not isinstance(public_key_pem, str) or not 1 <= len(public_key_pem) <= 4096:
            raise DeviceAuthorityError("INVALID_PUBLIC_KEY")
        try:
            key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        except (ValueError, TypeError, UnicodeEncodeError):
            raise DeviceAuthorityError("INVALID_PUBLIC_KEY") from None
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise DeviceAuthorityError("UNSUPPORTED_PUBLIC_KEY")
        canonical = key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        with self.lock, self._database() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                rows = db.execute(
                    "SELECT device_id,owner_subject FROM devices WHERE public_key_pem=? AND active=1",
                    (canonical,),
                ).fetchall()
                if len(rows) != 1:
                    raise DeviceAuthorityError("DEVICE_KEY_NOT_ACTIVE", 403)
                db.execute(
                    "UPDATE devices SET owner_subject=? WHERE device_id=? AND active=1",
                    (owner_subject, rows[0]["device_id"]),
                )
                yield True
                db.execute("COMMIT")
            except Exception:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise

    def replace_active_device_for_recovery(
        self, public_key_pem: Any, *, owner_subject: str,
        expected_old_public_key_pem: Any = None,
    ) -> dict[str, str]:
        """Install a replacement primary key after the recovery authority has verified its one-time proof.

        Existing active keys are replaced only when already owned by this same
        opaque operator principal. An unrelated active device blocks recovery.
        """
        if (
            not isinstance(owner_subject, str)
            or not re.fullmatch(r"operator:[0-9a-f]{32}", owner_subject)
        ):
            raise DeviceAuthorityError("INVALID_OPERATOR_SUBJECT", 403)
        if not isinstance(public_key_pem, str) or not 1 <= len(public_key_pem) <= 4096:
            raise DeviceAuthorityError("INVALID_PUBLIC_KEY")
        try:
            key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        except (ValueError, TypeError, UnicodeEncodeError):
            raise DeviceAuthorityError("INVALID_PUBLIC_KEY") from None
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise DeviceAuthorityError("UNSUPPORTED_PUBLIC_KEY")
        canonical = key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        expected_old_canonical = None
        if expected_old_public_key_pem is not None:
            if not isinstance(expected_old_public_key_pem, str) or not 1 <= len(expected_old_public_key_pem) <= 4096:
                raise DeviceAuthorityError("INVALID_OLD_PUBLIC_KEY")
            try:
                old_key = serialization.load_pem_public_key(expected_old_public_key_pem.encode("ascii"))
            except (ValueError, TypeError, UnicodeEncodeError):
                raise DeviceAuthorityError("INVALID_OLD_PUBLIC_KEY") from None
            if not isinstance(old_key, ec.EllipticCurvePublicKey) or not isinstance(old_key.curve, ec.SECP256R1):
                raise DeviceAuthorityError("INVALID_OLD_PUBLIC_KEY")
            expected_old_canonical = old_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("ascii")
        der = key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        device_id = hashlib.sha256(der).hexdigest()
        now = time.time()
        with self.lock, self._database() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                active = db.execute(
                    "SELECT device_id,public_key_pem,owner_subject FROM devices WHERE active=1"
                ).fetchall()
                if any(
                    row["owner_subject"] != owner_subject
                    and (expected_old_canonical is None or row["public_key_pem"] != expected_old_canonical)
                    for row in active
                ):
                    raise DeviceAuthorityError("UNRELATED_ACTIVE_DEVICE_BLOCKS_RECOVERY", 409)
                existing = db.execute(
                    "SELECT device_id,active,owner_subject FROM devices WHERE device_id=?",
                    (device_id,),
                ).fetchone()
                if existing is not None and not (
                    existing["active"] == 1 and existing["owner_subject"] == owner_subject
                ):
                    raise DeviceAuthorityError("DEVICE_KEY_PREVIOUSLY_ENROLLED", 409)
                for row in active:
                    if row["device_id"] == device_id and row["owner_subject"] == owner_subject:
                        db.execute(
                            "DELETE FROM device_challenges WHERE device_id=?",
                            (device_id,),
                        )
                        continue
                    db.execute(
                        "UPDATE devices SET active=0 WHERE device_id=?",
                        (row["device_id"],),
                    )
                    db.execute(
                        "DELETE FROM device_challenges WHERE device_id=?",
                        (row["device_id"],),
                    )
                if existing is None:
                    db.execute(
                        """INSERT INTO devices
                        (device_id,public_key_pem,owner_subject,active,created_at)
                        VALUES(?,?,?,1,?)""",
                        (device_id, canonical, owner_subject, now),
                    )
                db.execute("COMMIT")
            except Exception:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
        return {"device_id": device_id, "algorithm": "ECDSA-P256-SHA256"}

    @contextmanager
    def revoke_active_key(self, public_key_pem: Any):
        """Deactivate an exact enrolled key and invalidate all its pending proofs.

        Call only after the owning operator root signature has been verified.
        """
        if not isinstance(public_key_pem, str) or not 1 <= len(public_key_pem) <= 4096:
            raise DeviceAuthorityError("INVALID_PUBLIC_KEY")
        try:
            key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        except (ValueError, TypeError, UnicodeEncodeError):
            raise DeviceAuthorityError("INVALID_PUBLIC_KEY") from None
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise DeviceAuthorityError("UNSUPPORTED_PUBLIC_KEY")
        canonical = key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        with self.lock, self._database() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                rows = db.execute(
                    "SELECT device_id FROM devices WHERE public_key_pem=? AND active=1",
                    (canonical,),
                ).fetchall()
                if len(rows) != 1:
                    raise DeviceAuthorityError("DEVICE_KEY_NOT_ACTIVE", 403)
                device_id = rows[0]["device_id"]
                changed = db.execute(
                    "UPDATE devices SET active=0 WHERE device_id=? AND active=1",
                    (device_id,),
                ).rowcount
                if changed != 1:
                    raise DeviceAuthorityError("DEVICE_KEY_NOT_ACTIVE", 403)
                db.execute(
                    "DELETE FROM device_challenges WHERE device_id=?",
                    (device_id,),
                )
                yield True
                db.execute("COMMIT")
            except Exception:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise

    def verify_active_public_key(self, public_key_pem: Any) -> bool:
        """Check that an exact public key is currently enrolled and not revoked."""
        if not isinstance(public_key_pem, str) or not 1 <= len(public_key_pem) <= 4096:
            raise DeviceAuthorityError("INVALID_PUBLIC_KEY")
        try:
            key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        except (ValueError, TypeError, UnicodeEncodeError):
            raise DeviceAuthorityError("INVALID_PUBLIC_KEY") from None
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise DeviceAuthorityError("UNSUPPORTED_PUBLIC_KEY")
        canonical = key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        with self._database() as db:
            rows = db.execute(
                "SELECT public_key_pem FROM devices WHERE active=1"
            ).fetchall()
        matches = [row for row in rows if hmac.compare_digest(row["public_key_pem"], canonical)]
        if len(matches) != 1:
            raise DeviceAuthorityError("DEVICE_KEY_NOT_ACTIVE", 403)
        return True

    def challenge(self, device_id: Any, *, owner_subject: str) -> dict[str, str]:
        if not isinstance(device_id, str) or not re.fullmatch(r"[0-9a-f]{64}", device_id):
            raise DeviceAuthorityError("INVALID_DEVICE_ID")
        nonce = secrets.token_hex(32)
        now = time.time()
        with self.lock, self._database() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT active, owner_subject FROM devices WHERE device_id=?",
                (device_id,),
            ).fetchone()
            if row is None or row["active"] != 1:
                db.execute("ROLLBACK")
                raise DeviceAuthorityError("DEVICE_NOT_FOUND", 404)
            if not isinstance(owner_subject, str) or not hmac.compare_digest(
                row["owner_subject"] or "", owner_subject
            ):
                db.execute("ROLLBACK")
                raise DeviceAuthorityError("DEVICE_OWNER_MISMATCH", 403)
            # Bound persistent state even if a caller repeatedly requests
            # challenges without completing the signed proof. BEGIN IMMEDIATE
            # makes the per-device cap atomic across server processes.
            db.execute(
                "DELETE FROM device_challenges WHERE expires_at <= ?",
                (now,),
            )
            active_count = db.execute(
                """
                SELECT COUNT(*) FROM device_challenges
                WHERE device_id=? AND consumed_at IS NULL AND expires_at > ?
                """,
                (device_id, now),
            ).fetchone()[0]
            if active_count >= MAX_ACTIVE_CHALLENGES_PER_DEVICE:
                db.execute("ROLLBACK")
                raise DeviceAuthorityError("DEVICE_CHALLENGE_RATE_LIMITED", 429)
            db.execute(
                "INSERT INTO device_challenges(nonce,device_id,expires_at) VALUES(?,?,?)",
                (nonce, device_id, now + CHALLENGE_TTL_SECONDS),
            )
            db.execute("COMMIT")
        return {"nonce": nonce, "expires_in": CHALLENGE_TTL_SECONDS}

    def verify_request(
        self,
        payload: Any,
        *,
        method: str,
        path: str,
        request_digest: str,
        owner_subject: str,
    ) -> dict[str, str]:
        """Verify a one-time device signature bound to one exact API request.

        The caller must compute request_digest from the canonical request
        content and pass the same value when constructing the signed proof.
        This method grants no capability by itself.
        """
        if not isinstance(payload, dict):
            raise DeviceAuthorityError("INVALID_REQUEST")
        device_id = payload.get("device_id")
        nonce = payload.get("nonce")
        timestamp = payload.get("timestamp")
        supplied_digest = payload.get("request_digest")
        signature = payload.get("signature")
        if (
            not isinstance(device_id, str)
            or not re.fullmatch(r"[0-9a-f]{64}", device_id)
            or not isinstance(nonce, str)
            or not re.fullmatch(r"[0-9a-f]{64}", nonce)
            or isinstance(timestamp, bool)
            or not isinstance(timestamp, int)
            or not isinstance(method, str)
            or not re.fullmatch(r"[A-Z]{3,10}", method)
            or not isinstance(path, str)
            or not path.startswith("/")
            or "?" in path
            or not isinstance(request_digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", request_digest)
            or not isinstance(supplied_digest, str)
            or not hmac.compare_digest(supplied_digest, request_digest)
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

        signed_text = "\n".join(
            [method, path, str(timestamp), nonce, request_digest]
        ).encode("utf-8")
        with self.lock, self._database() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """
                SELECT d.public_key_pem, d.active, d.owner_subject, c.expires_at, c.consumed_at
                FROM devices d JOIN device_challenges c ON c.device_id=d.device_id
                WHERE d.device_id=? AND c.nonce=?
                """,
                (device_id, nonce),
            ).fetchone()
            if row is None or row["active"] != 1:
                db.execute("ROLLBACK")
                raise DeviceAuthorityError("DEVICE_OR_CHALLENGE_NOT_FOUND", 404)
            if not isinstance(owner_subject, str) or not hmac.compare_digest(
                row["owner_subject"] or "", owner_subject
            ):
                db.execute("ROLLBACK")
                raise DeviceAuthorityError("DEVICE_OWNER_MISMATCH", 403)
            if row["consumed_at"] is not None or row["expires_at"] < now:
                db.execute("ROLLBACK")
                raise DeviceAuthorityError("CHALLENGE_EXPIRED_OR_REPLAYED", 401)
            try:
                public_key = serialization.load_pem_public_key(
                    row["public_key_pem"].encode("ascii")
                )
                if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
                    public_key.curve, ec.SECP256R1
                ):
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
        return {"authority": "DEVICE_REQUEST_VERIFIED"}

    def verify_status(self, payload: Any, *, owner_subject: str) -> dict[str, str]:
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

        with self.lock, self._database() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """
                SELECT d.public_key_pem, d.active, d.owner_subject, c.expires_at, c.consumed_at
                FROM devices d JOIN device_challenges c ON c.device_id=d.device_id
                WHERE d.device_id=? AND c.nonce=?
                """,
                (device_id, nonce),
            ).fetchone()
            if row is None or row["active"] != 1:
                db.execute("ROLLBACK")
                raise DeviceAuthorityError("DEVICE_OR_CHALLENGE_NOT_FOUND", 404)
            if not isinstance(owner_subject, str) or not hmac.compare_digest(
                row["owner_subject"] or "", owner_subject
            ):
                db.execute("ROLLBACK")
                raise DeviceAuthorityError("DEVICE_OWNER_MISMATCH", 403)
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
        }
