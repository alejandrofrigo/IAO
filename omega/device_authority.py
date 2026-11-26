"""Autoridad de dispositivo IAO: ECDSA P-256, retos de un uso y revocación."""
import base64
import hashlib
import json
import secrets
import sqlite3
import time
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class DeviceError(Exception):
    def __init__(self, code: str, status: int = 403):
        self.code = code
        self.status = status
        super().__init__(code)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _b64decode(value: str) -> bytes:
    if not isinstance(value, str) or len(value) > 4096:
        raise ValueError("INVALID_ENCODING")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _canonical_action(action: str) -> bytes:
    return json.dumps(
        {"action": action}, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def ensure_schema(store) -> None:
    with store.lock:
        store.db.executescript("""
        CREATE TABLE IF NOT EXISTS device_enrollment (
            id TEXT PRIMARY KEY,
            code_hash TEXT NOT NULL UNIQUE,
            expires_at REAL NOT NULL,
            used_at REAL
        );
        CREATE TABLE IF NOT EXISTS trusted_device (
            id TEXT PRIMARY KEY,
            public_key_pem TEXT NOT NULL,
            created_at REAL NOT NULL,
            revoked_at REAL
        );
        CREATE TABLE IF NOT EXISTS device_nonce (
            nonce_hash TEXT PRIMARY KEY,
            device_id TEXT NOT NULL REFERENCES trusted_device(id),
            expires_at REAL NOT NULL,
            used_at REAL
        );
        CREATE TABLE IF NOT EXISTS device_authority_state (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            primary_device_id TEXT,
            updated_at REAL NOT NULL
        );
        """)
        store.db.execute(
            "INSERT OR IGNORE INTO device_authority_state "
            "(singleton,primary_device_id,updated_at) VALUES(1,NULL,?)",
            (time.time(),),
        )

def issue_enrollment(store, ttl: int = 600) -> str:
    ensure_schema(store)
    if not 60 <= ttl <= 900:
        raise ValueError("INVALID_TTL")
    code = secrets.token_urlsafe(32)
    now = time.time()
    with store.lock:
        store.db.execute("BEGIN IMMEDIATE")
        try:
            state = store.db.execute(
                "SELECT primary_device_id FROM device_authority_state WHERE singleton=1"
            ).fetchone()
            registered = store.db.execute(
                "SELECT COUNT(*) FROM trusted_device"
            ).fetchone()[0]
            if state is None or state["primary_device_id"] is not None or registered:
                raise DeviceError("PRIMARY_DEVICE_ALREADY_REGISTERED", 409)
            store.db.execute(
                "INSERT INTO device_enrollment(id,code_hash,expires_at) VALUES(?,?,?)",
                (str(uuid.uuid4()), _hash(code), now + ttl),
            )
            store.db.execute("COMMIT")
        except BaseException:
            store.db.execute("ROLLBACK")
            raise
    store.audit(
        "local_operator", "DEVICE_PRIMARY_ENROLLMENT_ISSUED",
        "device_authority", expires_in=ttl,
    )
    return code

def enroll(store, code: str, public_key_pem: str) -> dict:
    ensure_schema(store)
    if not isinstance(code, str) or not 30 <= len(code) <= 200:
        raise DeviceError("INVALID_ENROLLMENT_CODE", 400)
    if not isinstance(public_key_pem, str) or len(public_key_pem) > 4096:
        raise DeviceError("INVALID_PUBLIC_KEY", 400)
    try:
        key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    except Exception:
        raise DeviceError("INVALID_PUBLIC_KEY", 400) from None
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise DeviceError("P256_REQUIRED", 400)

    now = time.time()
    device_id = str(uuid.uuid4())
    with store.lock:
        store.db.execute("BEGIN IMMEDIATE")
        try:
            state = store.db.execute(
                "SELECT primary_device_id FROM device_authority_state WHERE singleton=1"
            ).fetchone()
            registered = store.db.execute(
                "SELECT COUNT(*) FROM trusted_device"
            ).fetchone()[0]
            if state is None or state["primary_device_id"] is not None or registered:
                raise DeviceError("PRIMARY_DEVICE_ALREADY_REGISTERED", 409)

            row = store.db.execute(
                "SELECT id,expires_at,used_at FROM device_enrollment WHERE code_hash=?",
                (_hash(code),),
            ).fetchone()
            if row is None or row["used_at"] is not None or row["expires_at"] < now:
                raise DeviceError("ENROLLMENT_CODE_INVALID_OR_EXPIRED")

            store.db.execute(
                "UPDATE device_enrollment SET used_at=? WHERE id=? AND used_at IS NULL",
                (now, row["id"]),
            )
            store.db.execute(
                "INSERT INTO trusted_device(id,public_key_pem,created_at) VALUES(?,?,?)",
                (device_id, public_key_pem, now),
            )
            changed = store.db.execute(
                "UPDATE device_authority_state SET primary_device_id=?,updated_at=? "
                "WHERE singleton=1 AND primary_device_id IS NULL",
                (device_id, now),
            ).rowcount
            if changed != 1:
                raise DeviceError("PRIMARY_DEVICE_ALREADY_REGISTERED", 409)
            store.db.execute("COMMIT")
        except BaseException:
            store.db.execute("ROLLBACK")
            raise

    store.audit(
        "device:" + device_id, "DEVICE_PRIMARY_ENROLLED",
        device_id, algorithm="ECDSA_P256_SHA256",
        authority="PRIMARY_DEVICE",
    )
    return {
        "device_id": device_id,
        "algorithm": "ECDSA_P256_SHA256",
        "authority": "PRIMARY_DEVICE",
    }

def create_challenge(store, device_id: str) -> dict:
    ensure_schema(store)
    if not isinstance(device_id, str) or not 1 <= len(device_id) <= 64:
        raise DeviceError("INVALID_DEVICE_ID", 400)

    now = time.time()
    nonce = secrets.token_urlsafe(32)

    with store.lock:
        store.db.execute("BEGIN IMMEDIATE")
        try:
            # Los nonces son efímeros: conservar los recientes para diagnóstico,
            # pero retirar los caducados o consumidos hace más de diez minutos.
            store.db.execute(
                """DELETE FROM device_nonce
                   WHERE expires_at < ? OR used_at < ?""",
                (now - 600, now - 600),
            )

            row = store.db.execute(
                "SELECT d.id FROM trusted_device d "
                "JOIN device_authority_state a ON a.primary_device_id=d.id "
                "WHERE d.id=? AND d.revoked_at IS NULL",
                (device_id,),
            ).fetchone()
            if row is None:
                raise DeviceError("DEVICE_NOT_AUTHORIZED")

            pending = store.db.execute(
                """SELECT COUNT(*) FROM device_nonce
                   WHERE device_id=? AND used_at IS NULL AND expires_at>=?""",
                (device_id, now),
            ).fetchone()[0]
            if pending >= 5:
                raise DeviceError("TOO_MANY_ACTIVE_CHALLENGES", 429)

            store.db.execute(
                "INSERT INTO device_nonce(nonce_hash,device_id,expires_at) VALUES(?,?,?)",
                (_hash(nonce), device_id, now + 90),
            )
            store.db.execute("COMMIT")
        except BaseException:
            store.db.execute("ROLLBACK")
            raise

    return {"device_id": device_id, "nonce": nonce, "expires_in": 90}

def verify_status_command(store, data: dict) -> dict:
    ensure_schema(store)
    if not isinstance(data, dict):
        raise DeviceError("INVALID_REQUEST", 400)

    device_id = data.get("device_id")
    nonce = data.get("nonce")
    timestamp = data.get("timestamp")
    signature_text = data.get("signature")
    action = data.get("action")

    if action != "status":
        raise DeviceError("ACTION_NOT_ENABLED", 403)
    if (not isinstance(device_id, str) or len(device_id) > 64
            or not isinstance(nonce, str) or len(nonce) > 128
            or not isinstance(timestamp, int) or isinstance(timestamp, bool)
            or not isinstance(signature_text, str)):
        raise DeviceError("INVALID_REQUEST", 400)

    now = time.time()
    if abs(now - timestamp) > 60:
        raise DeviceError("TIMESTAMP_EXPIRED")
    try:
        signature = _b64decode(signature_text)
    except Exception:
        raise DeviceError("INVALID_SIGNATURE", 400) from None

    signed = (
        "POST\n/v1/device/command\n"
        + str(timestamp) + "\n"
        + nonce + "\n"
        + hashlib.sha256(_canonical_action(action)).hexdigest()
    ).encode("utf-8")

    with store.lock:
        store.db.execute("BEGIN IMMEDIATE")
        try:
            row = store.db.execute(
                """SELECT d.public_key_pem,n.expires_at,n.used_at
                   FROM trusted_device d
                   JOIN device_nonce n ON n.device_id=d.id
                   JOIN device_authority_state a ON a.primary_device_id=d.id
                   WHERE d.id=? AND d.revoked_at IS NULL AND n.nonce_hash=?""",
                (device_id, _hash(nonce)),
            ).fetchone()
            if row is None or row["used_at"] is not None or row["expires_at"] < now:
                raise DeviceError("NONCE_INVALID_OR_REPLAYED")
            try:
                public_key = serialization.load_pem_public_key(
                    row["public_key_pem"].encode("ascii")
                )
                public_key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
            except Exception:
                raise DeviceError("SIGNATURE_VERIFICATION_FAILED") from None
            store.db.execute(
                "UPDATE device_nonce SET used_at=? WHERE nonce_hash=? AND used_at IS NULL",
                (now, _hash(nonce)),
            )
            store.db.execute("COMMIT")
        except BaseException:
            store.db.execute("ROLLBACK")
            raise

    store.audit("device:" + device_id, "DEVICE_COMMAND_AUTHORIZED",
                device_id, action="status", decision="ALLOW")
    return {
        "authorized": True,
        "action": "status",
        "authority": "DEVICE_SIGNATURE_VERIFIED_READ_ONLY",
        "device_id": device_id,
    }


def revoke_device(store, device_id: str) -> bool:
    ensure_schema(store)
    now = time.time()
    with store.lock:
        store.db.execute("BEGIN IMMEDIATE")
        try:
            cur = store.db.execute(
                "UPDATE trusted_device SET revoked_at=? WHERE id=? AND revoked_at IS NULL",
                (now, device_id),
            )
            changed = cur.rowcount == 1
            store.db.execute("COMMIT")
        except BaseException:
            store.db.execute("ROLLBACK")
            raise
    if changed:
        store.audit("local_operator", "DEVICE_REVOKED",
                    device_id, decision="REVOKED")
    return changed
