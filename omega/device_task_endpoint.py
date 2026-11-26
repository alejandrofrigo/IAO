import hashlib
import json
import os
import time


class DeviceTaskEndpointError(Exception):
    def __init__(self, status, code):
        super().__init__(code)
        self.status = int(status)
        self.code = str(code)


def _dispatch_outbox(store, limit=50):
    from omega.autonomous_core import AutonomousCore

    state_dir = os.environ.get(
        "IAO_AUTONOMOUS_CORE_DIR", ".state/iao-autonomous-core"
    )
    core = AutonomousCore(state_dir=state_dir)
    db = store.db
    delivered = 0

    with store.lock:
        rows = db.execute(
            "SELECT task_id, kind, payload, device_id FROM device_task_outbox "
            "WHERE delivered_at IS NULL ORDER BY created_at LIMIT ?",
            (int(limit),)
        ).fetchall()

    for row in rows:
        payload = json.loads(row["payload"])
        core.submit_idempotent(
            row["kind"], payload=payload,
            source="authorized-device:" + row["device_id"],
            task_id=row["task_id"],
        )
        with store.lock:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute(
                    "UPDATE device_task_outbox SET delivered_at=? "
                    "WHERE task_id=? AND delivered_at IS NULL",
                    (float(time.time()), row["task_id"])
                )
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        delivered += 1
    return delivered


def enqueue_device_task(store, data, clock=time.time):
    from omega.device_task_authority import (
        verify_task_signature, DeviceTaskError
    )

    if not isinstance(data, dict):
        raise DeviceTaskEndpointError(400, "INVALID_REQUEST")

    now = float(clock())
    device_id = data.get("device_id")
    nonce = data.get("nonce")
    idem = data.get("idempotency_key")

    try:
        semantic = {
            "device_id": device_id,
            "action": data.get("action"),
            "kind": data.get("kind"),
            "payload": data.get("payload"),
            "idempotency_key": idem,
        }
        semantic_bytes = json.dumps(
            semantic, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
        request_hash = hashlib.sha256(semantic_bytes).hexdigest()
        nonce_hash = hashlib.sha256(nonce.encode("ascii")).hexdigest()

        with store.lock:
            state = store.db.execute(
                "SELECT primary_device_id FROM device_authority_state "
                "WHERE singleton=1"
            ).fetchone()
            device = store.db.execute(
                "SELECT public_key_pem, revoked_at FROM trusted_device WHERE id=?",
                (device_id,)
            ).fetchone()

        if not state or state["primary_device_id"] != device_id:
            raise DeviceTaskEndpointError(403, "PRIMARY_DEVICE_REQUIRED")
        if not device or device["revoked_at"] is not None:
            raise DeviceTaskEndpointError(403, "DEVICE_NOT_TRUSTED")

        verified = verify_task_signature(
            device["public_key_pem"], data, now=now
        )
    except DeviceTaskEndpointError:
        raise
    except DeviceTaskError as exc:
        raise DeviceTaskEndpointError(
            getattr(exc, "status", 401),
            getattr(exc, "code", "SIGNATURE_INVALID")
        ) from None
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise DeviceTaskEndpointError(400, "INVALID_REQUEST") from None

    task_id = hashlib.sha256(
        (device_id + "\0" + idem).encode("utf-8")
    ).hexdigest()[:32]

    db = store.db
    try:
        with store.lock:
            db.execute("""
                CREATE TABLE IF NOT EXISTS device_task_idempotency (
                    device_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY(device_id, idempotency_key)
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS device_task_outbox (
                    task_id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    delivered_at REAL
                )
            """)
            db.execute("BEGIN IMMEDIATE")
            try:
                state = db.execute(
                    "SELECT primary_device_id FROM device_authority_state "
                    "WHERE singleton=1"
                ).fetchone()
                device = db.execute(
                    "SELECT revoked_at FROM trusted_device WHERE id=?",
                    (device_id,)
                ).fetchone()
                if not state or state["primary_device_id"] != device_id:
                    raise DeviceTaskEndpointError(403, "PRIMARY_DEVICE_REQUIRED")
                if not device or device["revoked_at"] is not None:
                    raise DeviceTaskEndpointError(403, "DEVICE_NOT_TRUSTED")

                nonce_row = db.execute(
                    "SELECT device_id, expires_at, used_at FROM device_nonce "
                    "WHERE nonce_hash=?", (nonce_hash,)
                ).fetchone()
                if (
                    not nonce_row
                    or nonce_row["device_id"] != device_id
                    or nonce_row["used_at"] is not None
                    or float(nonce_row["expires_at"]) <= now
                ):
                    raise DeviceTaskEndpointError(401, "NONCE_INVALID_OR_USED")

                db.execute(
                    "UPDATE device_nonce SET used_at=? "
                    "WHERE nonce_hash=? AND used_at IS NULL",
                    (now, nonce_hash)
                )

                previous = db.execute(
                    "SELECT request_hash, task_id FROM device_task_idempotency "
                    "WHERE device_id=? AND idempotency_key=?",
                    (device_id, idem)
                ).fetchone()

                if previous:
                    if previous["request_hash"] != request_hash:
                        raise DeviceTaskEndpointError(409, "IDEMPOTENCY_KEY_CONFLICT")
                    task_id = previous["task_id"]
                    duplicate = True
                else:
                    db.execute(
                        "INSERT INTO device_task_idempotency "
                        "(device_id,idempotency_key,request_hash,task_id,created_at) "
                        "VALUES(?,?,?,?,?)",
                        (device_id, idem, request_hash, task_id, now)
                    )
                    db.execute(
                        "INSERT INTO device_task_outbox "
                        "(task_id,device_id,kind,payload,created_at,delivered_at) "
                        "VALUES(?,?,?,?,?,NULL)",
                        (
                            task_id, device_id, verified["kind"],
                            json.dumps(
                                verified["payload"], sort_keys=True,
                                ensure_ascii=False, allow_nan=False
                            ), now
                        )
                    )
                    duplicate = False
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise

        try:
            _dispatch_outbox(store)
        except Exception:
            # La orden permanece en outbox para recuperación posterior.
            pass

        with store.lock:
            pending = db.execute(
                "SELECT 1 FROM device_task_outbox "
                "WHERE task_id=? AND delivered_at IS NULL",
                (task_id,)
            ).fetchone()

        try:
            store.audit(
                device_id,
                "DEVICE_TASK_ACCEPTED" if not duplicate else "DEVICE_TASK_DEDUPLICATED",
                task_id, kind=verified["kind"], idempotency_key=idem
            )
            audit_recorded = True
        except Exception:
            audit_recorded = False

        return {
            "status": (
                "PENDING_DELIVERY" if pending
                else "DUPLICATE" if duplicate else "QUEUED"
            ),
            "task_id": task_id,
            "kind": verified["kind"],
            "idempotent": duplicate,
            "audit_recorded": audit_recorded,
        }
    except DeviceTaskEndpointError:
        raise
    except Exception as exc:
        raise DeviceTaskEndpointError(
            503, "TASK_ENQUEUE_FAILED_" + type(exc).__name__.upper()
        ) from None


def recover_device_task_outbox(store):
    try:
        return _dispatch_outbox(store, limit=100)
    except Exception as exc:
        raise DeviceTaskEndpointError(
            503, "OUTBOX_RECOVERY_FAILED_" + type(exc).__name__.upper()
        ) from None
