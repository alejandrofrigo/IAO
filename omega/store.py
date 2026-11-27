"""SQLite persistence for dev/pilot-in-sandbox (PostgreSQL remains the target: ADR-002).
All reads of user data take the owner as a mandatory parameter (tenant isolation)."""
import json
import hashlib
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from omega.audit import GENESIS_HASH, make_event, verify_chain

SCHEMA_VERSION = 3

SCHEMA = """
CREATE TABLE IF NOT EXISTS conversation(
  id TEXT PRIMARY KEY, owner TEXT NOT NULL, title TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_conv_owner ON conversation(owner, created_at);
CREATE TABLE IF NOT EXISTS message(
  id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL REFERENCES conversation(id),
  role TEXT NOT NULL CHECK(role IN('USER','ASSISTANT','SYSTEM','TOOL')), content TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS task(
  id TEXT PRIMARY KEY, owner TEXT NOT NULL, state TEXT NOT NULL, intent_json TEXT NOT NULL,
  result_json TEXT, idem_key TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  lease_owner TEXT, lease_until TEXT, attempt_count INTEGER NOT NULL DEFAULT 0,
  UNIQUE(owner, idem_key));
CREATE INDEX IF NOT EXISTS idx_task_owner ON task(owner, created_at);
CREATE TABLE IF NOT EXISTS tool_execution(
  id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES task(id), tool_name TEXT NOT NULL, tool_version TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN('PENDING','RUNNING','SUCCEEDED','FAILED','DENIED','TIMED_OUT','CANCELLED')),
  input_digest TEXT NOT NULL, output_digest TEXT, error_code TEXT, started_at TEXT, finished_at TEXT);
CREATE TABLE IF NOT EXISTS memory(
  id TEXT PRIMARY KEY, owner TEXT NOT NULL, mtype TEXT NOT NULL CHECK(mtype IN('PREFERENCE','FACT')),
  value TEXT NOT NULL, provenance TEXT NOT NULL, consent_at TEXT NOT NULL, created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL, expires_at TEXT);
CREATE INDEX IF NOT EXISTS idx_memory_owner ON memory(owner, created_at);
CREATE TABLE IF NOT EXISTS audit_event(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, event_type TEXT NOT NULL, subject TEXT NOT NULL,
  details TEXT NOT NULL, previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL UNIQUE);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, path: str | Path, audit_key: bytes | None = None) -> None:
        self.audit_key = audit_key
        self.lock = threading.RLock()
        if str(path) == ":memory:":
            self.path = ":memory:"
        else:
            db_path = Path(path)
            db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if db_path.parent.is_symlink() or db_path.is_symlink():
                raise RuntimeError("DATABASE_SYMLINK_REFUSED")
            if db_path.exists() and not db_path.is_file():
                raise RuntimeError("DATABASE_PATH_NOT_REGULAR_FILE")
            # Chat content, task payloads and audit records are sensitive.
            # Keep the state directory private and refuse symlinked DB files.
            os.chmod(db_path.parent, 0o700)
            flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(str(db_path), flags, 0o600)
            try:
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
            self.path = str(db_path)
        self.db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        if self.path != ":memory:":
            os.chmod(self.path, 0o600)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA secure_delete=ON")  # overwrite freed pages: operational deletion must be physical
        self.db.executescript(SCHEMA)
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations("
            "version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        versions = self.db.execute(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"
        ).fetchone()[0]
        if versions > SCHEMA_VERSION:
            raise RuntimeError("DATABASE_SCHEMA_VERSION_UNSUPPORTED")
        if versions == 0:
            self.db.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES(1, ?)",
                (now_iso(),),
            )
        self._ensure_task_queue_columns()
        self._initialize_audit_v2()
        integrity = self.db.execute("PRAGMA quick_check").fetchone()
        if integrity is None or integrity[0] != "ok":
            raise RuntimeError("DATABASE_INTEGRITY_CHECK_FAILED")

    def _ensure_task_queue_columns(self) -> None:
        """Apply the versioned, additive task-lease migration exactly once."""
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                version = int(self.db.execute(
                    "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"
                ).fetchone()[0])
                columns = {
                    row["name"]
                    for row in self.db.execute("PRAGMA table_info(task)").fetchall()
                }
                additions = {
                    "lease_owner": "TEXT",
                    "lease_until": "TEXT",
                    "attempt_count": "INTEGER NOT NULL DEFAULT 0",
                }
                if version < 2:
                    for name, declaration in additions.items():
                        if name not in columns:
                            self.db.execute(
                                f"ALTER TABLE task ADD COLUMN {name} {declaration}"
                            )
                    self.db.execute(
                        "INSERT INTO schema_migrations(version, applied_at) VALUES(2, ?)",
                        (now_iso(),),
                    )
                elif not set(additions).issubset(columns):
                    raise RuntimeError("DATABASE_SCHEMA_MIGRATION_STATE_INVALID")
                self.db.execute(
                    "CREATE INDEX IF NOT EXISTS idx_task_queue "
                    "ON task(state, created_at, id)"
                )
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def close(self) -> None:
        self.db.close()

    def ping(self) -> bool:
        with self.lock:
            return self.db.execute("SELECT 1").fetchone()[0] == 1


    def _legacy_audit_snapshot(self) -> list[dict[str, Any]]:
        """Fingerprint de las tablas históricas; nunca modifica sus registros."""
        names = self.db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND (name='audit_event' OR name GLOB 'audit_event_legacy_*') "
            "ORDER BY name"
        ).fetchall()
        result = []
        for item in names:
            name = item["name"]
            safe = name.replace('"', '""')
            rows = self.db.execute(
                f'SELECT id,ts,event_type,subject,details,previous_hash,event_hash '
                f'FROM "{safe}" ORDER BY id'
            ).fetchall()
            records = [list(row) for row in rows]
            raw = json.dumps(
                records, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False
            ).encode()
            result.append({
                "table": name,
                "event_count": len(records),
                "sha256": hashlib.sha256(raw).hexdigest(),
            })
        return result

    def _initialize_audit_v2(self) -> None:
        """Crea la cadena vigente una sola vez y firma el acta de transición."""
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                self.db.execute("""
                    CREATE TABLE IF NOT EXISTS audit_event_v2(
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      ts TEXT NOT NULL,
                      event_type TEXT NOT NULL,
                      subject TEXT NOT NULL,
                      details TEXT NOT NULL,
                      previous_hash TEXT NOT NULL,
                      event_hash TEXT NOT NULL UNIQUE
                    )
                """)
                self.db.execute("""
                    CREATE TABLE IF NOT EXISTS audit_control(
                      id INTEGER PRIMARY KEY CHECK(id=1),
                      created_at TEXT NOT NULL,
                      legacy_status TEXT NOT NULL,
                      legacy_snapshot_json TEXT NOT NULL,
                      key_fingerprint TEXT NOT NULL
                    )
                """)
                control = self.db.execute(
                    "SELECT id FROM audit_control WHERE id=1"
                ).fetchone()

                if control is None:
                    snapshot = self._legacy_audit_snapshot()
                    total = sum(x["event_count"] for x in snapshot)
                    status = "legacy_unverified" if total else "no_legacy_history"
                    key_fp = hashlib.sha256(self.audit_key or b"").hexdigest()

                    if total:
                        details = {
                            "legacy_status": "legacy_unverified",
                            "reason": "HISTORICAL_CHAIN_INTEGRITY_NOT_ESTABLISHED",
                            "tables": snapshot,
                            "total_historical_events": total,
                            "key_fingerprint_sha256": key_fp,
                        }
                        ev = make_event(
                            "AUDIT_CHAIN_TRANSITION",
                            "iao_audit",
                            details,
                            GENESIS_HASH,
                            self.audit_key,
                        )
                        self.db.execute(
                            "INSERT INTO audit_event_v2"
                            "(ts,event_type,subject,details,previous_hash,event_hash) "
                            "VALUES(?,?,?,?,?,?)",
                            (
                                ev["timestamp"], ev["event_type"], ev["subject"],
                                json.dumps(details, sort_keys=True, ensure_ascii=False),
                                ev["previous_hash"], ev["event_hash"],
                            ),
                        )

                    self.db.execute(
                        "INSERT INTO audit_control"
                        "(id,created_at,legacy_status,legacy_snapshot_json,key_fingerprint) "
                        "VALUES(1,?,?,?,?)",
                        (
                            datetime.now(timezone.utc).isoformat(),
                            status,
                            json.dumps(snapshot, sort_keys=True),
                            key_fp,
                        ),
                    )
                version = int(self.db.execute(
                    "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"
                ).fetchone()[0])
                if version < 3:
                    self.db.execute(
                        "INSERT INTO schema_migrations(version, applied_at) VALUES(3, ?)",
                        (now_iso(),),
                    )
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def legacy_audit_status(self) -> dict[str, Any]:
        """Compara el historial conservado con la huella tomada en la transición."""
        with self.lock:
            row = self.db.execute(
                "SELECT legacy_status,legacy_snapshot_json "
                "FROM audit_control WHERE id=1"
            ).fetchone()
            current = self._legacy_audit_snapshot()

        if row is None:
            return {"status": "missing_transition_record", "unchanged": False}

        original = json.loads(row["legacy_snapshot_json"])
        unchanged = current == original
        historical_event_count = sum(
            int(item.get("event_count", 0)) for item in original
        )
        return {
            "status": (
                row["legacy_status"] if unchanged
                else "legacy_changed_after_transition"
            ),
            "unchanged": unchanged,
            "event_count": historical_event_count,
            "tables": current,
        }

    # ---- audit (hash chained) ----
    def audit(self, actor: str, event_type: str, subject: str, **details: Any) -> dict[str, Any]:
        details = {"actor": actor, **details}
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row = self.db.execute("SELECT event_hash FROM audit_event_v2 ORDER BY id DESC LIMIT 1").fetchone()
                ev = make_event(event_type, subject, details, row[0] if row else GENESIS_HASH, self.audit_key)
                self.db.execute(
                    "INSERT INTO audit_event_v2(ts,event_type,subject,details,previous_hash,event_hash) VALUES(?,?,?,?,?,?)",
                    (ev["timestamp"], event_type, subject, json.dumps(details, sort_keys=True, ensure_ascii=False),
                     ev["previous_hash"], ev["event_hash"]))
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise
        return ev

    def _all_events(self) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.db.execute("SELECT * FROM audit_event_v2 ORDER BY id").fetchall()
        return [{"id": r["id"], "event_type": r["event_type"], "subject": r["subject"],
                 "details": json.loads(r["details"]), "timestamp": r["ts"],
                 "previous_hash": r["previous_hash"], "event_hash": r["event_hash"]} for r in rows]

    def audit_status(self) -> dict[str, Any]:
        """Verify active chain and detect changes to the preserved legacy history."""
        events = self._all_events()
        payload = [{k: v for k, v in event.items() if k != "id"} for event in events]
        chain_valid, bad_index = verify_chain(payload, self.audit_key)

        bad_event_id = (
            events[bad_index]["id"]
            if bad_index is not None and 0 <= bad_index < len(events)
            else None
        )

        legacy = self.legacy_audit_status()
        legacy_valid = bool(legacy.get("unchanged", False))

        # The legacy transition stores a table-level digest, not per-row hashes.
        # On mismatch we can prove tampering, but cannot identify the exact row.
        if chain_valid and not legacy_valid:
            legacy_count = int(legacy.get("event_count", 0))
            bad_index = max(0, legacy_count - 1)
            bad_event_id = None

        return {
            "valid": bool(chain_valid and legacy_valid),
            "event_count": len(events),
            "first_invalid_index": bad_index,
            "first_invalid_event_id": bad_event_id,
        }

    def verify_audit(self) -> tuple[bool, int | None]:
        status = self.audit_status()
        return status["valid"], status["first_invalid_index"]

    def audit_events(self, actor: str | None, limit: int, after_id: int = 0) -> list[dict[str, Any]]:
        out = []
        for e in self._all_events():
            if e["id"] > after_id and (actor is None or e["details"].get("actor") == actor):
                out.append(e)
                if len(out) >= limit:
                    break
        return out

    # ---- conversations / messages ----
    def create_conversation(self, owner: str, title: str) -> str:
        cid = str(uuid.uuid4())
        with self.lock:
            self.db.execute("INSERT INTO conversation VALUES(?,?,?,?)", (cid, owner, title, now_iso()))
        return cid

    def get_conversation(self, cid: str, owner: str) -> dict[str, Any] | None:
        with self.lock:
            r = self.db.execute("SELECT * FROM conversation WHERE id=? AND owner=?", (cid, owner)).fetchone()
        return dict(r) if r else None

    def add_message(self, cid: str, role: str, content: str) -> str:
        mid = str(uuid.uuid4())
        with self.lock:
            self.db.execute("INSERT INTO message VALUES(?,?,?,?,?)", (mid, cid, role, content, now_iso()))
        return mid

    def list_messages(self, cid: str, owner: str) -> list[dict[str, Any]] | None:
        if self.get_conversation(cid, owner) is None:
            return None
        with self.lock:
            rows = self.db.execute("SELECT id,role,content,created_at FROM message WHERE conversation_id=? ORDER BY created_at", (cid,)).fetchall()
        return [dict(r) for r in rows]

    # ---- tasks ----
    def create_task(self, task_id: str, owner: str, intent: dict[str, Any], idem: str | None) -> tuple[dict[str, Any], bool]:
        ts = now_iso()
        with self.lock:
            try:
                self.db.execute("INSERT INTO task(id,owner,state,intent_json,idem_key,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                                (task_id, owner, "CREATED", json.dumps(intent, sort_keys=True), idem, ts, ts))
                created = True
            except sqlite3.IntegrityError:
                created = False
            if created:
                row = self.db.execute("SELECT * FROM task WHERE id=?", (task_id,)).fetchone()
            else:
                row = self.db.execute("SELECT * FROM task WHERE owner=? AND idem_key=?", (owner, idem)).fetchone()
        return dict(row), created

    def get_task_by_idempotency(self, owner: str, idem: str) -> dict[str, Any] | None:
        with self.lock:
            row = self.db.execute(
                "SELECT * FROM task WHERE owner=? AND idem_key=?",
                (owner, idem),
            ).fetchone()
        return dict(row) if row else None

    def queue_task(self, task_id: str) -> bool:
        """Move an authorized task into the durable queue exactly once."""
        with self.lock:
            changed = self.db.execute(
                "UPDATE task SET state='QUEUED', updated_at=? "
                "WHERE id=? AND state='AUTHORIZED'",
                (now_iso(), task_id),
            ).rowcount
        return changed == 1

    def claim_next_task(
        self, worker_id: str, lease_seconds: int = 30, *, now: str | None = None
    ) -> dict[str, Any] | None:
        """Atomically claim the oldest queued task; expired RUNNING tasks are never replayed."""
        if not isinstance(worker_id, str) or not 1 <= len(worker_id) <= 128:
            raise ValueError("INVALID_WORKER_ID")
        if isinstance(lease_seconds, bool) or not 1 <= lease_seconds <= 3600:
            raise ValueError("INVALID_LEASE_SECONDS")
        claimed_at = datetime.fromisoformat(now) if now else datetime.now(timezone.utc)
        if claimed_at.tzinfo is None:
            raise ValueError("CLAIM_TIME_MUST_BE_TIMEZONE_AWARE")
        lease_until = (claimed_at.timestamp() + lease_seconds)
        lease_until_iso = datetime.fromtimestamp(lease_until, timezone.utc).isoformat()
        claimed_at_iso = claimed_at.astimezone(timezone.utc).isoformat()
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row = self.db.execute(
                    "SELECT id FROM task WHERE state='QUEUED' "
                    "ORDER BY created_at, id LIMIT 1"
                ).fetchone()
                if row is None:
                    self.db.execute("COMMIT")
                    return None
                changed = self.db.execute(
                    "UPDATE task SET state='RUNNING', lease_owner=?, lease_until=?, "
                    "attempt_count=attempt_count+1, updated_at=? "
                    "WHERE id=? AND state='QUEUED'",
                    (worker_id, lease_until_iso, claimed_at_iso, row["id"]),
                ).rowcount
                if changed != 1:
                    self.db.execute("ROLLBACK")
                    return None
                claimed = self.db.execute(
                    "SELECT * FROM task WHERE id=?", (row["id"],)
                ).fetchone()
                self.db.execute("COMMIT")
                return dict(claimed)
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def update_claimed_task(
        self,
        task_id: str,
        worker_id: str,
        state: str,
        result: dict[str, Any] | None = None,
        *,
        release: bool = False,
    ) -> bool:
        """Fenced task update: only the current lease holder may change its task."""
        if state not in {"VERIFYING", "SUCCEEDED", "FAILED", "CANCELLED", "EXPIRED"}:
            raise ValueError("INVALID_CLAIMED_TASK_STATE")
        if release and state == "VERIFYING":
            raise ValueError("VERIFYING_CANNOT_RELEASE_LEASE")
        with self.lock:
            now = now_iso()
            if result is None:
                changed = self.db.execute(
                    "UPDATE task SET state=?, updated_at=?, "
                    "lease_owner=CASE WHEN ? THEN NULL ELSE lease_owner END, "
                    "lease_until=CASE WHEN ? THEN NULL ELSE lease_until END "
                    "WHERE id=? AND state IN ('RUNNING','VERIFYING') "
                    "AND lease_owner=? AND lease_until>?",
                    (state, now, int(release), int(release), task_id, worker_id, now),
                ).rowcount
            else:
                changed = self.db.execute(
                    "UPDATE task SET state=?, result_json=?, updated_at=?, "
                    "lease_owner=CASE WHEN ? THEN NULL ELSE lease_owner END, "
                    "lease_until=CASE WHEN ? THEN NULL ELSE lease_until END "
                    "WHERE id=? AND state IN ('RUNNING','VERIFYING') "
                    "AND lease_owner=? AND lease_until>?",
                    (state, json.dumps(result, sort_keys=True), now,
                     int(release), int(release), task_id, worker_id, now),
                ).rowcount
        return changed == 1

    def recover_interrupted_tasks(
        self, *, now: str | None = None
    ) -> list[dict[str, str]]:
        """Fail closed interrupted RUNNING/VERIFYING tasks; preserve live leases and never replay."""
        current = datetime.fromisoformat(now) if now else datetime.now(timezone.utc)
        if current.tzinfo is None:
            raise ValueError("RECOVERY_TIME_MUST_BE_TIMEZONE_AWARE")
        current_iso = current.astimezone(timezone.utc).isoformat()
        recovered: list[dict[str, str]] = []
        result = json.dumps(
            {"decision": "INTERRUPTED", "error": "PROCESS_INTERRUPTED"},
            sort_keys=True,
        )
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                rows = self.db.execute(
                    "SELECT id, owner FROM task "
                    "WHERE state IN ('RUNNING','VERIFYING') "
                    "AND (lease_until IS NULL OR lease_until<=?)",
                    (current_iso,),
                ).fetchall()
                for row in rows:
                    changed = self.db.execute(
                        "UPDATE task SET state='FAILED', result_json=?, updated_at=?, "
                        "lease_owner=NULL, lease_until=NULL "
                        "WHERE id=? AND state IN ('RUNNING','VERIFYING') "
                        "AND (lease_until IS NULL OR lease_until<=?)",
                        (result, current_iso, row["id"], current_iso),
                    ).rowcount
                    if changed == 1:
                        recovered.append({"id": row["id"], "owner": row["owner"]})
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise
        return recovered

    def get_task(self, task_id: str, owner: str) -> dict[str, Any] | None:
        with self.lock:
            r = self.db.execute("SELECT * FROM task WHERE id=? AND owner=?", (task_id, owner)).fetchone()
        return dict(r) if r else None

    def set_task_state(self, task_id: str, state: str, result: dict[str, Any] | None = None) -> None:
        with self.lock:
            if state == "RUNNING":
                if result is None:
                    self.db.execute(
                        "UPDATE task SET state=?, updated_at=? WHERE id=?",
                        (state, now_iso(), task_id),
                    )
                else:
                    self.db.execute(
                        "UPDATE task SET state=?, result_json=?, updated_at=? WHERE id=?",
                        (state, json.dumps(result, sort_keys=True), now_iso(), task_id),
                    )
            elif result is None:
                self.db.execute(
                    "UPDATE task SET state=?, updated_at=?, lease_owner=NULL, lease_until=NULL "
                    "WHERE id=?",
                    (state, now_iso(), task_id),
                )
            else:
                self.db.execute(
                    "UPDATE task SET state=?, result_json=?, updated_at=?, "
                    "lease_owner=NULL, lease_until=NULL WHERE id=?",
                    (state, json.dumps(result, sort_keys=True), now_iso(), task_id),
                )

    def count_tasks_since(self, owner: str, since_iso: str) -> int:
        with self.lock:
            return int(self.db.execute("SELECT COUNT(*) FROM task WHERE owner=? AND created_at>=?", (owner, since_iso)).fetchone()[0])

    def add_tool_execution(self, task_id: str, name: str, version: str, status: str, input_digest: str,
                           output_digest: str | None, error_code: str | None, started: str | None, finished: str | None) -> None:
        with self.lock:
            self.db.execute("INSERT INTO tool_execution VALUES(?,?,?,?,?,?,?,?,?,?)",
                            (str(uuid.uuid4()), task_id, name, version, status, input_digest, output_digest, error_code, started, finished))

    def tool_executions(self, task_id: str) -> list[dict[str, Any]]:
        with self.lock:
            return [dict(r) for r in self.db.execute("SELECT * FROM tool_execution WHERE task_id=?", (task_id,)).fetchall()]

    # ---- memory (explicit consent, owner-scoped, hard delete) ----
    def memory_add(self, owner: str, mtype: str, value: str, provenance: str, now: str, expires: str | None) -> str:
        mid = str(uuid.uuid4())
        with self.lock:
            self.db.execute("INSERT INTO memory VALUES(?,?,?,?,?,?,?,?,?)", (mid, owner, mtype, value, provenance, now, now, now, expires))
        return mid

    def memory_list(self, owner: str, now: str) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.db.execute("SELECT id,mtype,value,provenance,created_at,updated_at,expires_at FROM memory "
                                   "WHERE owner=? AND (expires_at IS NULL OR expires_at>?) ORDER BY created_at", (owner, now)).fetchall()
        return [dict(r) for r in rows]

    def memory_update(self, owner: str, mid: str, value: str, now: str) -> bool:
        with self.lock:
            return self.db.execute("UPDATE memory SET value=?, updated_at=? WHERE id=? AND owner=?", (value, now, mid, owner)).rowcount == 1

    def memory_delete(self, owner: str, mid: str | None) -> int:
        with self.lock:
            if mid is None:
                return self.db.execute("DELETE FROM memory WHERE owner=?", (owner,)).rowcount
            return self.db.execute("DELETE FROM memory WHERE id=? AND owner=?", (mid, owner)).rowcount

    def memory_purge_expired(self, now: str) -> int:
        with self.lock:
            return self.db.execute("DELETE FROM memory WHERE expires_at IS NOT NULL AND expires_at<=?", (now,)).rowcount

    # ---- backup / restore ----
    def backup(self, dest: str | Path) -> None:
        with self.lock:
            out = sqlite3.connect(str(dest))
            try:
                self.db.backup(out)
            finally:
                out.close()
