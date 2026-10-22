"""SQLite persistence for dev/pilot-in-sandbox (PostgreSQL remains the target: ADR-002).
All reads of user data take the owner as a mandatory parameter (tenant isolation)."""
import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from omega.audit import GENESIS_HASH, make_event, verify_chain

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
        self.path = str(path)
        self.audit_key = audit_key
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA secure_delete=ON")  # overwrite freed pages: operational deletion must be physical
        self.db.executescript(SCHEMA)

    def close(self) -> None:
        self.db.close()

    def ping(self) -> bool:
        with self.lock:
            return self.db.execute("SELECT 1").fetchone()[0] == 1

    # ---- audit (hash chained) ----
    def audit(self, actor: str, event_type: str, subject: str, **details: Any) -> dict[str, Any]:
        details = {"actor": actor, **details}
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row = self.db.execute("SELECT event_hash FROM audit_event ORDER BY id DESC LIMIT 1").fetchone()
                ev = make_event(event_type, subject, details, row[0] if row else GENESIS_HASH, self.audit_key)
                self.db.execute(
                    "INSERT INTO audit_event(ts,event_type,subject,details,previous_hash,event_hash) VALUES(?,?,?,?,?,?)",
                    (ev["timestamp"], event_type, subject, json.dumps(details, sort_keys=True, ensure_ascii=False),
                     ev["previous_hash"], ev["event_hash"]))
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise
        return ev

    def _all_events(self) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.db.execute("SELECT * FROM audit_event ORDER BY id").fetchall()
        return [{"id": r["id"], "event_type": r["event_type"], "subject": r["subject"],
                 "details": json.loads(r["details"]), "timestamp": r["ts"],
                 "previous_hash": r["previous_hash"], "event_hash": r["event_hash"]} for r in rows]

    def verify_audit(self) -> tuple[bool, int | None]:
        evs = [{k: v for k, v in e.items() if k != "id"} for e in self._all_events()]
        return verify_chain(evs, self.audit_key)

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

    def get_task(self, task_id: str, owner: str) -> dict[str, Any] | None:
        with self.lock:
            r = self.db.execute("SELECT * FROM task WHERE id=? AND owner=?", (task_id, owner)).fetchone()
        return dict(r) if r else None

    def set_task_state(self, task_id: str, state: str, result: dict[str, Any] | None = None) -> None:
        with self.lock:
            if result is None:
                self.db.execute("UPDATE task SET state=?, updated_at=? WHERE id=?", (state, now_iso(), task_id))
            else:
                self.db.execute("UPDATE task SET state=?, result_json=?, updated_at=? WHERE id=?",
                                (state, json.dumps(result, sort_keys=True), now_iso(), task_id))

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
