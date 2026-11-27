"""Persistent SQLite state must be private and must not follow DB symlinks."""
import stat

import pytest

from omega.store import Store


def test_store_creates_private_state_directory_and_database(tmp_path):
    state = tmp_path / "private-state"
    store = Store(state / "omega.db", audit_key=b"audit-key-" + b"x" * 40)
    try:
        assert stat.S_IMODE(state.stat().st_mode) == 0o700
        assert stat.S_IMODE((state / "omega.db").stat().st_mode) == 0o600
        assert store.ping()
    finally:
        store.close()


def test_store_refuses_database_symlink(tmp_path):
    state = tmp_path / "private-state"
    state.mkdir(mode=0o700)
    target = tmp_path / "outside.db"
    target.write_bytes(b"must remain untouched")
    link = state / "omega.db"
    link.symlink_to(target)

    with pytest.raises(RuntimeError, match="DATABASE_SYMLINK_REFUSED"):
        Store(link, audit_key=b"audit-key-" + b"x" * 40)

    assert target.read_bytes() == b"must remain untouched"


def test_schema_migrations_are_versioned_and_repeatable(tmp_path):
    path = tmp_path / "state" / "omega.db"
    first = Store(path, audit_key=b"audit-key-" + b"x" * 40)
    try:
        versions = [row[0] for row in first.db.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        )]
        assert versions == [1, 2, 3]
        assert first.db.execute("SELECT COUNT(*) FROM audit_control").fetchone()[0] == 1
    finally:
        first.close()

    second = Store(path, audit_key=b"audit-key-" + b"x" * 40)
    try:
        assert second.db.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 3
        assert second.db.execute("SELECT COUNT(*) FROM audit_control").fetchone()[0] == 1
        assert second.ping()
    finally:
        second.close()


def test_legacy_task_schema_is_migrated_additively(tmp_path):
    import sqlite3

    path = tmp_path / "legacy.db"
    db = sqlite3.connect(path)
    db.execute(
        "CREATE TABLE task(id TEXT PRIMARY KEY, owner TEXT NOT NULL, "
        "state TEXT NOT NULL, intent_json TEXT NOT NULL, result_json TEXT, "
        "idem_key TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, "
        "UNIQUE(owner, idem_key))"
    )
    db.commit()
    db.close()

    store = Store(path, audit_key=b"audit-key-" + b"x" * 40)
    try:
        columns = {row["name"] for row in store.db.execute("PRAGMA table_info(task)")}
        assert {"lease_owner", "lease_until", "attempt_count"} <= columns
        assert store.db.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 3
    finally:
        store.close()


def test_future_schema_version_fails_closed(tmp_path):
    import sqlite3

    path = tmp_path / "future.db"
    db = sqlite3.connect(path)
    db.execute(
        "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
    )
    db.execute("INSERT INTO schema_migrations(version, applied_at) VALUES(99, 'future')")
    db.commit()
    db.close()

    with pytest.raises(RuntimeError, match="DATABASE_SCHEMA_VERSION_UNSUPPORTED"):
        Store(path, audit_key=b"audit-key-" + b"x" * 40)


def test_audit_hmac_key_rotation_fails_closed(tmp_path):
    path = tmp_path / "audit.db"
    first = Store(path, audit_key=b"first-audit-key-" + b"a" * 40)
    first.audit("test", "TEST_EVENT", "subject")
    first.close()

    with pytest.raises(RuntimeError, match="AUDIT_HMAC_KEY_MISMATCH"):
        Store(path, audit_key=b"second-audit-key-" + b"b" * 40)


def test_audit_status_detects_persisted_event_tampering(tmp_path):
    path = tmp_path / "tampered.db"
    store = Store(path, audit_key=b"audit-key-" + b"x" * 40)
    try:
        store.audit("test", "TEST_EVENT", "subject", safe_detail="original")
        store.db.execute(
            "UPDATE audit_event_v2 SET details=? WHERE id=1",
            ('{"actor":"test","safe_detail":"changed"}',),
        )
        status = store.audit_status()
        assert status["authenticated"] is True
        assert status["valid"] is False
        assert status["first_invalid_index"] == 0
    finally:
        store.close()


def test_unkeyed_audit_is_not_reported_as_authenticated():
    store = Store(":memory:")
    try:
        store.audit("test", "TEST_EVENT", "subject")
        status = store.audit_status()
        assert status["authenticated"] is False
        assert status["valid"] is True
    finally:
        store.close()