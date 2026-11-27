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
