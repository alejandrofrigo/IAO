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
