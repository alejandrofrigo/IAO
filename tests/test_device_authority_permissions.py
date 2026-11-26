"""Filesystem safety tests for the privileged device-authority database."""
import stat

import pytest

from omega.device_authority import DeviceAuthority


def test_device_authority_database_and_parent_are_private(tmp_path):
    parent = tmp_path / "state"
    parent.mkdir(mode=0o777)
    database = parent / "device-authority.sqlite3"
    DeviceAuthority(database)
    assert stat.S_IMODE(parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(database.stat().st_mode) == 0o600


def test_device_authority_refuses_database_symlink(tmp_path):
    target = tmp_path / "target.sqlite3"
    target.write_bytes(b"not an authority database")
    link = tmp_path / "device-authority.sqlite3"
    link.symlink_to(target)
    with pytest.raises(RuntimeError, match="SYMLINK_REFUSED|DATABASE_OPEN_FAILED"):
        DeviceAuthority(link)
    assert target.read_bytes() == b"not an authority database"


def test_device_authority_refuses_directory_as_database(tmp_path):
    database = tmp_path / "database"
    database.mkdir()
    with pytest.raises(RuntimeError, match="PATH_NOT_REGULAR_FILE"):
        DeviceAuthority(database)


def test_device_authority_refuses_symlinked_state_directory(tmp_path):
    real = tmp_path / "real-state"
    real.mkdir()
    alias = tmp_path / "state-link"
    alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(RuntimeError, match="SYMLINK_REFUSED"):
        DeviceAuthority(alias / "device-authority.sqlite3")
    assert list(real.iterdir()) == []
