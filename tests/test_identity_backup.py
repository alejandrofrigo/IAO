"""Paired offline identity backup tests."""
import sqlite3
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from omega.device_authority import DeviceAuthority
from omega.identity_backup import (
    IdentityBackupError,
    create_identity_backup,
    verify_identity_backup,
)
from omega.operator_identity import OperatorIdentityAuthority, ROOT_SIGNATURE_DOMAIN


def _pair(tmp_path):
    root_private = ec.generate_private_key(ec.SECP256R1())
    root_public = root_private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")
    device_private = ec.generate_private_key(ec.SECP256R1())
    device_public = device_private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")
    identity_db = tmp_path / "identity.sqlite3"
    device_db = tmp_path / "device.sqlite3"
    identity = OperatorIdentityAuthority(
        identity_db, "unused-bootstrap-secret-" + "x" * 40,
        bootstrap_expires_at=time.time() + 600,
        subject_digest_key=b"identity-backup-test-hmac-key-" + b"k" * 32,
    )
    device = DeviceAuthority(device_db, enrollment_code="device-enrollment-secret-" + "d" * 40)
    enrolled = identity.bootstrap(
        "unused-bootstrap-secret-" + "x" * 40, root_public,
        recovery_code="offline-recovery-secret-" + "r" * 40,
    )
    device.enroll("device-enrollment-secret-" + "d" * 40, device_public, owner_subject="operator")
    payload = identity.device_binding_payload(device_public, key_version=1)[1]
    signature = root_private.sign(ROOT_SIGNATURE_DOMAIN + payload, ec.ECDSA(hashes.SHA256()))
    identity.bind_primary_device(enrolled["identity_id"], device_public, signature, expected_key_version=1)
    return identity_db, device_db, root_private, root_public, device_public, identity


def test_paired_identity_backup_is_private_and_verifiable(tmp_path):
    identity_db, device_db, *_ = _pair(tmp_path)
    backup = tmp_path / "offline-backup"
    result = create_identity_backup(identity_db, device_db, backup)
    assert result == {"created": True, "format_version": 1, "root_key_version": 1}
    assert verify_identity_backup(backup) == {
        "valid": True, "root_key_version": 1, "paired": True,
    }
    assert (backup / "manifest.json").stat().st_mode & 0o777 == 0o600
    assert (backup / "operator-identity.sqlite3").stat().st_mode & 0o777 == 0o600
    with pytest.raises(IdentityBackupError, match="IDENTITY_BACKUP_DESTINATION_EXISTS"):
        create_identity_backup(identity_db, device_db, backup)


def test_backup_refuses_divergent_identity_and_device_databases(tmp_path):
    identity_db, device_db, *_ = _pair(tmp_path)
    with sqlite3.connect(device_db) as db:
        db.execute("UPDATE devices SET active=0")
    with pytest.raises(IdentityBackupError, match="IDENTITY_BACKUP_PAIR_MISMATCH"):
        create_identity_backup(identity_db, device_db, tmp_path / "mismatched")


def test_backup_verification_detects_tampering(tmp_path):
    identity_db, device_db, *_ = _pair(tmp_path)
    backup = tmp_path / "backup"
    create_identity_backup(identity_db, device_db, backup)
    with (backup / "device-authority.sqlite3").open("ab") as stream:
        stream.write(b"tampered")
    with pytest.raises(IdentityBackupError, match="IDENTITY_BACKUP_CHECKSUM_MISMATCH"):
        verify_identity_backup(backup)


def test_backup_does_not_restore_revoked_state_or_replace_live_databases(tmp_path):
    identity_db, device_db, root_private, root_public, device_public, identity = _pair(tmp_path)
    backup = tmp_path / "pre-revocation"
    create_identity_backup(identity_db, device_db, backup)
    with sqlite3.connect(identity_db) as db:
        row = db.execute("SELECT identity_id FROM operator_identities WHERE status='ACTIVE'").fetchone()
    identity_id = row[0]
    payload = b"revoke-root-v1\n" + identity_id.encode("ascii")
    signature = root_private.sign(ROOT_SIGNATURE_DOMAIN + payload, ec.ECDSA(hashes.SHA256()))
    identity.revoke(identity_id, signature, expected_key_version=1)
    with pytest.raises(IdentityBackupError, match="IDENTITY_BACKUP_DESTINATION_EXISTS"):
        create_identity_backup(identity_db, device_db, backup)
    assert verify_identity_backup(backup)["valid"] is True
    with sqlite3.connect(identity_db) as db:
        assert db.execute("SELECT status FROM operator_identities WHERE identity_id=?", (identity_id,)).fetchone()[0] == "REVOKED"
    # Verification is intentionally not an installation/restore operation.
