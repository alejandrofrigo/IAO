"""Monotonic identity rollback-anchor tests, including an old SQLite snapshot replay."""
import shutil
import sqlite3
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from omega.device_authority import DeviceAuthority
from omega.identity_backup import create_identity_backup
from omega.identity_rollback_anchor import (
    IdentityRollbackAnchor,
    IdentityRollbackAnchorError,
    capture_identity_state,
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
    identity_db, device_db = tmp_path / "identity.sqlite3", tmp_path / "device.sqlite3"
    identity = OperatorIdentityAuthority(
        identity_db, "bootstrap-secret-" + "b" * 40,
        bootstrap_expires_at=time.time() + 600,
        subject_digest_key=b"rollback-anchor-test-hmac-key-" + b"k" * 32,
    )
    device = DeviceAuthority(device_db, enrollment_code="device-secret-" + "d" * 40)
    enrolled = identity.bootstrap(
        "bootstrap-secret-" + "b" * 40, root_public,
        recovery_code="recovery-secret-" + "r" * 40,
    )
    device.enroll("device-secret-" + "d" * 40, device_public, owner_subject="operator")
    _, payload = identity.device_binding_payload(device_public, key_version=1)
    signature = root_private.sign(ROOT_SIGNATURE_DOMAIN + payload, ec.ECDSA(hashes.SHA256()))
    identity.bind_primary_device(enrolled["identity_id"], device_public, signature, expected_key_version=1)
    return identity_db, device_db, root_private, enrolled["identity_id"]


def test_anchor_detects_restoration_of_pre_revocation_database_pair(tmp_path):
    identity_db, device_db, root_private, identity_id = _pair(tmp_path)
    backup = tmp_path / "old-backup"
    create_identity_backup(identity_db, device_db, backup)
    anchor = IdentityRollbackAnchor(tmp_path / "trusted-state" / "identity.anchor", tmp_path / "trusted-state" / "identity.key")
    before = capture_identity_state(identity_db, device_db)
    assert anchor.initialize(before) == {"initialized": True, "sequence": 1}

    payload = b"revoke-root-v1\n" + identity_id.encode("ascii")
    signature = root_private.sign(ROOT_SIGNATURE_DOMAIN + payload, ec.ECDSA(hashes.SHA256()))
    # Reopen the authority from the same database and apply the real revocation path.
    authority = OperatorIdentityAuthority(identity_db)
    authority.revoke(identity_id, signature, expected_key_version=1)
    after = capture_identity_state(identity_db, device_db)
    assert anchor.advance(after, expected_sequence=1) == {"advanced": True, "sequence": 2}
    assert anchor.verify(after) == {"valid": True, "sequence": 2}

    restored = tmp_path / "restored"
    restored.mkdir()
    shutil.copy2(backup / "operator-identity.sqlite3", restored / "identity.sqlite3")
    shutil.copy2(backup / "device-authority.sqlite3", restored / "device.sqlite3")
    old_state = capture_identity_state(restored / "identity.sqlite3", restored / "device.sqlite3")
    with pytest.raises(IdentityRollbackAnchorError, match="IDENTITY_ANCHOR_STATE_MISMATCH"):
        anchor.verify(old_state)


def test_anchor_rejects_wrong_sequence_and_unchanged_state(tmp_path):
    identity_db, device_db, *_ = _pair(tmp_path)
    state = capture_identity_state(identity_db, device_db)
    anchor = IdentityRollbackAnchor(tmp_path / "anchor" / "state.json", tmp_path / "anchor" / "key")
    anchor.initialize(state)
    with pytest.raises(IdentityRollbackAnchorError, match="IDENTITY_ANCHOR_SEQUENCE_CONFLICT"):
        anchor.advance({**state, "ledger_digest": "f" * 64}, expected_sequence=2)
    with pytest.raises(IdentityRollbackAnchorError, match="IDENTITY_ANCHOR_NO_STATE_CHANGE"):
        anchor.advance(state, expected_sequence=1)


def test_anchor_digest_covers_recovery_and_replay_state_tables(tmp_path):
    identity_db, device_db, *_ = _pair(tmp_path)
    before = capture_identity_state(identity_db, device_db)
    anchor = IdentityRollbackAnchor(
        tmp_path / "trusted" / "identity.anchor",
        tmp_path / "trusted" / "identity.key",
    )
    anchor.initialize(before)
    with sqlite3.connect(identity_db) as db:
        db.execute(
            "INSERT INTO consumed_bootstrap_codes(code_digest,consumed_at) VALUES(?,?)",
            ("a" * 64, 123.0),
        )
    after = capture_identity_state(identity_db, device_db)
    assert after["identity_database_digest"] != before["identity_database_digest"]
    with pytest.raises(IdentityRollbackAnchorError, match="IDENTITY_ANCHOR_STATE_MISMATCH"):
        anchor.verify(after)


def test_anchor_detects_record_tampering_and_missing_key(tmp_path):
    identity_db, device_db, *_ = _pair(tmp_path)
    state = capture_identity_state(identity_db, device_db)
    directory = tmp_path / "anchor"
    anchor = IdentityRollbackAnchor(directory / "state.json", directory / "key")
    anchor.initialize(state)
    path = directory / "state.json"
    path.write_text(path.read_text().replace('"sequence":1', '"sequence":2'), encoding="ascii")
    with pytest.raises(IdentityRollbackAnchorError, match="IDENTITY_ANCHOR_MAC_INVALID"):
        anchor.verify(state)
    path.unlink()
    (directory / "key").unlink()
    with pytest.raises(IdentityRollbackAnchorError, match="IDENTITY_ANCHOR_UNAVAILABLE"):
        anchor.verify(state)


def test_anchor_refuses_symlink_key_and_insecure_key_permissions(tmp_path):
    identity_db, device_db, *_ = _pair(tmp_path)
    state = capture_identity_state(identity_db, device_db)
    directory = tmp_path / "anchor"
    directory.mkdir()
    real_key = directory / "real-key"
    real_key.write_bytes(b"x" * 32)
    real_key.chmod(0o600)
    (directory / "key").symlink_to(real_key)
    anchor = IdentityRollbackAnchor(directory / "state.json", directory / "key")
    with pytest.raises(IdentityRollbackAnchorError, match="IDENTITY_ANCHOR_ALREADY_INITIALIZED"):
        anchor.initialize(state)
