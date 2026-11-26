"""Tests for the isolated durable operator root-key registry."""
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from omega.operator_identity import (
    OperatorIdentityAuthority,
    OperatorIdentityError,
    ROOT_SIGNATURE_DOMAIN,
)


def keypair():
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return private, public


def sign(private, payload):
    return private.sign(ROOT_SIGNATURE_DOMAIN + payload, ec.ECDSA(hashes.SHA256()))


def test_bootstrap_is_one_time_and_persists_across_restart(tmp_path):
    code = "bootstrap-secret-" + "x" * 40
    private, public = keypair()
    db = tmp_path / "identity.sqlite3"
    authority = OperatorIdentityAuthority(db, code, bootstrap_expires_at=time.time() + 600)
    enrolled = authority.bootstrap(code, public)
    assert enrolled["key_version"] == 1
    assert authority.verify_root_signature(
        enrolled["identity_id"], b"probe", sign(private, b"probe"),
        expected_key_version=1,
    )
    restarted = OperatorIdentityAuthority(db, code, bootstrap_expires_at=time.time() + 600)
    with pytest.raises(OperatorIdentityError, match="OPERATOR_BOOTSTRAP_ALREADY_USED"):
        restarted.bootstrap(code, public)


def test_bootstrap_rejects_invalid_secret_and_non_p256_key(tmp_path):
    code = "bootstrap-secret-" + "x" * 40
    _, public = keypair()
    authority = OperatorIdentityAuthority(tmp_path / "identity.sqlite3", code, bootstrap_expires_at=time.time() + 600)
    with pytest.raises(OperatorIdentityError, match="INVALID_OPERATOR_BOOTSTRAP"):
        authority.bootstrap("wrong-" + "y" * 40, public)
    rsa = __import__("cryptography.hazmat.primitives.asymmetric.rsa", fromlist=["rsa"]).generate_private_key(
        public_exponent=65537, key_size=2048
    )
    rsa_public = rsa.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    with pytest.raises(OperatorIdentityError, match="UNSUPPORTED_ROOT_KEY"):
        authority.bootstrap(code, rsa_public)


def test_only_one_active_root_and_signature_is_domain_separated(tmp_path):
    code = "bootstrap-secret-" + "x" * 40
    private, public = keypair()
    _, other_public = keypair()
    authority = OperatorIdentityAuthority(tmp_path / "identity.sqlite3", code, bootstrap_expires_at=time.time() + 600)
    enrolled = authority.bootstrap(code, public)
    second_code = "another-bootstrap-" + "z" * 40
    second_authority = OperatorIdentityAuthority(
        tmp_path / "identity.sqlite3", second_code,
        bootstrap_expires_at=time.time() + 600,
    )
    with pytest.raises(OperatorIdentityError, match="OPERATOR_ROOT_ALREADY_ENROLLED"):
        second_authority.bootstrap(second_code, other_public)
    with pytest.raises(OperatorIdentityError, match="INVALID_ROOT_SIGNATURE"):
        authority.verify_root_signature(
            enrolled["identity_id"], b"probe", sign(private, b"other"),
            expected_key_version=1,
        )


def test_root_rotation_requires_old_key_and_invalidates_old_key(tmp_path):
    code = "bootstrap-secret-" + "x" * 40
    old_private, old_public = keypair()
    new_private, new_public = keypair()
    authority = OperatorIdentityAuthority(tmp_path / "identity.sqlite3", code, bootstrap_expires_at=time.time() + 600)
    enrolled = authority.bootstrap(code, old_public)
    identity_id = enrolled["identity_id"]
    next_version = 2
    canonical_new = serialization.load_pem_public_key(new_public.encode()).public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    import hashlib
    payload = (
        b"rotate-root-v1\n" + identity_id.encode("ascii") + b"\n"
        + b"2\n" + hashlib.sha256(canonical_new.encode("ascii")).hexdigest().encode("ascii")
    )
    assert authority.rotate_root(identity_id, new_public, sign(old_private, payload)) == {
        "key_version": next_version
    }
    with pytest.raises(OperatorIdentityError, match="OPERATOR_ROOT_KEY_VERSION_MISMATCH"):
        authority.verify_root_signature(
            identity_id, b"probe", sign(old_private, b"probe"),
            expected_key_version=1,
        )
    assert authority.verify_root_signature(
        identity_id, b"probe", sign(new_private, b"probe"),
        expected_key_version=2,
    )


def test_revocation_is_persistent_and_fail_closed(tmp_path):
    code = "bootstrap-secret-" + "x" * 40
    private, public = keypair()
    db = tmp_path / "identity.sqlite3"
    authority = OperatorIdentityAuthority(db, code, bootstrap_expires_at=time.time() + 600)
    enrolled = authority.bootstrap(code, public)
    identity_id = enrolled["identity_id"]
    authority.revoke(
        identity_id, sign(private, b"revoke-root-v1\n" + identity_id.encode("ascii")),
        expected_key_version=1,
    )
    restarted = OperatorIdentityAuthority(db, code, bootstrap_expires_at=time.time() + 600)
    with pytest.raises(OperatorIdentityError, match="OPERATOR_IDENTITY_NOT_ACTIVE"):
        restarted.verify_root_signature(
            identity_id, b"probe", sign(private, b"probe"),
            expected_key_version=1,
        )


def test_disabled_bootstrap_and_oversized_payload_fail_closed(tmp_path):
    _, public = keypair()
    disabled = OperatorIdentityAuthority(tmp_path / "disabled.sqlite3")
    with pytest.raises(OperatorIdentityError, match="OPERATOR_BOOTSTRAP_DISABLED"):
        disabled.bootstrap("x" * 40, public)
    enabled = OperatorIdentityAuthority(tmp_path / "enabled.sqlite3", "x" * 40, bootstrap_expires_at=time.time() + 600)
    enrolled = enabled.bootstrap("x" * 40, public)
    with pytest.raises(OperatorIdentityError, match="INVALID_ROOT_SIGNED_PAYLOAD"):
        enabled.verify_root_signature(
            enrolled["identity_id"], b"x" * 8193, b"x" * 70,
            expected_key_version=1,
        )



def test_root_signature_binds_exact_primary_device_key_once(tmp_path):
    code = "bootstrap-secret-" + "x" * 40
    root_private, root_public = keypair()
    _, device_public = keypair()
    _, attacker_public = keypair()
    authority = OperatorIdentityAuthority(tmp_path / "identity.sqlite3", code, bootstrap_expires_at=time.time() + 600)
    identity = authority.bootstrap(code, root_public)
    device_id, payload = authority.device_binding_payload(
        device_public, key_version=1
    )
    assert device_id
    signature = sign(root_private, payload)
    assert authority.bind_primary_device(
        identity["identity_id"], device_public, signature,
        expected_key_version=1,
    ) == {"key_version": 1}
    assert authority.verify_primary_device(identity["identity_id"], device_public)
    with pytest.raises(OperatorIdentityError, match="PRIMARY_DEVICE_KEY_MISMATCH"):
        authority.verify_primary_device(identity["identity_id"], attacker_public)


def test_primary_device_binding_rejects_wrong_root_signature_and_duplicate(tmp_path):
    code = "bootstrap-secret-" + "x" * 40
    root_private, root_public = keypair()
    wrong_private, _ = keypair()
    _, device_public = keypair()
    _, other_device_public = keypair()
    authority = OperatorIdentityAuthority(tmp_path / "identity.sqlite3", code, bootstrap_expires_at=time.time() + 600)
    identity = authority.bootstrap(code, root_public)
    _, payload = authority.device_binding_payload(device_public, key_version=1)
    with pytest.raises(OperatorIdentityError, match="INVALID_ROOT_SIGNATURE"):
        authority.bind_primary_device(
            identity["identity_id"], device_public, sign(wrong_private, payload),
            expected_key_version=1,
        )
    authority.bind_primary_device(
        identity["identity_id"], device_public, sign(root_private, payload),
        expected_key_version=1,
    )
    _, other_payload = authority.device_binding_payload(other_device_public, key_version=1)
    with pytest.raises(OperatorIdentityError, match="PRIMARY_DEVICE_ALREADY_BOUND"):
        authority.bind_primary_device(
            identity["identity_id"], other_device_public,
            sign(root_private, other_payload), expected_key_version=1,
        )


def test_root_rotation_invalidates_old_device_binding_until_rebound(tmp_path):
    import hashlib
    code = "bootstrap-secret-" + "x" * 40
    root_private, root_public = keypair()
    new_root_private, new_root_public = keypair()
    _, device_public = keypair()
    authority = OperatorIdentityAuthority(tmp_path / "identity.sqlite3", code, bootstrap_expires_at=time.time() + 600)
    identity = authority.bootstrap(code, root_public)
    identity_id = identity["identity_id"]
    _, device_payload = authority.device_binding_payload(device_public, key_version=1)
    authority.bind_primary_device(
        identity_id, device_public, sign(root_private, device_payload),
        expected_key_version=1,
    )
    canonical_new = serialization.load_pem_public_key(new_root_public.encode()).public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    rotate_payload = (
        b"rotate-root-v1\n" + identity_id.encode("ascii") + b"\n"
        + b"2\n" + hashlib.sha256(canonical_new.encode("ascii")).hexdigest().encode("ascii")
    )
    authority.rotate_root(
        identity_id, new_root_public, sign(root_private, rotate_payload)
    )
    with pytest.raises(OperatorIdentityError, match="OPERATOR_ROOT_KEY_VERSION_MISMATCH"):
        authority.verify_primary_device(identity_id, device_public)
    _, rebound_payload = authority.device_binding_payload(device_public, key_version=2)
    authority.bind_primary_device(
        identity_id, device_public, sign(new_root_private, rebound_payload),
        expected_key_version=2,
    )
    assert authority.verify_primary_device(identity_id, device_public)



def test_bootstrap_rejects_expired_or_missing_expiry(tmp_path):
    code = "bootstrap-secret-" + "x" * 40
    _, public = keypair()
    expired = OperatorIdentityAuthority(
        tmp_path / "expired.sqlite3", code,
        bootstrap_expires_at=time.time() - 1,
    )
    with pytest.raises(OperatorIdentityError, match="OPERATOR_BOOTSTRAP_DISABLED"):
        expired.bootstrap(code, public)
    no_expiry = OperatorIdentityAuthority(tmp_path / "no-expiry.sqlite3", code)
    with pytest.raises(OperatorIdentityError, match="OPERATOR_BOOTSTRAP_DISABLED"):
        no_expiry.bootstrap(code, public)



def test_bootstrap_rechecks_expiry_inside_write_transaction(tmp_path, monkeypatch):
    code = "bootstrap-race-secret-" + "x" * 40
    _, public = keypair()
    db = tmp_path / "expiry-race.sqlite3"
    authority = OperatorIdentityAuthority(
        db, code, bootstrap_expires_at=200.0
    )

    clock_values = iter([100.0, 201.0])
    monkeypatch.setattr(
        "omega.operator_identity.time.time", lambda: next(clock_values)
    )
    with pytest.raises(OperatorIdentityError, match="OPERATOR_BOOTSTRAP_DISABLED"):
        authority.bootstrap(code, public)
    monkeypatch.undo()

    # The expired attempt must not consume the one-time capability or create
    # an active root; a separately provisioned, fresh window can still enroll.
    fresh = OperatorIdentityAuthority(
        db, code, bootstrap_expires_at=time.time() + 600
    )
    assert fresh.bootstrap(code, public)["key_version"] == 1


def test_revocation_releases_primary_slot_for_explicit_new_root_recovery(tmp_path):
    code = "bootstrap-secret-" + "x" * 40
    recovery_code = "recovery-bootstrap-" + "y" * 40
    old_root, old_root_public = keypair()
    new_root, new_root_public = keypair()
    _, old_device_public = keypair()
    _, new_device_public = keypair()
    db = tmp_path / "identity.sqlite3"
    authority = OperatorIdentityAuthority(
        db, code, bootstrap_expires_at=time.time() + 600
    )
    old_identity = authority.bootstrap(code, old_root_public)
    old_id = old_identity["identity_id"]
    _, old_binding = authority.device_binding_payload(
        old_device_public, key_version=1
    )
    authority.bind_primary_device(
        old_id, old_device_public, sign(old_root, old_binding),
        expected_key_version=1,
    )
    authority.revoke(
        old_id, sign(old_root, b"revoke-root-v1\n" + old_id.encode("ascii")),
        expected_key_version=1,
    )
    with pytest.raises(OperatorIdentityError, match="PRIMARY_DEVICE_NOT_AUTHORIZED"):
        authority.verify_primary_device(old_id, old_device_public)

    recovered = OperatorIdentityAuthority(
        db, recovery_code, bootstrap_expires_at=time.time() + 600
    )
    new_identity = recovered.bootstrap(recovery_code, new_root_public)
    new_id = new_identity["identity_id"]
    _, new_binding = recovered.device_binding_payload(
        new_device_public, key_version=1
    )
    recovered.bind_primary_device(
        new_id, new_device_public, sign(new_root, new_binding),
        expected_key_version=1,
    )
    assert recovered.verify_primary_device(new_id, new_device_public)
    with pytest.raises(OperatorIdentityError, match="PRIMARY_DEVICE_NOT_AUTHORIZED"):
        recovered.verify_primary_device(old_id, old_device_public)
