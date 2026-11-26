"""Tests for the isolated durable operator root-key registry."""
import base64
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from omega.device_authority import DeviceAuthority

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



def test_session_challenge_binds_exact_authenticated_subject_and_persists(tmp_path):
    import base64

    code = "session-bootstrap-" + "s" * 40
    root_private, root_public = keypair()
    db = tmp_path / "identity.sqlite3"
    authority = OperatorIdentityAuthority(
        db, code, bootstrap_expires_at=time.time() + 600,
        subject_digest_key="operator-session-test-key-" + "a" * 40,
    )
    identity = authority.bootstrap(code, root_public)
    token_a = "session-token-A-" + "a" * 40
    token_b = "session-token-B-" + "b" * 40
    challenge = authority.create_session_challenge("verified-subject-A", token_a)
    payload = base64.urlsafe_b64decode(
        challenge["signing_payload"] + "=" * (-len(challenge["signing_payload"]) % 4)
    )
    signature = sign(root_private, payload)

    with pytest.raises(OperatorIdentityError, match="OPERATOR_SESSION_MISMATCH"):
        authority.bind_authenticated_session(
            challenge["challenge"], "verified-subject-B", token_a, signature
        )
    with pytest.raises(OperatorIdentityError, match="OPERATOR_SESSION_MISMATCH"):
        authority.bind_authenticated_session(
            challenge["challenge"], "verified-subject-A", token_b, signature
        )
    assert authority.bind_authenticated_session(
        challenge["challenge"], "verified-subject-A", token_a, signature
    ) == {"key_version": 1}
    assert authority.verify_authenticated_session("verified-subject-A", token_a)
    assert not authority.verify_authenticated_session("verified-subject-A", token_b)
    assert not authority.verify_authenticated_session("verified-subject-B", token_a)

    refreshed = authority.create_session_challenge("verified-subject-A", token_b)
    refreshed_payload = base64.urlsafe_b64decode(
        refreshed["signing_payload"]
        + "=" * (-len(refreshed["signing_payload"]) % 4)
    )
    authority.bind_authenticated_session(
        refreshed["challenge"], "verified-subject-A", token_b,
        sign(root_private, refreshed_payload),
    )
    assert authority.verify_authenticated_session("verified-subject-A", token_b)
    assert not authority.verify_authenticated_session("verified-subject-A", token_a)

    restarted = OperatorIdentityAuthority(
        db, subject_digest_key="operator-session-test-key-" + "a" * 40
    )
    assert restarted.verify_authenticated_session("verified-subject-A", token_b)
    with pytest.raises(OperatorIdentityError, match="SESSION_CHALLENGE_REPLAYED"):
        restarted.bind_authenticated_session(
            challenge["challenge"], "verified-subject-A", token_a, signature
        )
    assert "identity_id" not in challenge
    assert identity["identity_id"] not in challenge["signing_payload"]
    assert token_a not in challenge["signing_payload"]
    assert token_a.encode("utf-8") not in db.read_bytes()
    assert "verified-subject-A" not in challenge["signing_payload"]


def test_session_binding_rejects_invalid_signature_guest_and_expiry(tmp_path, monkeypatch):
    import base64

    code = "session-bootstrap-" + "t" * 40
    root_private, root_public = keypair()
    attacker, _ = keypair()
    authority = OperatorIdentityAuthority(
        tmp_path / "identity.sqlite3", code,
        bootstrap_expires_at=time.time() + 600,
        subject_digest_key="operator-session-test-key-" + "b" * 40,
    )
    authority.bootstrap(code, root_public)
    with pytest.raises(OperatorIdentityError, match="OPERATOR_SESSION_REQUIRED"):
        authority.create_session_challenge(
            "guest:anonymous", "session-token-guest-" + "g" * 40
        )
    token = "session-token-valid-" + "v" * 40
    challenge = authority.create_session_challenge("verified-subject", token)
    payload = base64.urlsafe_b64decode(
        challenge["signing_payload"] + "=" * (-len(challenge["signing_payload"]) % 4)
    )
    with pytest.raises(OperatorIdentityError, match="INVALID_ROOT_SIGNATURE"):
        authority.bind_authenticated_session(
            challenge["challenge"], "verified-subject", token,
            sign(attacker, payload)
        )

    expired = authority.create_session_challenge("verified-subject", token)
    expired_payload = base64.urlsafe_b64decode(
        expired["signing_payload"] + "=" * (-len(expired["signing_payload"]) % 4)
    )
    future = time.time() + 1000
    monkeypatch.setattr("omega.operator_identity.time.time", lambda: future)
    with pytest.raises(OperatorIdentityError, match="SESSION_CHALLENGE_EXPIRED"):
        authority.bind_authenticated_session(
            expired["challenge"], "verified-subject", token,
            sign(root_private, expired_payload)
        )


def test_session_binding_is_invalidated_by_root_rotation_and_revocation(tmp_path):
    import base64
    import hashlib

    code = "session-bootstrap-" + "u" * 40
    old_root, old_public = keypair()
    new_root, new_public = keypair()
    authority = OperatorIdentityAuthority(
        tmp_path / "identity.sqlite3", code,
        bootstrap_expires_at=time.time() + 600,
        subject_digest_key="operator-session-test-key-" + "c" * 40,
    )
    identity = authority.bootstrap(code, old_public)
    token = "session-token-lifecycle-" + "r" * 40
    challenge = authority.create_session_challenge("verified-subject", token)
    payload = base64.urlsafe_b64decode(
        challenge["signing_payload"] + "=" * (-len(challenge["signing_payload"]) % 4)
    )
    authority.bind_authenticated_session(
        challenge["challenge"], "verified-subject", token, sign(old_root, payload)
    )
    assert authority.verify_authenticated_session("verified-subject", token)

    canonical_new = serialization.load_pem_public_key(new_public.encode()).public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    rotate_payload = (
        b"rotate-root-v1\n" + identity["identity_id"].encode("ascii") + b"\n"
        + b"2\n" + hashlib.sha256(canonical_new.encode("ascii")).hexdigest().encode("ascii")
    )
    authority.rotate_root(
        identity["identity_id"], new_public, sign(old_root, rotate_payload)
    )
    assert not authority.verify_authenticated_session("verified-subject", token)

    refreshed = authority.create_session_challenge("verified-subject", token)
    refreshed_payload = base64.urlsafe_b64decode(
        refreshed["signing_payload"]
        + "=" * (-len(refreshed["signing_payload"]) % 4)
    )
    authority.bind_authenticated_session(
        refreshed["challenge"], "verified-subject", token,
        sign(new_root, refreshed_payload),
    )
    assert authority.verify_authenticated_session("verified-subject", token)

    revoke_payload = b"revoke-root-v1\n" + identity["identity_id"].encode("ascii")
    authority.revoke(
        identity["identity_id"], sign(new_root, revoke_payload),
        expected_key_version=2,
    )
    assert not authority.verify_authenticated_session("verified-subject", token)


def test_dual_signature_operator_login_is_one_time_and_read_only(tmp_path):
    import base64
    from omega.auth import verify_token

    code = "operator-login-bootstrap-" + "l" * 40
    root_private, root_public = keypair()
    device_private, device_public = keypair()
    authority = OperatorIdentityAuthority(
        tmp_path / "operator-login.sqlite3", code,
        bootstrap_expires_at=time.time() + 600,
        subject_digest_key="operator-login-session-key-" + "s" * 40,
    )
    identity = authority.bootstrap(code, root_public)
    device_id, binding_payload = authority.device_binding_payload(
        device_public, key_version=1
    )
    authority.bind_primary_device(
        identity["identity_id"], device_public,
        sign(root_private, binding_payload), expected_key_version=1,
    )

    challenge = authority.create_operator_login_challenge()
    payload = base64.urlsafe_b64decode(
        challenge["signing_payload"]
        + "=" * (-len(challenge["signing_payload"]) % 4)
    )
    root_signature = sign(root_private, payload)
    device_signature = device_private.sign(
        b"IAO-OPERATOR-DEVICE-LOGIN-V1\x00" + payload,
        ec.ECDSA(hashes.SHA256()),
    )
    result = authority.complete_operator_login(
        challenge["challenge"], root_signature, device_signature,
        "operator-login-token-key-" + "k" * 40,
    )
    assert result["authority"] == "OPERATOR_AUTHENTICATED_READ_ONLY"
    assert result["scopes"] == []
    assert result["expires_in"] == 900
    principal = verify_token(
        "operator-login-token-key-" + "k" * 40, result["access_token"]
    )
    assert principal is not None
    assert principal.subject == "operator:" + identity["identity_id"]
    assert principal.scopes == frozenset()
    assert authority.verify_authenticated_session(
        principal.subject, result["access_token"]
    )
    with pytest.raises(OperatorIdentityError, match="OPERATOR_LOGIN_REPLAYED"):
        authority.complete_operator_login(
            challenge["challenge"], root_signature, device_signature,
            "operator-login-token-key-" + "k" * 40,
        )
    assert result["access_token"].encode() not in (
        tmp_path / "operator-login.sqlite3"
    ).read_bytes()
    assert device_id not in challenge["signing_payload"]


def test_dual_signature_operator_login_rejects_wrong_device_signature(tmp_path):
    import base64

    code = "operator-login-invalid-" + "m" * 40
    root_private, root_public = keypair()
    device_private, device_public = keypair()
    attacker, _ = keypair()
    authority = OperatorIdentityAuthority(
        tmp_path / "operator-login-invalid.sqlite3", code,
        bootstrap_expires_at=time.time() + 600,
        subject_digest_key="operator-login-session-key-" + "t" * 40,
    )
    identity = authority.bootstrap(code, root_public)
    _, binding_payload = authority.device_binding_payload(device_public, key_version=1)
    authority.bind_primary_device(
        identity["identity_id"], device_public,
        sign(root_private, binding_payload), expected_key_version=1,
    )
    challenge = authority.create_operator_login_challenge()
    payload = base64.urlsafe_b64decode(
        challenge["signing_payload"]
        + "=" * (-len(challenge["signing_payload"]) % 4)
    )
    with pytest.raises(OperatorIdentityError, match="INVALID_OPERATOR_LOGIN_SIGNATURE"):
        authority.complete_operator_login(
            challenge["challenge"], sign(root_private, payload),
            attacker.sign(
                b"IAO-OPERATOR-DEVICE-LOGIN-V1\x00" + payload,
                ec.ECDSA(hashes.SHA256()),
            ),
            "operator-login-token-key-" + "u" * 40,
        )
    # Failed proof does not consume the challenge; the enrolled device can retry.
    valid_device_signature = device_private.sign(
        b"IAO-OPERATOR-DEVICE-LOGIN-V1\x00" + payload,
        ec.ECDSA(hashes.SHA256()),
    )
    result = authority.complete_operator_login(
        challenge["challenge"], sign(root_private, payload),
        valid_device_signature, "operator-login-token-key-" + "u" * 40,
    )
    assert result["scopes"] == []


def test_one_time_recovery_replaces_root_and_primary_device_after_revocation(tmp_path):
    bootstrap = "bootstrap-secret-" + "b" * 40
    recovery = "offline-recovery-secret-" + "r" * 48
    next_recovery = "rotated-offline-recovery-" + "n" * 48
    old_private, old_public = keypair()
    new_root_private, new_root_public = keypair()
    new_device_private, new_device_public = keypair()
    authority = OperatorIdentityAuthority(
        tmp_path / "recover.sqlite3", bootstrap,
        bootstrap_expires_at=time.time() + 600,
        subject_digest_key=b"operator-recovery-test-key-" + b"a" * 40,
    )
    identity = authority.bootstrap(bootstrap, old_public, recovery_code=recovery)
    identity_id = identity["identity_id"]
    authority.revoke(
        identity_id,
        sign(old_private, b"revoke-root-v1\n" + identity_id.encode("ascii")),
        expected_key_version=1,
    )

    challenge = authority.create_operator_recovery_challenge(
        recovery, new_root_public, new_device_public, next_recovery,
    )
    payload = base64.urlsafe_b64decode(
        challenge["signing_payload"] + "=" * (-len(challenge["signing_payload"]) % 4)
    )
    root_signature = new_root_private.sign(
        b"IAO-OPERATOR-RECOVERY-V1\x00" + payload,
        ec.ECDSA(hashes.SHA256()),
    )
    device_signature = new_device_private.sign(
        b"IAO-OPERATOR-RECOVERY-DEVICE-V1\x00" + payload,
        ec.ECDSA(hashes.SHA256()),
    )
    replacements = []
    result = authority.complete_operator_recovery(
        challenge["challenge"], root_signature, device_signature,
        device_replacement=lambda public, subject, old=None: replacements.append((public, subject)),
    )
    assert result == {
        "authority": "OPERATOR_RECOVERED_READ_ONLY",
        "key_version": 2,
        "device_replaced": True,
        "recovery_code_rotated": True,
    }
    assert replacements == [(new_device_public, "operator:" + identity_id)]
    assert authority.primary_device_public_key() == new_device_public
    assert authority.verify_root_signature(
        identity_id, b"post-recovery", sign(new_root_private, b"post-recovery"),
        expected_key_version=2,
    )
    with pytest.raises(OperatorIdentityError, match="INVALID_OPERATOR_RECOVERY_CODE"):
        authority.create_operator_recovery_challenge(
            recovery, new_root_public, new_device_public, "unused-next-recovery-" + "u" * 40,
        )
    _, next_root_public = keypair()
    _, next_device_public = keypair()
    next_challenge = authority.create_operator_recovery_challenge(
        next_recovery, next_root_public, next_device_public,
        "second-rotated-recovery-" + "t" * 48,
    )
    assert next_challenge["protocol"] == "IAO-OPERATOR-RECOVERY-V1"
    with pytest.raises(OperatorIdentityError, match="OPERATOR_RECOVERY_REPLAYED"):
        authority.complete_operator_recovery(
            challenge["challenge"], root_signature, device_signature,
            device_replacement=lambda public, subject, old=None: None,
        )


def test_recovery_requires_both_new_private_keys_and_does_not_consume_on_bad_signature(tmp_path):
    bootstrap = "bootstrap-secret-" + "c" * 40
    recovery = "offline-recovery-secret-" + "s" * 48
    next_recovery = "rotated-offline-recovery-" + "m" * 48
    _, old_public = keypair()
    root_private, root_public = keypair()
    device_private, device_public = keypair()
    authority = OperatorIdentityAuthority(
        tmp_path / "recover-signatures.sqlite3", bootstrap,
        bootstrap_expires_at=time.time() + 600,
        subject_digest_key=b"operator-recovery-test-key-" + b"b" * 40,
    )
    authority.bootstrap(bootstrap, old_public, recovery_code=recovery)
    challenge = authority.create_operator_recovery_challenge(
        recovery, root_public, device_public, next_recovery,
    )
    payload = base64.urlsafe_b64decode(
        challenge["signing_payload"] + "=" * (-len(challenge["signing_payload"]) % 4)
    )
    root_signature = root_private.sign(
        b"IAO-OPERATOR-RECOVERY-V1\x00" + payload,
        ec.ECDSA(hashes.SHA256()),
    )
    with pytest.raises(OperatorIdentityError, match="INVALID_OPERATOR_RECOVERY_SIGNATURE"):
        authority.complete_operator_recovery(
            challenge["challenge"], root_signature, b"x" * 70,
            device_replacement=lambda public, subject, old=None: None,
        )
    device_signature = device_private.sign(
        b"IAO-OPERATOR-RECOVERY-DEVICE-V1\x00" + payload,
        ec.ECDSA(hashes.SHA256()),
    )
    result = authority.complete_operator_recovery(
        challenge["challenge"], root_signature, device_signature,
        device_replacement=lambda public, subject, old=None: None,
    )
    assert result["key_version"] == 2


def test_recovery_invalidates_preexisting_operator_session_binding(tmp_path):
    bootstrap = "bootstrap-session-recovery-" + "b" * 40
    recovery = "offline-session-recovery-" + "r" * 48
    next_recovery = "next-offline-session-recovery-" + "n" * 48
    digest_key = b"operator-recovery-session-digest-key-" + b"k" * 24
    old_root, old_public = keypair()
    new_root, new_root_public = keypair()
    new_device, new_device_public = keypair()
    authority = OperatorIdentityAuthority(
        tmp_path / "recovery-session.sqlite3", bootstrap,
        bootstrap_expires_at=time.time() + 600,
        subject_digest_key=digest_key,
    )
    identity = authority.bootstrap(bootstrap, old_public, recovery_code=recovery)
    subject = "operator:" + identity["identity_id"]
    token = "operator-session-token-" + "t" * 48
    session_challenge = authority.create_session_challenge(subject, token)
    session_payload = base64.urlsafe_b64decode(
        session_challenge["signing_payload"]
        + "=" * (-len(session_challenge["signing_payload"]) % 4)
    )
    authority.bind_authenticated_session(
        session_challenge["challenge"], subject, token,
        sign(old_root, session_payload),
    )
    assert authority.verify_authenticated_session(subject, token)

    challenge = authority.create_operator_recovery_challenge(
        recovery, new_root_public, new_device_public, next_recovery,
    )
    payload = base64.urlsafe_b64decode(
        challenge["signing_payload"] + "=" * (-len(challenge["signing_payload"]) % 4)
    )
    root_signature = new_root.sign(
        b"IAO-OPERATOR-RECOVERY-V1\x00" + payload,
        ec.ECDSA(hashes.SHA256()),
    )
    device_signature = new_device.sign(
        b"IAO-OPERATOR-RECOVERY-DEVICE-V1\x00" + payload,
        ec.ECDSA(hashes.SHA256()),
    )
    authority.complete_operator_recovery(
        challenge["challenge"], root_signature, device_signature,
        device_replacement=lambda public, owner, old=None: None,
    )
    assert not authority.verify_authenticated_session(subject, token)


def test_recovery_challenge_and_device_binding_survive_server_restart(tmp_path):
    bootstrap = "restart-bootstrap-" + "b" * 40
    recovery = "restart-recovery-" + "r" * 48
    rotated_recovery = "restart-rotated-recovery-" + "n" * 48
    digest_key = b"restart-recovery-digest-key-" + b"k" * 32
    old_root, old_root_public = keypair()
    _, old_device_public = keypair()
    new_root, new_root_public = keypair()
    new_device_private, new_device_public = keypair()

    identity_db = tmp_path / "operator-identity.sqlite3"
    device_db = tmp_path / "device-authority.sqlite3"
    authority = OperatorIdentityAuthority(
        identity_db, bootstrap,
        bootstrap_expires_at=time.time() + 600,
        subject_digest_key=digest_key,
    )
    identity = authority.bootstrap(
        bootstrap, old_root_public, recovery_code=recovery,
    )
    identity_id = identity["identity_id"]
    owner = "operator:" + identity_id

    enrollment_code = "restart-device-enrollment-" + "e" * 40
    devices = DeviceAuthority(device_db, enrollment_code=enrollment_code)
    devices.enroll(
        enrollment_code, old_device_public, owner_subject="pre-login-owner",
    )
    _, binding_payload = authority.device_binding_payload(
        old_device_public, key_version=1,
    )
    authority.bind_primary_device(
        identity_id, old_device_public, sign(old_root, binding_payload),
        expected_key_version=1,
    )

    challenge = authority.create_operator_recovery_challenge(
        recovery, new_root_public, new_device_public, rotated_recovery,
    )
    payload = base64.urlsafe_b64decode(
        challenge["signing_payload"]
        + "=" * (-len(challenge["signing_payload"]) % 4)
    )
    root_signature = new_root.sign(
        b"IAO-OPERATOR-RECOVERY-V1\x00" + payload,
        ec.ECDSA(hashes.SHA256()),
    )
    device_signature = new_device_private.sign(
        b"IAO-OPERATOR-RECOVERY-DEVICE-V1\x00" + payload,
        ec.ECDSA(hashes.SHA256()),
    )
    # Recreate both authorities as a process restart would, then finish the
    # already-issued one-time challenge against the same durable databases.
    restarted = OperatorIdentityAuthority(
        identity_db, subject_digest_key=digest_key,
    )
    restarted_devices = DeviceAuthority(device_db, enrollment_code="")
    result = restarted.complete_operator_recovery(
        challenge["challenge"], root_signature, device_signature,
        device_replacement=lambda public, subject, old=None: (
            restarted_devices.replace_active_device_for_recovery(
                public, owner_subject=subject,
                expected_old_public_key_pem=old,
            )
        ),
    )

    assert result["key_version"] == 2
    assert restarted.primary_device_public_key() == new_device_public
    assert restarted.verify_root_signature(
        identity_id, b"restart-probe", sign(new_root, b"restart-probe"),
        expected_key_version=2,
    )
    assert restarted_devices.verify_registered_public_key(
        new_device_public, owner_subject=owner,
    )
    with pytest.raises(OperatorIdentityError, match="INVALID_OPERATOR_RECOVERY_CODE"):
        restarted.create_operator_recovery_challenge(
            recovery, new_root_public, new_device_public,
            "unused-recovery-after-restart-" + "u" * 40,
        )
    _, next_root_public = keypair()
    _, next_device_public = keypair()
    next_challenge = restarted.create_operator_recovery_challenge(
        rotated_recovery, next_root_public, next_device_public,
        "second-rotated-recovery-" + "s" * 48,
    )
    assert next_challenge["protocol"] == "IAO-OPERATOR-RECOVERY-V1"


def test_operator_recovery_challenge_expires_before_any_device_replacement(tmp_path, monkeypatch):
    bootstrap = "expiry-bootstrap-" + "b" * 40
    recovery = "expiry-recovery-" + "r" * 48
    rotated = "expiry-rotated-recovery-" + "n" * 48
    _, old_public = keypair()
    new_root, new_root_public = keypair()
    new_device, new_device_public = keypair()
    authority = OperatorIdentityAuthority(
        tmp_path / "recovery-expiry.sqlite3", bootstrap,
        bootstrap_expires_at=time.time() + 600,
        subject_digest_key=b"recovery-expiry-digest-key-" + b"k" * 32,
    )
    authority.bootstrap(bootstrap, old_public, recovery_code=recovery)
    challenge = authority.create_operator_recovery_challenge(
        recovery, new_root_public, new_device_public, rotated,
        ttl_seconds=30,
    )
    payload = base64.urlsafe_b64decode(
        challenge["signing_payload"] + "=" * (-len(challenge["signing_payload"]) % 4)
    )
    root_signature = new_root.sign(
        b"IAO-OPERATOR-RECOVERY-V1\x00" + payload,
        ec.ECDSA(hashes.SHA256()),
    )
    device_signature = new_device.sign(
        b"IAO-OPERATOR-RECOVERY-DEVICE-V1\x00" + payload,
        ec.ECDSA(hashes.SHA256()),
    )
    replaced = []
    expiry = challenge["expires_at"] + 1
    monkeypatch.setattr("omega.operator_identity.time.time", lambda: expiry)
    with pytest.raises(OperatorIdentityError, match="OPERATOR_RECOVERY_EXPIRED"):
        authority.complete_operator_recovery(
            challenge["challenge"], root_signature, device_signature,
            device_replacement=lambda *args: replaced.append(args),
        )
    assert replaced == []
    with authority._database() as db:
        row = db.execute(
            "SELECT consumed_at FROM operator_recovery_challenges WHERE challenge_digest=?",
            (authority._digest(challenge["challenge"]),),
        ).fetchone()
    assert row["consumed_at"] is None
    with authority._database() as db:
        identity = db.execute(
            "SELECT recovery_code_digest, key_version FROM operator_identities"
        ).fetchone()
    assert identity["recovery_code_digest"] == authority._recovery_digest(recovery)
    assert identity["key_version"] == 1



def test_recovery_retries_after_device_commit_and_identity_transaction_failure(tmp_path):
    bootstrap = "partial-commit-bootstrap-" + "b" * 40
    recovery = "partial-commit-recovery-" + "r" * 48
    rotated_recovery = "partial-commit-rotated-" + "n" * 48
    digest_key = b"partial-commit-digest-key-" + b"k" * 32
    old_root, old_root_public = keypair()
    old_device_private, old_device_public = keypair()
    new_root, new_root_public = keypair()
    new_device_private, new_device_public = keypair()

    identity_db = tmp_path / "partial-commit-identity.sqlite3"
    device_db = tmp_path / "partial-commit-device.sqlite3"
    authority = OperatorIdentityAuthority(
        identity_db, bootstrap,
        bootstrap_expires_at=time.time() + 600,
        subject_digest_key=digest_key,
    )
    identity = authority.bootstrap(
        bootstrap, old_root_public, recovery_code=recovery,
    )
    identity_id = identity["identity_id"]
    owner = "operator:" + identity_id
    devices = DeviceAuthority(
        device_db, enrollment_code="partial-commit-enrollment-" + "e" * 40,
    )
    devices.enroll(
        devices.enrollment_code, old_device_public, owner_subject=owner,
    )
    _, binding_payload = authority.device_binding_payload(
        old_device_public, key_version=1,
    )
    authority.bind_primary_device(
        identity_id, old_device_public, sign(old_root, binding_payload),
        expected_key_version=1,
    )

    challenge = authority.create_operator_recovery_challenge(
        recovery, new_root_public, new_device_public, rotated_recovery,
    )
    payload = base64.urlsafe_b64decode(
        challenge["signing_payload"] + "=" * (-len(challenge["signing_payload"]) % 4)
    )
    root_signature = new_root.sign(
        b"IAO-OPERATOR-RECOVERY-V1\x00" + payload,
        ec.ECDSA(hashes.SHA256()),
    )
    device_signature = new_device_private.sign(
        b"IAO-OPERATOR-RECOVERY-DEVICE-V1\x00" + payload,
        ec.ECDSA(hashes.SHA256()),
    )

    with authority._database() as db:
        db.execute("""
            CREATE TRIGGER reject_recovery_identity_update
            BEFORE UPDATE OF root_public_key_pem ON operator_identities
            BEGIN SELECT RAISE(ABORT, 'injected_identity_commit_failure'); END
        """)

    replace_device = lambda public, subject, old=None: (
        devices.replace_active_device_for_recovery(
            public, owner_subject=subject, expected_old_public_key_pem=old,
        )
    )
    with pytest.raises(Exception, match="injected_identity_commit_failure"):
        authority.complete_operator_recovery(
            challenge["challenge"], root_signature, device_signature,
            device_replacement=replace_device,
        )

    # The device DB committed first, but identity state and recovery proof
    # remain unchanged and retryable after the identity transaction rolled back.
    assert devices.verify_registered_public_key(new_device_public, owner_subject=owner)
    with pytest.raises(Exception, match="DEVICE_KEY_NOT_ENROLLED_FOR_OWNER"):
        devices.verify_registered_public_key(old_device_public, owner_subject=owner)
    assert authority.primary_device_public_key() == old_device_public
    with authority._database() as db:
        identity_row = db.execute(
            "SELECT key_version,recovery_code_digest FROM operator_identities"
        ).fetchone()
        challenge_row = db.execute(
            "SELECT consumed_at FROM operator_recovery_challenges WHERE challenge_digest=?",
            (authority._digest(challenge["challenge"]),),
        ).fetchone()
        db.execute("DROP TRIGGER reject_recovery_identity_update")

    assert identity_row["key_version"] == 1
    assert identity_row["recovery_code_digest"] == authority._recovery_digest(recovery)
    assert challenge_row["consumed_at"] is None

    # Retry uses DeviceAuthority's idempotent same-owner replacement path.
    result = authority.complete_operator_recovery(
        challenge["challenge"], root_signature, device_signature,
        device_replacement=replace_device,
    )
    assert result["key_version"] == 2
    assert authority.primary_device_public_key() == new_device_public
    assert devices.verify_registered_public_key(new_device_public, owner_subject=owner)
    with pytest.raises(OperatorIdentityError, match="INVALID_ROOT_SIGNATURE"):
        authority.verify_root_signature(
            identity_id, b"old-root-probe", sign(old_root, b"old-root-probe"),
            expected_key_version=2,
        )
    with authority._database() as db:
        final = db.execute(
            "SELECT key_version,recovery_code_digest FROM operator_identities"
        ).fetchone()
        consumed = db.execute(
            "SELECT consumed_at FROM operator_recovery_challenges WHERE challenge_digest=?",
            (authority._digest(challenge["challenge"]),),
        ).fetchone()
    assert final["key_version"] == 2
    assert final["recovery_code_digest"] == authority._recovery_digest(rotated_recovery)
    assert consumed["consumed_at"] is not None

def test_recovery_challenge_is_single_use_across_independent_authority_instances(tmp_path):
    """Two server workers cannot commit the same recovery challenge twice."""
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier, Lock

    bootstrap = "concurrent-bootstrap-" + "b" * 40
    recovery = "concurrent-recovery-" + "r" * 48
    rotated = "concurrent-rotated-recovery-" + "n" * 48
    digest_key = b"concurrent-recovery-digest-key-" + b"k" * 32
    old_root, old_root_public = keypair()
    _, old_device_public = keypair()
    new_root, new_root_public = keypair()
    new_device, new_device_public = keypair()
    identity_db = tmp_path / "concurrent-identity.sqlite3"
    device_db = tmp_path / "concurrent-device.sqlite3"

    authority = OperatorIdentityAuthority(
        identity_db, bootstrap,
        bootstrap_expires_at=time.time() + 600,
        subject_digest_key=digest_key,
    )
    identity = authority.bootstrap(
        bootstrap, old_root_public, recovery_code=recovery,
    )
    identity_id = identity["identity_id"]
    owner = "operator:" + identity_id
    devices = DeviceAuthority(
        device_db, enrollment_code="concurrent-enrollment-" + "e" * 40,
    )
    devices.enroll(
        devices.enrollment_code, old_device_public, owner_subject=owner,
    )
    _, binding_payload = authority.device_binding_payload(
        old_device_public, key_version=1,
    )
    authority.bind_primary_device(
        identity_id, old_device_public, sign(old_root, binding_payload),
        expected_key_version=1,
    )
    challenge = authority.create_operator_recovery_challenge(
        recovery, new_root_public, new_device_public, rotated,
    )
    payload = base64.urlsafe_b64decode(
        challenge["signing_payload"] + "=" * (-len(challenge["signing_payload"]) % 4)
    )
    root_signature = new_root.sign(
        b"IAO-OPERATOR-RECOVERY-V1\x00" + payload,
        ec.ECDSA(hashes.SHA256()),
    )
    device_signature = new_device.sign(
        b"IAO-OPERATOR-RECOVERY-DEVICE-V1\x00" + payload,
        ec.ECDSA(hashes.SHA256()),
    )

    # Distinct objects model separate API worker processes, not a shared
    # in-process threading lock. Both target the same durable SQLite files.
    workers = [
        OperatorIdentityAuthority(identity_db, subject_digest_key=digest_key),
        OperatorIdentityAuthority(identity_db, subject_digest_key=digest_key),
    ]
    device_workers = [
        DeviceAuthority(device_db, enrollment_code=""),
        DeviceAuthority(device_db, enrollment_code=""),
    ]
    gate = Barrier(2)
    replacement_calls = []
    calls_lock = Lock()

    def attempt(index):
        def replace(public, subject, old=None):
            with calls_lock:
                replacement_calls.append((public, subject))
            return device_workers[index].replace_active_device_for_recovery(
                public, owner_subject=subject, expected_old_public_key_pem=old,
            )

        gate.wait(timeout=10)
        try:
            result = workers[index].complete_operator_recovery(
                challenge["challenge"], root_signature, device_signature,
                device_replacement=replace,
            )
            return ("committed", result["key_version"])
        except OperatorIdentityError as exc:
            return ("rejected", exc.code)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(attempt, range(2)))

    assert sorted(outcomes) == [
        ("committed", 2),
        ("rejected", "OPERATOR_RECOVERY_REPLAYED"),
    ]
    assert replacement_calls == [(new_device_public, owner)]
    assert workers[0].primary_device_public_key() == new_device_public
    assert devices.verify_registered_public_key(
        new_device_public, owner_subject=owner,
    )
    with workers[0]._database() as db:
        identities = db.execute(
            "SELECT status,key_version,recovery_code_digest FROM operator_identities"
        ).fetchall()
        bindings = db.execute(
            "SELECT device_public_key_pem,key_version FROM primary_device_bindings"
        ).fetchall()
        consumed = db.execute(
            "SELECT consumed_at FROM operator_recovery_challenges WHERE challenge_digest=?",
            (workers[0]._digest(challenge["challenge"]),),
        ).fetchone()
    assert len(identities) == 1
    assert identities[0]["status"] == "ACTIVE"
    assert identities[0]["key_version"] == 2
    assert identities[0]["recovery_code_digest"] == workers[0]._recovery_digest(rotated)
    assert len(bindings) == 1
    assert bindings[0]["device_public_key_pem"] == new_device_public
    assert bindings[0]["key_version"] == 2
    assert consumed["consumed_at"] is not None
    with devices._database() as db:
        active = db.execute(
            "SELECT public_key_pem,owner_subject FROM devices WHERE active=1"
        ).fetchall()
    assert len(active) == 1
    assert active[0]["public_key_pem"] == new_device_public
    assert active[0]["owner_subject"] == owner

def test_recovery_rolls_back_identity_when_device_authority_fails_before_commit(tmp_path):
    bootstrap = "device-failure-bootstrap-" + "b" * 40
    recovery = "device-failure-recovery-" + "r" * 48
    rotated = "device-failure-rotated-" + "n" * 48
    authority = OperatorIdentityAuthority(
        tmp_path / "device-failure-identity.sqlite3", bootstrap,
        bootstrap_expires_at=time.time() + 600,
        subject_digest_key=b"device-failure-digest-key-" + b"k" * 32,
    )
    old_root, old_root_public = keypair()
    new_root, new_root_public = keypair()
    new_device, new_device_public = keypair()
    identity = authority.bootstrap(
        bootstrap, old_root_public, recovery_code=recovery,
    )
    challenge = authority.create_operator_recovery_challenge(
        recovery, new_root_public, new_device_public, rotated,
    )
    payload = base64.urlsafe_b64decode(
        challenge["signing_payload"] + "=" * (-len(challenge["signing_payload"]) % 4)
    )
    root_signature = new_root.sign(
        b"IAO-OPERATOR-RECOVERY-V1\x00" + payload,
        ec.ECDSA(hashes.SHA256()),
    )
    device_signature = new_device.sign(
        b"IAO-OPERATOR-RECOVERY-DEVICE-V1\x00" + payload,
        ec.ECDSA(hashes.SHA256()),
    )

    def unavailable_device_authority(*args):
        raise RuntimeError("injected_device_authority_failure")

    with pytest.raises(RuntimeError, match="injected_device_authority_failure"):
        authority.complete_operator_recovery(
            challenge["challenge"], root_signature, device_signature,
            device_replacement=unavailable_device_authority,
        )

    assert authority.verify_root_signature(
        identity["identity_id"], b"old-root-still-active",
        sign(old_root, b"old-root-still-active"), expected_key_version=1,
    )
    assert authority.primary_device_public_key() is None
    with authority._database() as db:
        row = db.execute(
            "SELECT key_version,recovery_code_digest FROM operator_identities"
        ).fetchone()
        consumed = db.execute(
            "SELECT consumed_at FROM operator_recovery_challenges WHERE challenge_digest=?",
            (authority._digest(challenge["challenge"]),),
        ).fetchone()
    assert row["key_version"] == 1
    assert row["recovery_code_digest"] == authority._recovery_digest(recovery)
    assert consumed["consumed_at"] is None

    result = authority.complete_operator_recovery(
        challenge["challenge"], root_signature, device_signature,
        device_replacement=lambda public, subject, old=None: None,
    )
    assert result["key_version"] == 2
    assert authority.verify_root_signature(
        identity["identity_id"], b"new-root-active",
        sign(new_root, b"new-root-active"), expected_key_version=2,
    )

