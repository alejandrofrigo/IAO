"""Tests for the isolated durable operator root-key registry."""
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
    authority = OperatorIdentityAuthority(db, code)
    enrolled = authority.bootstrap(code, public)
    assert enrolled["key_version"] == 1
    assert authority.verify_root_signature(
        enrolled["identity_id"], b"probe", sign(private, b"probe"),
        expected_key_version=1,
    )
    restarted = OperatorIdentityAuthority(db, code)
    with pytest.raises(OperatorIdentityError, match="OPERATOR_BOOTSTRAP_ALREADY_USED"):
        restarted.bootstrap(code, public)


def test_bootstrap_rejects_invalid_secret_and_non_p256_key(tmp_path):
    code = "bootstrap-secret-" + "x" * 40
    _, public = keypair()
    authority = OperatorIdentityAuthority(tmp_path / "identity.sqlite3", code)
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
    authority = OperatorIdentityAuthority(tmp_path / "identity.sqlite3", code)
    enrolled = authority.bootstrap(code, public)
    second_code = "another-bootstrap-" + "z" * 40
    second_authority = OperatorIdentityAuthority(
        tmp_path / "identity.sqlite3", second_code
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
    authority = OperatorIdentityAuthority(tmp_path / "identity.sqlite3", code)
    enrolled = authority.bootstrap(code, old_public)
    identity_id = enrolled["identity_id"]
    next_version = 2
    canonical_new = serialization.load_pem_public_key(new_public.encode()).public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    import hashlib
    payload = (
        b"rotate-root-v1\\n" + identity_id.encode("ascii") + b"\\n"
        + b"2\\n" + hashlib.sha256(canonical_new.encode("ascii")).hexdigest().encode("ascii")
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
    authority = OperatorIdentityAuthority(db, code)
    enrolled = authority.bootstrap(code, public)
    identity_id = enrolled["identity_id"]
    authority.revoke(
        identity_id, sign(private, b"revoke-root-v1\\n" + identity_id.encode("ascii")),
        expected_key_version=1,
    )
    restarted = OperatorIdentityAuthority(db, code)
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
    enabled = OperatorIdentityAuthority(tmp_path / "enabled.sqlite3", "x" * 40)
    enrolled = enabled.bootstrap("x" * 40, public)
    with pytest.raises(OperatorIdentityError, match="INVALID_ROOT_SIGNED_PAYLOAD"):
        enabled.verify_root_signature(
            enrolled["identity_id"], b"x" * 8193, b"x" * 70,
            expected_key_version=1,
        )
