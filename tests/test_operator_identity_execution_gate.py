from __future__ import annotations

import threading
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from omega.operator_identity import OperatorIdentityAuthority, OperatorIdentityError


def test_execution_permit_serializes_cross_connection_root_revocation(tmp_path):
    database = tmp_path / "operator-identity.db"
    subject_key = b"operator-execution-gate-test-key-32-bytes"
    authority = OperatorIdentityAuthority(
        database, subject_digest_key=subject_key,
    )
    root_private = ec.generate_private_key(ec.SECP256R1())
    root_public_pem = root_private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    identity_id = "a" * 32
    owner = "operator:execution-gate-test"
    session_digest = "b" * 64
    device_id = "c" * 64
    subject_digest = authority._session_subject_digest(owner)

    with authority._database() as db:
        db.execute(
            """INSERT INTO operator_identities
            (identity_id,root_public_key_pem,key_version,status,created_at,updated_at)
            VALUES(?,?,1,'ACTIVE',?,?)""",
            (identity_id, root_public_pem, time.time(), time.time()),
        )
        db.execute(
            """INSERT INTO primary_device_bindings
            (identity_id,device_id,device_public_key_pem,key_version,bound_at)
            VALUES(?,?,?,?,?)""",
            (identity_id, device_id, "test-public-device-key", 1, time.time()),
        )
        db.execute(
            """INSERT INTO operator_session_bindings
            (identity_id,subject_digest,session_digest,key_version,bound_at)
            VALUES(?,?,?,?,?)""",
            (identity_id, subject_digest, session_digest, 1, time.time()),
        )

    permit_entered = threading.Event()
    release_permit = threading.Event()
    revoke_started = threading.Event()
    revoke_done = threading.Event()
    failures: list[BaseException] = []

    def execute_under_permit():
        try:
            with authority.authorize_tool_execution(
                owner, session_digest, device_id,
            ):
                permit_entered.set()
                if not release_permit.wait(5):
                    raise AssertionError("permit release timed out")
        except BaseException as exc:
            failures.append(exc)

    def revoke_root():
        revoke_started.set()
        try:
            payload = b"revoke-root-v1\n" + identity_id.encode("ascii")
            signature = root_private.sign(payload, ec.ECDSA(hashes.SHA256()))
            authority.revoke(
                identity_id, signature, expected_key_version=1,
            )
        except BaseException as exc:
            failures.append(exc)
        finally:
            revoke_done.set()

    execution_thread = threading.Thread(target=execute_under_permit)
    execution_thread.start()
    assert permit_entered.wait(2), "execution permit was not acquired"

    revocation_thread = threading.Thread(target=revoke_root)
    revocation_thread.start()
    assert revoke_started.wait(2), "revocation thread did not start"
    # Revocation uses a separate SQLite connection and must wait for the
    # execution transaction rather than committing during an active call.
    assert not revoke_done.wait(0.2)

    release_permit.set()
    execution_thread.join(3)
    revocation_thread.join(3)
    assert not execution_thread.is_alive()
    assert not revocation_thread.is_alive()
    assert failures == []
    assert revoke_done.is_set()

    with pytest.raises(OperatorIdentityError):
        with authority.authorize_tool_execution(owner, session_digest, device_id):
            pytest.fail("revoked operator must never receive a new execution permit")
