"""Runtime integration tests for fail-closed identity rollback anchoring."""
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from omega.server import build_service
from omega.identity_rollback_anchor import (
    IdentityRollbackAnchorError,
    capture_identity_state,
)

KEY = "rollback-integration-token-key-0123456789"
CORPUS = Path(__file__).resolve().parent.parent / "docs" / "corpus"


class RollbackAnchorRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state_dir = self.root / "runtime-state"
        self.trust_dir = self.root / "trust-anchor"
        self.env = patch.dict(os.environ, {
            "AUDIT_HMAC_KEY": "rollback-integration-audit-key-" + "a" * 40,
            "IAO_IDENTITY_ROLLBACK_DIR": str(self.trust_dir),
        })
        self.env.start()
        self.service = build_service(
            self.state_dir, KEY, CORPUS,
            identity_rollback_anchor_enabled=True,
        )

    def tearDown(self):
        self.service.store.close()
        self.env.stop()
        self.tmp.cleanup()

    def test_protected_api_runs_under_anchor_and_keeps_sequence_for_noop(self):
        status, payload = self.service.handle(
            "POST", "/v1/operator/recovery/challenge", {}, b"{}"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "INVALID_OPERATOR_RECOVERY")
        state = capture_identity_state(
            self.service.operator_identity_authority.database,
            self.service.device_authority.database,
        )
        self.assertEqual(
            self.service.identity_rollback_anchor.verify(state),
            {"valid": True, "sequence": 1},
        )

    def test_write_ahead_transition_advances_anchor_after_database_change(self):
        authority = self.service.operator_identity_authority
        public = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

        def mutate():
            with sqlite3.connect(authority.database) as db:
                db.execute(
                    """INSERT INTO operator_identities
                    (identity_id,root_public_key_pem,key_version,status,created_at,updated_at)
                    VALUES(?, ?, 1, 'REVOKED', 1, 1)""",
                    ("b" * 32, public),
                )
            return "committed"

        result = self.service.identity_rollback_anchor.execute(
            self.service.identity_state_supplier, mutate,
        )
        self.assertEqual(result, "committed")
        current = capture_identity_state(
            authority.database, self.service.device_authority.database,
        )
        self.assertEqual(
            self.service.identity_rollback_anchor.verify(current),
            {"valid": True, "sequence": 2},
        )

    def test_live_database_divergence_blocks_protected_api_before_route(self):
        public = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        with sqlite3.connect(self.service.operator_identity_authority.database) as db:
            db.execute(
                """INSERT INTO operator_identities
                (identity_id,root_public_key_pem,key_version,status,created_at,updated_at)
                VALUES(?, ?, 1, 'REVOKED', 1, 1)""",
                ("a" * 32, public),
            )
        status, payload = self.service.handle(
            "POST", "/v1/operator/recovery/challenge", {}, b"{}"
        )
        self.assertEqual(status, 503)
        self.assertEqual(payload["error"], "IDENTITY_ROLLBACK_ANCHOR_BLOCKED")

    def test_pending_transition_blocks_until_explicit_reconciliation(self):
        anchor = self.service.identity_rollback_anchor
        state = capture_identity_state(
            self.service.operator_identity_authority.database,
            self.service.device_authority.database,
        )
        anchor.pending_path.write_text("interrupted", encoding="ascii")
        with self.assertRaises(IdentityRollbackAnchorError):
            anchor.verify(state)
        status, payload = self.service.handle("POST", "/v1/operator/recovery/challenge", {}, b"{}")
        self.assertEqual((status, payload["error"]), (503, "IDENTITY_ROLLBACK_ANCHOR_BLOCKED"))
