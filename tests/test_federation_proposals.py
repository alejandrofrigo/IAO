import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from omega.federation_proposals import (
    PendingProposalStore, create_proposal, verify_proposal,
)
from omega.tools.registry import ToolRegistry, ToolSpec


def registry():
    r = ToolRegistry()
    noop = lambda value: value
    r.register(ToolSpec(
        "knowledge.search", "1.0.0", "knowledge.search",
        "READ_ONLY", 5.0, noop, noop, lambda value: "PASS",
    ))
    r.register(ToolSpec(
        "danger.write", "1.0.0", "danger.write",
        "CHANGE_REVERSIBLE", 5.0, noop, noop, lambda value: "PASS",
    ))
    return r


class ProposalTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_000_000.0
        self.key = Ed25519PrivateKey.generate()
        self.reg = registry()
        self.served = frozenset({"knowledge.search"})

    def proposal(self, **kwargs):
        return create_proposal(
            self.key, ["knowledge.search"], now=self.now, **kwargs
        )

    def test_valid_proposal_is_verified_but_not_enrolled(self):
        p = self.proposal()
        result = verify_proposal(p, self.reg, self.served, now=self.now)
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "PENDING")
        self.assertEqual(
            result["contract"]["capabilities"], ["knowledge.search"]
        )

    def test_tampered_capability_invalidates_signature(self):
        p = self.proposal()
        p["contract"]["capabilities"] = ["danger.write"]
        result = verify_proposal(p, self.reg, self.served, now=self.now)
        self.assertFalse(result["ok"])

    def test_expired_proposal_rejected(self):
        p = self.proposal(ttl_seconds=10)
        result = verify_proposal(
            p, self.reg, self.served, now=self.now + 11
        )
        self.assertEqual(
            result["error"], "PROPOSAL_EXPIRED_OR_INVALID_TTL"
        )

    def test_clock_skew_rejected(self):
        p = self.proposal()
        result = verify_proposal(
            p, self.reg, self.served, now=self.now + 61
        )
        self.assertEqual(result["error"], "PROPOSAL_CLOCK_SKEW")

    def test_non_read_only_capability_rejected(self):
        p = create_proposal(self.key, ["danger.write"], now=self.now)
        result = verify_proposal(
            p, self.reg, {"danger.write"}, now=self.now
        )
        self.assertEqual(result["error"], "CAPABILITY_NOT_READ_ONLY")

    def test_endpoint_must_be_https_and_exact_path(self):
        with self.assertRaises(ValueError):
            self.proposal(
                endpoint="http://example.com/fed/v1/message"
            )
        with self.assertRaises(ValueError):
            self.proposal(endpoint="https://example.com/other")

    def test_pending_store_persists_and_rejects_duplicate(self):
        p = self.proposal()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "pending.json"
            store = PendingProposalStore(path, self.reg, self.served, now=self.now)
            first = store.submit(
                p, self.reg, self.served, now=self.now
            )
            self.assertTrue(first["ok"])
            self.assertEqual(first["status"], "PENDING")
            second = store.submit(
                p, self.reg, self.served, now=self.now
            )
            self.assertEqual(second["error"], "DUPLICATE_PROPOSAL")
            restored = PendingProposalStore(path, self.reg, self.served, now=self.now)
            self.assertEqual(len(restored.items), 1)
            self.assertEqual(
                next(iter(restored.items.values()))["status"], "PENDING"
            )
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


    def test_reload_reverifies_saved_signature(self):
        p = self.proposal()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "pending.json"
            store = PendingProposalStore(
                path, self.reg, self.served, now=self.now
            )
            self.assertTrue(store.submit(p, now=self.now)["ok"])
            saved = __import__("json").loads(path.read_text())
            saved["proposals"][0]["raw_proposal"]["contract"][
                "capabilities"
            ] = ["danger.write"]
            path.write_text(__import__("json").dumps(saved))
            with self.assertRaisesRegex(
                RuntimeError, "PROPOSAL_STORE_INVALID_FAIL_CLOSED"
            ):
                PendingProposalStore(
                    path, self.reg, self.served, now=self.now
                )

    def test_duplicate_json_keys_rejected(self):
        raw = '{"protocol":"wrong","protocol":"iao-federation-proposal"}'
        result = verify_proposal(
            raw, self.reg, self.served, now=self.now
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "INVALID_PROPOSAL")

    def test_store_version_two_and_original_signature_persisted(self):
        p = self.proposal()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "pending.json"
            store = PendingProposalStore(
                path, self.reg, self.served, now=self.now
            )
            self.assertTrue(store.submit(p, now=self.now)["ok"])
            saved = __import__("json").loads(path.read_text())
            self.assertEqual(saved["version"], 2)
            self.assertIn("sig", saved["proposals"][0]["raw_proposal"])
            restored = PendingProposalStore(
                path, self.reg, self.served, now=self.now
            )
            self.assertEqual(len(restored.items), 1)


if __name__ == "__main__":
    unittest.main()
