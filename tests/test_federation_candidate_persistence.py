import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from omega import federation_discovery as discovery


class FederationCandidatePersistenceTests(unittest.TestCase):
    def manifest(self):
        public_key = "11" * 32
        node_id = hashlib.sha256(bytes.fromhex(public_key)).hexdigest()[:16]
        return {
            "protocol": "iao-federation",
            "version": 1,
            "consent": True,
            "node_id": node_id,
            "public_key": public_key,
            "origin": "https://peer.example",
            "capabilities": ["knowledge.search", " " * 2, "x" * 129, 7],
        }

    def test_persist_candidate_creates_untrusted_inventory_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / ".state"
            candidate_id, created = discovery._persist_candidate(
                state, self.manifest(), "owner/repo"
            )
            path = state / "iao-node-network" / "discovered-candidates.json"
            saved = json.loads(path.read_text(encoding="utf-8"))
            candidate = saved["candidates"][candidate_id]
            self.assertTrue(created)
            self.assertEqual(candidate["status"], "DISCOVERED_UNVERIFIED")
            self.assertIs(candidate["identity_verified"], False)
            self.assertIs(candidate["enrolled"], False)
            self.assertEqual(candidate["granted_capabilities"], [])
            self.assertIs(candidate["remote_code_execution"], False)
            self.assertEqual(candidate["requested_capabilities"], ["knowledge.search"])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)

    def test_persist_candidate_is_idempotent_and_preserves_revocation(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / ".state"
            manifest = self.manifest()
            candidate_id, _ = discovery._persist_candidate(state, manifest, "owner/repo")
            path = state / "iao-node-network" / "discovered-candidates.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            data["candidates"][candidate_id].update({
                "status": "REVOKED",
                "granted_capabilities": ["manual.review"],
                "identity_verified": True,
            })
            from omega.federation_autonomous import _write_registry
            _write_registry(path, data)
            same_id, created = discovery._persist_candidate(state, manifest, "owner/repo")
            saved = json.loads(path.read_text(encoding="utf-8"))["candidates"][candidate_id]
            self.assertEqual(same_id, candidate_id)
            self.assertFalse(created)
            self.assertEqual(saved["status"], "REVOKED")
            self.assertEqual(saved["granted_capabilities"], ["manual.review"])
            self.assertIs(saved["identity_verified"], True)

    def test_persist_candidate_rejects_symlink_registry_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / ".state"
            outside = root / "outside"
            outside.mkdir()
            target = state / "iao-node-network"
            target.parent.mkdir()
            try:
                target.symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            with self.assertRaisesRegex(RuntimeError, "PARENT_REFUSED"):
                discovery._persist_candidate(state, self.manifest(), "owner/repo")
            self.assertEqual(list(outside.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
