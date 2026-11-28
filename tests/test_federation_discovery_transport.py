import base64
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from omega import federation_discovery as discovery


class FederationDiscoveryTransportTests(unittest.TestCase):
    def test_manifest_rejects_node_id_not_matching_public_key(self):
        public_key = "11" * 32
        manifest = {
            "protocol": "iao-federation",
            "version": 1,
            "consent": True,
            "node_id": "0123456789abcdef",
            "public_key": public_key,
            "origin": "https://peer.example",
        }
        self.assertEqual(
            discovery._valid_manifest(manifest),
            (False, "NODE_ID_PUBLIC_KEY_MISMATCH"),
        )

    def test_manifest_accepts_matching_public_key_fingerprint(self):
        public_key = "11" * 32
        node_id = hashlib.sha256(bytes.fromhex(public_key)).hexdigest()[:16]
        manifest = {
            "protocol": "iao-federation",
            "version": 1,
            "consent": True,
            "node_id": node_id,
            "public_key": public_key,
            "origin": "https://peer.example",
        }
        self.assertEqual(
            discovery._valid_manifest(manifest),
            (True, "MANIFEST_UNVERIFIED"),
        )

    def test_discovery_audit_rejects_symlink_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "state"
            state.mkdir()
            outside = Path(tmp) / "outside.jsonl"
            outside.write_text("keep", encoding="utf-8")
            link = state / "federation-discovery.jsonl"
            try:
                link.symlink_to(outside)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            with self.assertRaisesRegex(RuntimeError, "AUDIT_FILE_REFUSED"):
                discovery._append(state, {"event": "TEST"})
            self.assertEqual(outside.read_text(encoding="utf-8"), "keep")

    def test_discovery_audit_rejects_symlink_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            outside = Path(tmp) / "outside"
            outside.mkdir()
            link = Path(tmp) / "linked-state"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            with self.assertRaisesRegex(RuntimeError, "DIRECTORY_REFUSED"):
                discovery._append(link / "nested", {"event": "TEST"})
            self.assertEqual(list(outside.iterdir()), [])

    @patch("omega.federation_discovery._request_json")
    def test_discovery_cycle_runs_candidate_audit_without_remote_enrollment(self, request):
        request.return_value = {"items": []}
        public_key = "11" * 32
        node_id = hashlib.sha256(bytes.fromhex(public_key)).hexdigest()[:16]
        manifest = {
            "node_id": node_id,
            "public_key": public_key,
            "origin": "https://peer.example",
        }
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / ".state"
            candidate_id, created = discovery._persist_candidate(
                state, manifest, "owner/repo"
            )
            self.assertTrue(created)

            totals = discovery.discover_once(state)

            registry = json.loads(
                (state / "iao-node-network" / "discovered-candidates.json").read_text()
            )
            candidate = registry["candidates"][candidate_id]
            self.assertEqual(totals["candidate_evaluation"]["checked"], 1)
            self.assertEqual(totals["candidate_evaluation"]["enrolled"], 0)
            self.assertEqual(candidate["status"], "DISCOVERED_UNVERIFIED")
            self.assertFalse(candidate["identity_verified"])
            self.assertEqual(
                candidate["last_federation_error"], "RuntimeError"
            )
            audit = (state / "federation-autonomous.jsonl").read_text()
            self.assertIn("FEDERATION_AUTOJOIN_CYCLE", audit)
            discovery_audit = (state / "federation-discovery.jsonl").read_text()
            self.assertIn("CANDIDATE_EVALUATION_FINISHED", discovery_audit)

    @patch("omega.federation_discovery.fetch_public_json")
    def test_search_json_uses_pinned_transport(self, fetch):
        fetch.return_value = {"items": []}
        result = discovery._request_json(
            "https://api.github.com/search/repositories?q=iao"
        )
        self.assertEqual(result, {"items": []})
        fetch.assert_called_once_with(
            "https://api.github.com/search/repositories?q=iao",
            timeout=12.0,
            max_bytes=1024 * 1024,
        )

    @patch("omega.federation_discovery._request_json")
    def test_manifest_uses_github_contents_json_and_decodes_base64(self, request):
        manifest = {
            "protocol": "iao-federation",
            "version": 1,
            "node_id": "0123456789abcdef",
        }
        encoded = base64.b64encode(
            json.dumps(manifest).encode("utf-8")
        ).decode("ascii")
        wrapped = encoded[:20] + "\n" + encoded[20:]
        request.return_value = {"encoding": "base64", "content": wrapped}

        result = discovery._request_manifest(
            "owner/repo", "main", ".well-known/iao-federation.json"
        )

        self.assertEqual(result, manifest)
        request.assert_called_once_with(
            "https://api.github.com/repos/owner/repo/contents/"
            ".well-known/iao-federation.json?ref=main"
        )

    @patch("omega.federation_discovery._request_json")
    def test_manifest_rejects_invalid_contents_payload(self, request):
        request.return_value = {"encoding": "utf-8", "content": "{}"}
        with self.assertRaisesRegex(ValueError, "INVALID_GITHUB_CONTENTS_RESPONSE"):
            discovery._request_manifest("owner/repo", "main", "manifest.json")

    @patch("omega.federation_discovery._request_json")
    def test_manifest_rejects_invalid_base64(self, request):
        request.return_value = {"encoding": "base64", "content": "%%%"}
        with self.assertRaisesRegex(ValueError, "INVALID_FEDERATION_MANIFEST"):
            discovery._request_manifest("owner/repo", "main", "manifest.json")


if __name__ == "__main__":
    unittest.main()
