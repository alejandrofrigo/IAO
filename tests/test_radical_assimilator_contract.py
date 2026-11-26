import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from omega.radical_assimilator import RadicalAssimilator


class RadicalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.state = root / "state.json"
        self.integrations = root / "integrations.json"
        self.worker = RadicalAssimilator(
            state_file=self.state,
            integrations_file=self.integrations,
        )
        self.worker.registry_urls = []

    def tearDown(self):
        self.tmp.cleanup()

    def test_valid_openapi(self):
        self.assertTrue(self.worker._is_openapi_document({
            "openapi": "3.0.3",
            "info": {"title": "Test API", "version": "1.0"},
            "paths": {"/health": {"get": {}}},
        }))

    def test_rejects_arbitrary_json(self):
        self.assertFalse(self.worker._is_openapi_document({"message": "OK"}))

    def test_rejects_incomplete_contract(self):
        self.assertFalse(self.worker._is_openapi_document({
            "openapi": "3.0.0",
            "info": {"title": "Missing version"},
            "paths": {},
        }))

    def test_rejects_non_https(self):
        self.assertFalse(self.worker._safe_url("http://example.com/api"))
        self.assertFalse(self.worker._safe_url("file:///etc/passwd"))

    def test_persistence(self):
        self.worker.assimilated["https://example.com/openapi.json"] = {
            "status": "openapi_spec_verified"
        }
        self.worker._save_state()
        restored = RadicalAssimilator(
            state_file=self.state,
            integrations_file=self.integrations,
        )
        self.assertIn("https://example.com/openapi.json", restored.assimilated)
        data = json.loads(self.integrations.read_text())
        self.assertEqual(len(data["integrations"]), 1)

    def test_http_200_non_contract_is_not_assimilated(self):
        with patch.object(self.worker, "_fetch_json", return_value={"message": "OK"}):
            self.assertFalse(self.worker._verify_spec("https://example.com/api"))
        self.assertEqual(self.worker.assimilated, {})
        self.assertIn("https://example.com/api", self.worker.candidates)


if __name__ == "__main__":
    unittest.main()
