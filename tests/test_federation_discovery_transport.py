import base64
import json
import unittest
from unittest.mock import patch

from omega import federation_discovery as discovery


class FederationDiscoveryTransportTests(unittest.TestCase):
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
        request.return_value = {"encoding": "base64", "content": encoded[:20] + "\\n" + encoded[20:]}

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
