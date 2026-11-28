import unittest
from unittest.mock import patch

from omega.federation_autojoin import _get_contract


class FederationAutojoinTransportTests(unittest.TestCase):
    @patch("omega.federation_autojoin.fetch_public_json")
    def test_contract_fetch_uses_pinned_public_https_transport(self, fetch):
        fetch.return_value = {"peer_id": "0123456789abcdef"}
        result = _get_contract("https://peer.example")
        self.assertEqual(result, {"peer_id": "0123456789abcdef"})
        fetch.assert_called_once_with(
            "https://peer.example/fed/v1/contract",
            timeout=12.0,
            max_bytes=65536,
        )

    @patch("omega.federation_autojoin.fetch_public_json")
    def test_non_object_contract_is_rejected(self, fetch):
        fetch.return_value = ["not", "an", "object"]
        with self.assertRaisesRegex(ValueError, "CONTRACT_NOT_OBJECT"):
            _get_contract("https://peer.example")


if __name__ == "__main__":
    unittest.main()
