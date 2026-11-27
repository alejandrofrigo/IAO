import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from omega.server import build_service


class StdlibRuntimePersistentKeyTests(unittest.TestCase):
    def test_build_service_rejects_short_auth_key_before_store_creation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch("omega.server._load_persistent_audit_key", return_value="b" * 32), patch(
                "omega.server.Store"
            ) as store:
                with self.assertRaisesRegex(RuntimeError, "PERSISTENT_AUTH_KEY_INVALID"):
                    build_service(Path(directory), "short", Path(directory) / "corpus")
                store.assert_not_called()

    def test_build_service_rejects_reused_auth_and_audit_keys(self) -> None:
        key = "distinct-material-required-" * 2
        with tempfile.TemporaryDirectory() as directory:
            with patch("omega.server._load_persistent_audit_key", return_value=key), patch(
                "omega.server.Store"
            ) as store:
                with self.assertRaisesRegex(RuntimeError, "PERSISTENT_KEYS_MUST_BE_DISTINCT"):
                    build_service(Path(directory), key, Path(directory) / "corpus")
                store.assert_not_called()

    def test_build_service_rejects_padded_audit_key_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            key_path = home / ".config" / "iao" / "audit-hmac-key"
            key_path.parent.mkdir(parents=True)
            key_path.write_text(" " + "b" * 32 + "\\n", encoding="utf-8")
            with patch("omega.server.Path.home", return_value=home), patch(
                "omega.server.Store"
            ) as store:
                with self.assertRaisesRegex(RuntimeError, "PERSISTENT_KEYS_INVALID_FORMAT"):
                    build_service(home / "state", "a" * 32, home / "corpus")
                store.assert_not_called()


if __name__ == "__main__":
    unittest.main()
