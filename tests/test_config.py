import unittest

from omega.config import load_settings


class ConfigTests(unittest.TestCase):
    def test_defaults(self) -> None:
        s = load_settings({})
        self.assertEqual((s.app_env, s.port, s.model_adapter), ("development", 8080, "disabled"))

    def test_rejects_bad_env(self) -> None:
        with self.assertRaises(ValueError):
            load_settings({"APP_ENV": "prod-ish"})

    def test_rejects_bad_port(self) -> None:
        with self.assertRaises(ValueError):
            load_settings({"PORT": "99999"})
