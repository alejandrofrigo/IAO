import unittest

from omega.config import load_settings


class ConfigTests(unittest.TestCase):
    def test_defaults(self) -> None:
        s = load_settings({})
        self.assertEqual((s.app_env, s.port, s.model_adapter), ("development", 8080, "disabled"))
        self.assertEqual(s.host, "127.0.0.1")
        self.assertEqual(s.public_base_url, "http://localhost:8080")

    def test_rejects_bad_env(self) -> None:
        with self.assertRaisesRegex(ValueError, "APP_ENV"):
            load_settings({"APP_ENV": "prod-ish"})

    def test_rejects_bad_port(self) -> None:
        for value in ("0", "65536", "not-a-port"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                load_settings({"PORT": value})

    def test_rejects_empty_or_whitespace_host(self) -> None:
        for value in ("", " localhost", "localhost "):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "HOST"):
                load_settings({"HOST": value})

    def test_rejects_unknown_adapter(self) -> None:
        with self.assertRaisesRegex(ValueError, "MODEL_ADAPTER"):
            load_settings({"MODEL_ADAPTER": "unlisted"})

    def test_rejects_mismatched_adapter_and_provider(self) -> None:
        with self.assertRaisesRegex(ValueError, "must match"):
            load_settings({"MODEL_ADAPTER": "groq", "MODEL_PROVIDER": "gemini"})

    def test_accepts_supported_http_and_https_urls(self) -> None:
        self.assertEqual(
            load_settings({"PUBLIC_BASE_URL": "https://iao.example:8443/api/"}).public_base_url,
            "https://iao.example:8443/api",
        )
        self.assertEqual(
            load_settings({"PUBLIC_BASE_URL": "http://127.0.0.1:8080"}).public_base_url,
            "http://127.0.0.1:8080",
        )

    def test_rejects_unsafe_or_malformed_public_urls(self) -> None:
        values = (
            "",
            " ftp://iao.example ",
            "ftp://iao.example",
            "https:///missing-host",
            "https://user:secret@iao.example",
            "https://iao.example:99999",
            "https://iao.example/path?token=secret",
            "https://iao.example/path#fragment",
        )
        for value in values:
            with self.subTest(value=value), self.assertRaises(ValueError):
                load_settings({"PUBLIC_BASE_URL": value})

    def test_settings_repr_does_not_include_other_configuration(self) -> None:
        settings = load_settings({
            "HOST": "internal.example",
            "PUBLIC_BASE_URL": "https://internal.example",
        })
        rendered = repr(settings)
        self.assertNotIn("internal.example", rendered)
