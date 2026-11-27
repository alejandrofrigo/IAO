from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from tools.iao_termux_agent_preflight import run, validate_base


class FakeResponse:
    def __init__(self, status: int, payload: dict) -> None:
        self.status = status
        self.data = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit: int) -> bytes:
        return self.data


class FakeOpener:
    def __init__(self, responses: list[FakeResponse]) -> None:
        self.responses = iter(responses)
        self.paths: list[str] = []

    def open(self, request, timeout=0):
        self.paths.append(request.full_url)
        return next(self.responses)


class TermuxAgentPreflightTests(unittest.TestCase):
    def test_accepts_only_https_origin_without_path_or_credentials(self) -> None:
        self.assertEqual(
            validate_base("https://iao.example.net/"),
            "https://iao.example.net",
        )
        for value in (
            "http://iao.example.net",
            "https://user:pass@iao.example.net",
            "https://iao.example.net/path",
            "https://iao.example.net:8443",
            "https://localhost",
            "https://127.0.0.1",
            "https://iao.example.net?token=secret",
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_base(value)

    @patch("tools.iao_termux_agent_preflight.urllib.request.build_opener")
    def test_reports_preflight_only_when_agent_polling_is_disabled(self, build_opener) -> None:
        opener = FakeOpener([
            FakeResponse(200, {"status": "live"}),
            FakeResponse(503, {"status": "degraded"}),
            FakeResponse(200, {
                "protocol": "IAO-CLOUDFLARE-GATEWAY-V1",
                "mode": "fixed_origin_api_proxy",
                "agent_polling": "disabled",
                "privileged_commands": "disabled",
            }),
        ])
        build_opener.return_value = opener
        code, report = run("https://iao.example.net")
        self.assertEqual(code, 2)
        self.assertEqual(report["decision"], "BLOCKED_AGENT_PROTOCOL_NOT_ENABLED")
        self.assertFalse(report["agent_connected"])
        self.assertFalse(report["remote_execution_enabled"])
        self.assertEqual(len(opener.paths), 3)

    @patch("tools.iao_termux_agent_preflight.urllib.request.build_opener")
    def test_unknown_contract_fails_closed(self, build_opener) -> None:
        build_opener.return_value = FakeOpener([
            FakeResponse(200, {"status": "live"}),
            FakeResponse(503, {"status": "degraded"}),
            FakeResponse(200, {"protocol": "unknown"}),
        ])
        code, report = run("https://iao.example.net")
        self.assertEqual(code, 2)
        self.assertEqual(report["decision"], "BLOCKED_UNKNOWN_GATEWAY_CONTRACT")

    @patch("tools.iao_termux_agent_preflight.urllib.request.build_opener")
    def test_never_claims_connected_even_if_contract_says_enabled(self, build_opener) -> None:
        build_opener.return_value = FakeOpener([
            FakeResponse(200, {"status": "live"}),
            FakeResponse(200, {"status": "normal"}),
            FakeResponse(200, {
                "protocol": "IAO-CLOUDFLARE-GATEWAY-V1",
                "agent_polling": "enabled",
                "privileged_commands": "disabled",
            }),
        ])
        code, report = run("https://iao.example.net")
        self.assertEqual(code, 2)
        self.assertEqual(report["decision"], "PREFLIGHT_ONLY_AGENT_NOT_IMPLEMENTED")
        self.assertFalse(report["agent_connected"])
        self.assertFalse(report["remote_execution_enabled"])


if __name__ == "__main__":
    unittest.main()
