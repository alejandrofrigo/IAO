#!/usr/bin/env python3
"""Read-only preflight probe for the IAO Cloudflare gateway.

This is deliberately not a task agent: it sends no credentials, signs no
requests, polls no queue, and executes no remote instructions.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        return None


def validate_base(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.port not in (None, 443)
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("INVALID_GATEWAY_URL")
    host = parsed.hostname.lower()
    if host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".local"):
        raise ValueError("INVALID_GATEWAY_URL")
    return "https://" + host


def get_json(opener: urllib.request.OpenerDirector, base: str,
             path: str, timeout: float) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        base + path,
        headers={"Accept": "application/json", "Cache-Control": "no-store"},
        method="GET",
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            status = response.status
            raw = response.read(65537)
    except urllib.error.HTTPError as exc:
        status = exc.code
        raw = exc.read(65537)
    except (urllib.error.URLError, TimeoutError, OSError):
        return 0, {"error": "GATEWAY_UNREACHABLE"}
    if len(raw) > 65536:
        return status, {"error": "RESPONSE_TOO_LARGE"}
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return status, {"error": "INVALID_JSON_RESPONSE"}
    return status, payload if isinstance(payload, dict) else {"error": "INVALID_RESPONSE"}


def run(base_url: str, timeout: float = 8.0) -> tuple[int, dict[str, Any]]:
    base = validate_base(base_url)
    opener = urllib.request.build_opener(NoRedirect())
    live_status, live = get_json(opener, base, "/health/live", timeout)
    ready_status, ready = get_json(opener, base, "/health/ready", timeout)
    contract_status, contract = get_json(opener, base, "/v1/gateway/contract", timeout)

    result = {
        "probe": "IAO-TERMUX-AGENT-PREFLIGHT-V1",
        "gateway": base,
        "liveness": {"http_status": live_status, "status": live.get("status")},
        "readiness": {"http_status": ready_status, "status": ready.get("status")},
        "contract": {
            "http_status": contract_status,
            "protocol": contract.get("protocol"),
            "mode": contract.get("mode"),
            "agent_polling": contract.get("agent_polling"),
            "privileged_commands": contract.get("privileged_commands"),
        },
        "agent_connected": False,
        "remote_execution_enabled": False,
    }
    if live_status != 200 or live.get("status") != "live":
        result["decision"] = "BLOCKED_GATEWAY_LIVENESS"
        return 2, result
    if contract_status != 200 or contract.get("protocol") != "IAO-CLOUDFLARE-GATEWAY-V1":
        result["decision"] = "BLOCKED_UNKNOWN_GATEWAY_CONTRACT"
        return 2, result
    if contract.get("agent_polling") != "enabled":
        result["decision"] = "BLOCKED_AGENT_PROTOCOL_NOT_ENABLED"
        return 2, result
    # This preflight intentionally never transitions to connected/ready.
    result["decision"] = "PREFLIGHT_ONLY_AGENT_NOT_IMPLEMENTED"
    return 2, result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--gateway-url",
        default=os.environ.get("IAO_GATEWAY_URL", ""),
        help="HTTPS gateway origin; may also be set with IAO_GATEWAY_URL",
    )
    parser.add_argument("--timeout", type=float, default=8.0)
    args = parser.parse_args()
    if not args.gateway_url:
        print(json.dumps({"decision": "BLOCKED_GATEWAY_URL_REQUIRED"}, indent=2))
        return 2
    if not 1.0 <= args.timeout <= 30.0:
        print(json.dumps({"decision": "BLOCKED_INVALID_TIMEOUT"}, indent=2))
        return 2
    try:
        code, report = run(args.gateway_url, args.timeout)
    except ValueError as exc:
        code, report = 2, {"decision": str(exc)}
    print(json.dumps(report, sort_keys=True, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
