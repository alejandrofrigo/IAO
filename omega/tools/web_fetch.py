"""web.fetch v1.0.0 - READ_ONLY. Only reachable through omega.egress; registered only when an
allowlist is configured. Fetched content is untrusted data and never alters policy."""
import hashlib
from typing import Any

from omega.egress import EgressDenied, EgressPolicy, fetch
from omega.tools.registry import ToolSpec


def make_web_fetch(pol: EgressPolicy) -> ToolSpec:
    def validate(raw: Any) -> dict[str, Any]:
        if not isinstance(raw, dict) or set(raw) != {"url"} or not isinstance(raw["url"], str):
            raise ValueError("INVALID_INPUT")
        return {"url": raw["url"]}

    def run(inp: dict[str, Any]) -> dict[str, Any]:
        try:
            r = fetch(inp["url"], pol)
        except EgressDenied as e:
            return {"tool": "web.fetch", "tool_version": "1.0.0", "status": "DENIED", "error": e.code}
        return {"tool": "web.fetch", "tool_version": "1.0.0", "status": "SUCCEEDED", **r}

    def verify(out: Any) -> str:
        try:
            if out.get("status") == "DENIED":
                return "PASS" if isinstance(out.get("error"), str) else "FAIL"  # a denial is a correct, verifiable outcome
            ok = out["sha256"] == "sha256:" + hashlib.sha256(out["body"].encode()).hexdigest() or out["body"].endswith("\ufffd")
            return "PASS" if ok and out["untrusted"] is True and out["status"] == 200 else "FAIL"
        except (KeyError, AttributeError, TypeError):
            return "FAIL"

    return ToolSpec("web.fetch", "1.0.0", "web.fetch", "READ_ONLY", pol.total_timeout + 2, validate, run, verify)
