#!/usr/bin/env python3
"""Read-only local health aggregation for the IAO control plane."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".state"

def command(args, timeout=100):
    try:
        p = subprocess.run(
            args, cwd=ROOT, capture_output=True, text=True,
            timeout=timeout,
            env={**__import__("os").environ, "PYTHONUNBUFFERED": "1"},
        )
        if p.returncode:
            return {"ok": False, "exit_code": p.returncode,
                    "error": (p.stderr or p.stdout)[-1500:]}
        try:
            return {"ok": True, "data": json.loads(p.stdout)}
        except ValueError:
            return {"ok": True, "output": p.stdout[-3000:]}
    except Exception as exc:
        return {"ok": False, "error": type(exc).__name__ + ": " + str(exc)[:300]}

def main():
    autonomy = command([sys.executable, "tools/iao_autonomy.py", "--check"])
    core = command([sys.executable, "tools/iao_autonomous_core.py", "status"])
    continuity_path = STATE / "iao-continuity-status.json"
    continuity = {"ok": False, "status": "NOT_REPORTED"}
    if continuity_path.is_file():
        try:
            data = json.loads(continuity_path.read_text("utf-8"))
            continuity = {
                "ok": data.get("status") == "LOCAL_ONLINE"
                     and data.get("local_http", {}).get("ok") is True,
                "status": data.get("status"),
                "cycle": data.get("cycle"),
                "local_http": data.get("local_http"),
                "configured_nodes": data.get("configured_nodes"),
                "verified_peer_exchanges": data.get("verified_peer_exchanges"),
                "timestamp": data.get("utc"),
            }
        except Exception as exc:
            continuity = {"ok": False, "status": "INVALID_REPORT",
                          "error": type(exc).__name__}
    else:
        continuity["report_path"] = str(continuity_path)

    result = {
        "component": "IAO_LOCAL_SUPERVISION",
        "autonomy_check": autonomy,
        "autonomous_core": core,
        "continuity": continuity,
    }
    checks = [
        autonomy.get("ok") is True
        and autonomy.get("data", {}).get("syntax_ok") is True
        and autonomy.get("data", {}).get("audit_ok") is True,
        core.get("ok") is True,
        continuity.get("ok") is True,
    ]
    result["overall"] = "HEALTHY" if all(checks) else "DEGRADED"
    result["checks_passed"] = sum(bool(x) for x in checks)
    result["checks_total"] = len(checks)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if all(checks) else 1

if __name__ == "__main__":
    raise SystemExit(main())
