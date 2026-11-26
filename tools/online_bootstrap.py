"""Runs ONLY when egress works. Verifies DNS+TLS from IAO's own probe first; if blocked it
stops with BLOCKED_NETWORK (it never tries to bypass the gateway). Then: venv -> pinned install ->
ruff -> mypy -> pytest -> offline suite -> runtime evidence. Writes artifacts/online-bootstrap.json."""
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from omega.net import probe_https  # noqa: E402

HOSTS = ["pypi.org", "files.pythonhosted.org"]
STEPS = [
    ("create-venv", [sys.executable, "-m", "venv", ".venv"]),
    ("install-pinned", [".venv/bin/python", "-m", "pip", "install", "-e", ".[dev]"]),
    ("ruff", [".venv/bin/ruff", "check", "."]),
    ("mypy-strict", [".venv/bin/mypy", "apps", "omega"]),
    ("pytest", [".venv/bin/pytest", "-q"]),
    ("runtime-evidence", [".venv/bin/python", "tools/run_runtime.py"]),
]


def main() -> int:
    out: dict = {"timestamp": datetime.now(timezone.utc).isoformat(), "probes": [], "steps": []}  # type: ignore[type-arg]
    out["probes"] = [probe_https(h, timeout=8) for h in HOSTS]
    if not all(p["verdict"] == "DIRECT_INTERNET_CONNECTED" for p in out["probes"]):
        out["state"] = "BLOCKED_NETWORK"
        out["action_required"] = "Enable network access for this sandbox (allow pypi.org, files.pythonhosted.org), then rerun."
    else:
        out["state"] = "RUNNING"
        for name, cmd in STEPS:
            r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
            out["steps"].append({"step": name, "exit": r.returncode, "tail": (r.stdout + r.stderr)[-600:]})
            if r.returncode:
                out["state"] = f"FAILED_AT_{name}"
                break
        else:
            out["state"] = "ONLINE_VERIFIED"
    (ROOT / "artifacts" / "online-bootstrap.json").write_text(json.dumps(out, indent=2))
    print(out["state"], "-", out.get("action_required", ""))
    return 0 if out["state"] == "ONLINE_VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
