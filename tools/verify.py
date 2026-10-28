"""Offline-capable verifier: runs tests, probes network from IAO's own process,
writes hashed evidence to artifacts/. Never reports success it did not observe."""
import hashlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "artifacts"
sys.path.insert(0, str(ROOT))
from omega.net import probe_https  # noqa: E402

PROBE_TARGETS = ["pypi.org", "example.com"]


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main() -> int:
    ART.mkdir(exist_ok=True)
    now = datetime.now(timezone.utc).isoformat()
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip() or "no-commit"

    cmd = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v"]
    t = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    (ART / "test-results.txt").write_text(f"$ {' '.join(cmd)}\nexit={t.returncode}\n\n{t.stdout}\n{t.stderr}")

    probes = [probe_https(h, timeout=5) for h in PROBE_TARGETS]
    net_state = "DIRECT_INTERNET_CONNECTED" if any(p["verdict"] == "DIRECT_INTERNET_CONNECTED" for p in probes) else "BLOCKED_NETWORK"
    (ART / "network-connectivity.json").write_text(json.dumps({"timestamp": now, "origin": "omega.net.probe_https (IAO process)", "state": net_state, "probes": probes}, indent=2))

    files = sorted(p for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.parts and "__pycache__" not in p.parts and "artifacts" not in p.parts and ".state" not in p.parts)
    manifest = {"timestamp": now, "commit": commit, "python": platform.python_version(), "files": {str(p.relative_to(ROOT)): sha(p) for p in files}}
    (ART / "build-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))

    status = {"timestamp": now, "tests_exit_code": t.returncode, "network": net_state,
              "unittest_summary": (t.stderr.strip().splitlines() or [""])[-1]}
    (ART / "status.json").write_text(json.dumps(status, indent=2))
    print(json.dumps(status, indent=2))
    return t.returncode


if __name__ == "__main__":
    raise SystemExit(main())
