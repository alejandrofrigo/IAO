import os
import json
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path.cwd()
STATE = ROOT / ".state"
REPORTS = STATE / "reports"
REPORTS.mkdir(parents=True, exist_ok=True)

report = []

def out(key, value):
    report.append(f"{key}={value}")

def run(cmd):
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=15
        ).stdout.strip()
    except Exception as exc:
        return f"ERROR:{type(exc).__name__}"

out("IAO_INTEGRAL_AUTONOMY_AUDIT", "START")
out("UTC", datetime.now(timezone.utc).isoformat())
out("MODE", "READ_ONLY")

# 1. Processes
processes = run(["ps", "-A", "-o", "pid=,comm="])
keywords = (
    "omega.server", "supervisor", "padge",
    "guardian", "node_network",
    "distributed_intelligence", "autonomy"
)

matches = []
for line in processes.splitlines():
    low = line.lower()
    if any(k in low for k in keywords):
        matches.append(line.strip())

out("PROCESSES_MATCHED", len(matches))
for item in matches:
    out("PROCESS", item)

# 2. Local API probes
for port in (8000, 8080, 5000, 3000):
    for endpoint in ("/health/live", "/health/ready"):
        url = f"http://127.0.0.1:{port}{endpoint}"
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "IAO-Audit/1.0"}
            )
            with urllib.request.urlopen(req, timeout=3) as response:
                body = response.read(8192).decode(
                    "utf-8", errors="replace"
                )
                out(f"HTTP_{port}_{endpoint}", response.status)
                try:
                    data = json.loads(body)
                    out(f"API_{port}_{endpoint}_STATUS",
                        data.get("status", "UNKNOWN"))
                    checks = data.get("checks")
                    if isinstance(checks, dict):
                        out(f"API_{port}_{endpoint}_CHECKS",
                            json.dumps(checks, sort_keys=True))
                except Exception:
                    out(f"API_{port}_{endpoint}_BODY", "NON_JSON")
        except urllib.error.HTTPError as exc:
            out(f"HTTP_{port}_{endpoint}", exc.code)
        except Exception:
            out(f"HTTP_{port}_{endpoint}", "UNAVAILABLE")

# 3. Git status
git = run(["git", "status", "--short"])
out("GIT_STATUS_LINES", len(git.splitlines()))
out("GIT_STATUS", git if git else "CLEAN")

# 4. Motor configuration: names and enabled flags only
config = STATE / "iao-five-motors" / "adapters.json"
if config.exists():
    try:
        data = json.loads(config.read_text(encoding="utf-8"))
        for name, spec in data.get("motors", {}).items():
            out(f"MOTOR_{name}_ENABLED",
                spec.get("enabled", "UNKNOWN"))
    except Exception as exc:
        out("MOTOR_CONFIG", f"INVALID:{type(exc).__name__}")
else:
    out("MOTOR_CONFIG", "NOT_FOUND")

# 5. Recent operational logs: counters, never print contents
log_names = [
    "padge.log",
    "guardian.log",
    "node_network.log",
    "distributed_intelligence.log",
    "autonomy_continuous.log",
]

log_root = STATE / "iao-five-motors" / "logs"

for name in log_names:
    path = log_root / name
    if not path.exists():
        out(f"LOG_{name}", "MISSING")
        continue

    try:
        lines = path.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
        recent = lines[-500:]
        low = "\n".join(recent).lower()

        out(f"LOG_{name}_LINES", len(lines))
        out(f"LOG_{name}_ERRORS",
            low.count("error") + low.count("exception"))
        out(f"LOG_{name}_CYCLES",
            low.count("cycle") + low.count("iteration"))
    except Exception as exc:
        out(f"LOG_{name}", f"READ_ERROR:{type(exc).__name__}")

# 6. JSONL integrity: syntax only, not cryptographic chain validation
audit_candidates = []
for folder in (STATE / "autonomy", STATE / "audit", STATE):
    if folder.exists():
        try:
            audit_candidates.extend(
                p for p in folder.glob("*.jsonl")
                if p.is_file()
            )
        except OSError:
            pass

seen = set()
for path in audit_candidates[:20]:
    if path in seen:
        continue
    seen.add(path)
    valid = 0
    invalid = 0
    try:
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    continue
                try:
                    json.loads(line)
                    valid += 1
                except Exception:
                    invalid += 1
        out(f"AUDIT_{path.name}",
            f"VALID_JSON={valid};INVALID_JSON={invalid}")
    except Exception as exc:
        out(f"AUDIT_{path.name}",
            f"READ_ERROR:{type(exc).__name__}")

out("AUDIT_CHAIN_CRYPTOGRAPHICALLY_VERIFIED", "NO")
out("EXTERNAL_NODES_VERIFIED", "NOT_TESTED")
out("AUTONOMY_END_TO_END", "NOT_CERTIFIED")
out("MODE", "READ_ONLY")
out("AUDIT_FINISHED", "YES")

destination = REPORTS / (
    "IAO_INTEGRAL_AUTONOMY_" +
    datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") +
    ".txt"
)

destination.write_text(
    "\n".join(report) + "\n",
    encoding="utf-8"
)

print("\n".join(report))
print(f"\nREPORT={destination}")
