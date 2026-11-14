#!/usr/bin/env python3
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / ".state" / "padge" / "reports"
INTERVAL = 300

def latest_report():
    files = list(REPORTS.glob("*.json"))
    return max(files, key=lambda p: p.stat().st_mtime_ns) if files else None

def run_cycle():
    previous = latest_report()
    previous_name = previous.name if previous else None

    print("\nPADGE: iniciando ciclo autónomo", flush=True)

    result = subprocess.run(
        [sys.executable, "-m", "omega.padge", "once"],
        cwd=ROOT,
        check=False,
    )

    if result.returncode != 0:
        print("STOP: PADGE devolvió un error", flush=True)
        return False

    report = latest_report()
    if report is None or report.name == previous_name:
        print("STOP: no se generó un informe nuevo", flush=True)
        return False

    try:
        data = json.loads(report.read_text(encoding="utf-8"))
    except Exception as exc:
        print("STOP: informe ilegible:", str(exc), flush=True)
        return False

    status = str(data.get("status", "")).upper()
    promotion = data.get("promotion")
    policy = data.get("policy")

    print("INFORME:", report.name, flush=True)
    print("ESTADO:", status, flush=True)
    print("PROMOCION:", json.dumps(promotion, ensure_ascii=False), flush=True)

    if any(word in status for word in (
        "REJECT", "DENIED", "FAIL", "ERROR", "INVALID"
    )):
        print("STOP: rechazo o fallo; requiere adaptación", flush=True)
        return False

    if isinstance(policy, dict) and policy.get("approved") is False:
        print("STOP: política independiente rechazó la propuesta", flush=True)
        return False

    promotion_text = str(promotion).upper()
    if "PROMOT" not in status and "PROMOT" not in promotion_text:
        print("STOP: promoción no confirmada en el informe", flush=True)
        return False

    print("PROMOTION_VERIFIED=PASS", flush=True)
    return True

def main():
    print("IAO PADGE AUTONOMOUS SUPERVISOR", flush=True)
    print("INTERVAL_SECONDS:", INTERVAL, flush=True)

    while True:
        if not run_cycle():
            print("PADGE_SUPERVISOR=SAFE_STOP", flush=True)
            return 1

        print(
            f"PADGE: siguiente ciclo en {INTERVAL} segundos",
            flush=True,
        )
        time.sleep(INTERVAL)

if __name__ == "__main__":
    raise SystemExit(main())
