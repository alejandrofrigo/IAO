#!/usr/bin/env python3
"""Gate-enforced deployment wrapper for IAO."""

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def load_gate(path, max_age=300):
    p = Path(path)
    if not p.is_file():
        raise RuntimeError("RELEASE_GATE_REPORT_MISSING")

    data = json.loads(p.read_text(encoding="utf-8"))

    if data.get("release_authorized") is not True:
        raise RuntimeError("RELEASE_NOT_AUTHORIZED")
    if data.get("status") != "READY_FOR_SEPARATE_DEPLOYMENT_REVIEW":
        raise RuntimeError("RELEASE_STATUS_NOT_READY")
    if data.get("checks_failed") != 0:
        raise RuntimeError("RELEASE_GATE_HAS_FAILURES")
    if data.get("deployment_performed") is not False:
        raise RuntimeError("GATE_REPORT_NOT_PREDEPLOYMENT")

    timestamp = float(data.get("timestamp", 0))
    age = time.time() - timestamp
    if age < -30 or age > max_age:
        raise RuntimeError("RELEASE_GATE_REPORT_STALE")

    checks = data.get("checks")
    if not isinstance(checks, list) or not checks:
        raise RuntimeError("RELEASE_GATE_CHECKS_MISSING")
    if any(not isinstance(c, dict) or c.get("ok") is not True
           for c in checks):
        raise RuntimeError("RELEASE_GATE_CHECK_FAILED")

    return data


def health_check(url, timeout=8):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "IAO-deployment-verifier/1.0"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(65536).decode("utf-8", "replace")
            if response.status != 200:
                return False, f"HTTP_{response.status}"
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                return False, "HEALTH_RESPONSE_NOT_JSON"

            if payload.get("status") not in ("live", "ready", "ok"):
                return False, "HEALTH_STATUS_NOT_ACCEPTED"
            return True, f"HTTP_{response.status}:{payload.get('status')}"
    except Exception as exc:
        return False, type(exc).__name__ + ":" + str(exc)[:250]


def run_command(command, cwd, log_path, timeout):
    if not command:
        raise RuntimeError("DEPLOY_COMMAND_MISSING")
    with open(log_path, "w", encoding="utf-8") as log:
        result = subprocess.run(
            command,
            cwd=cwd,
            stdout=log,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
    return result.returncode


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--gate", required=True)
    parser.add_argument("--health-url", required=True)
    parser.add_argument("--health-attempts", type=int, default=12)
    parser.add_argument("--health-interval", type=float, default=5)
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--rollback-timeout", type=int, default=300)
    parser.add_argument("--rollback-command", nargs="+")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    report_dir = root / ".state" / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / (
        "deploy-guard-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        + ".json"
    )

    report = {
        "deployment_attempted": False,
        "deployment_succeeded": False,
        "health_verified": False,
        "rollback_attempted": False,
        "rollback_succeeded": False,
    }

    try:
        gate_path = Path(args.gate)
        if not gate_path.is_absolute():
            gate_path = root / gate_path
        gate = load_gate(gate_path)
        report["gate_authorized"] = True
        report["gate_timestamp"] = gate.get("timestamp")

        command = args.command
        if command and command[0] == "--":
            command = command[1:]

        if not command:
            raise RuntimeError("DEPLOY_COMMAND_MISSING")

        report["deployment_command"] = command[0]

        if not args.execute:
            report["status"] = "DRY_RUN_GATE_APPROVED"
            print(json.dumps(report, indent=2))
            return 0

        report["deployment_attempted"] = True
        rc = run_command(
            command, str(root),
            str(report_dir / "deploy-command.log"),
            args.timeout,
        )
        report["deployment_exit"] = rc

        if rc != 0:
            raise RuntimeError("DEPLOY_COMMAND_FAILED")

        report["deployment_succeeded"] = True

        healthy = False
        last_detail = "NOT_CHECKED"
        for _ in range(max(1, args.health_attempts)):
            healthy, last_detail = health_check(args.health_url)
            if healthy:
                break
            time.sleep(max(0, args.health_interval))

        report["health_verified"] = healthy
        report["health_detail"] = last_detail

        if not healthy:
            raise RuntimeError("POST_DEPLOY_HEALTH_CHECK_FAILED")

        report["status"] = "DEPLOYED_AND_HEALTH_VERIFIED"

    except Exception as exc:
        report["error"] = str(exc)
        if report["deployment_attempted"] and args.rollback_command:
            report["rollback_attempted"] = True
            try:
                rc = run_command(
                    args.rollback_command, str(root),
                    str(report_dir / "rollback-command.log"),
                    args.rollback_timeout,
                )
                report["rollback_exit"] = rc
                report["rollback_succeeded"] = rc == 0
            except Exception as rollback_exc:
                report["rollback_error"] = str(rollback_exc)
        report["status"] = "BLOCKED_OR_FAILED"

    finally:
        report_path.write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8"
        )
        print("DEPLOY_GUARD_REPORT=" + str(report_path))
        print(json.dumps(report, indent=2))

    return 0 if report.get("status") in (
        "DRY_RUN_GATE_APPROVED",
        "DEPLOYED_AND_HEALTH_VERIFIED",
    ) else 2


if __name__ == "__main__":
    sys.exit(main())
