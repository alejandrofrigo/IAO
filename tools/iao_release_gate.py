#!/usr/bin/env python3
"""Fail-closed release gate for IAO.

This gate evaluates local evidence. It never deploys or publishes by itself.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


REQUIRED_FILES = (
    "omega/padge.py",
    "omega/federation.py",
    "tools/iao_public_node_launcher.py",
    "tools/iao_five_motor_supervisor.py",
    "tools/iao_control_plane_local.py",
    "apps/api/main.py",
)

TEST_GROUPS = {
    "federation": (
        "tests/test_public_node_launcher_verification.py",
        "tests/test_federation.py",
    ),
    "autonomy": (
        "tests/test_iao_runtime_recovery.py",
    ),
    "trust": (
        "tests/test_federation_trust_store.py",
    ),
}

class ReleaseGate:
    def __init__(self, root: Path, timeout: int = 900):
        self.root = root.resolve()
        self.timeout = timeout
        self.results: list[dict[str, Any]] = []

    def record(self, name: str, ok: bool, detail: str) -> None:
        self.results.append({
            "check": name,
            "ok": bool(ok),
            "detail": str(detail)[:1000],
        })

    def check_files(self) -> None:
        missing = [f for f in REQUIRED_FILES
                   if not (self.root / f).is_file()]
        self.record(
            "critical_files",
            not missing,
            "missing=" + ",".join(missing) if missing else "all_present",
        )

    def check_python_compile(self) -> None:
        targets = [
            self.root / f for f in REQUIRED_FILES
            if f.endswith(".py") and (self.root / f).is_file()
        ]
        result = subprocess.run(
            [sys.executable, "-m", "py_compile", *map(str, targets)],
            cwd=self.root,
            capture_output=True,
            text=True,
            timeout=self.timeout,
        )
        self.record(
            "python_compile",
            result.returncode == 0,
            (result.stdout + result.stderr).strip()
            or f"exit={result.returncode}",
        )

    def check_tests(self) -> None:
        for group, paths in TEST_GROUPS.items():
            existing = [p for p in paths if (self.root / p).is_file()]
            missing = [p for p in paths if not (self.root / p).is_file()]
            if missing:
                self.record(
                    f"tests_{group}",
                    False,
                    "missing=" + ",".join(missing),
                )
                continue
            result = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", *existing],
                cwd=self.root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            output = (result.stdout + result.stderr).strip()
            self.record(
                f"tests_{group}",
                result.returncode == 0,
                output or f"exit={result.returncode}",
            )

    def check_configuration(self) -> None:
        env_path = self.root / ".env"
        configured = set()
        if env_path.is_file():
            for line in env_path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    configured.add(line.split("=", 1)[0].strip())

        required = {"APP_ENV", "HOST", "PORT"}
        missing = sorted(required - configured)
        # Never disclose values from environment or .env.
        self.record(
            "deployment_configuration",
            not missing,
            "missing_keys=" + ",".join(missing)
            if missing else "required_keys_present",
        )

    def check_trust_store(self) -> None:
        module = self.root / "omega/federation_trust_store.py"
        recovery = self.root / "tools/iao_runtime_recovery.py"
        self.record(
            "federation_trust_store",
            module.is_file(),
            "present" if module.is_file() else "not_installed",
        )
        self.record(
            "runtime_recovery",
            recovery.is_file(),
            "present" if recovery.is_file() else "not_installed",
        )

    def run(self) -> dict[str, Any]:
        self.check_files()
        self.check_python_compile()
        self.check_tests()
        self.check_configuration()
        self.check_trust_store()

        passed = sum(1 for r in self.results if r["ok"])
        failed = len(self.results) - passed
        return {
            "version": 1,
            "timestamp": time.time(),
            "release_authorized": failed == 0,
            "status": "READY_FOR_SEPARATE_DEPLOYMENT_REVIEW"
                     if failed == 0 else "BLOCKED",
            "checks_passed": passed,
            "checks_failed": failed,
            "checks": self.results,
            "deployment_performed": False,
            "external_service_verified": False,
        }


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(".state/reports/iao-release-gate/latest.json"),
    )
    args = parser.parse_args()

    report = ReleaseGate(args.root).run()
    output = args.output
    if not output.is_absolute():
        output = args.root / output
    output.parent.mkdir(parents=True, exist_ok=True)
    tmp = output.with_suffix(output.suffix + ".tmp")
    tmp.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, output)

    print(json.dumps(report, indent=2))
    print(f"REPORT_FILE={output}")
    return 0 if report["release_authorized"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
