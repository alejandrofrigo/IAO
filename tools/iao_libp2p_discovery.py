#!/usr/bin/env python3
"""Autonomous, outbound-only IAO libp2p discovery and quarantined assimilation."""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from omega import libp2p_discovery  # noqa: E402
from omega.p2p_assimilation import assimilate_discovered_peers  # noqa: E402

MIN_INTERVAL = 60
MAX_INTERVAL = 86400
DEFAULT_INTERVAL = 900
DEFAULT_TIMEOUT = 30.0
MAX_TIMEOUT = 120.0


def utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def state_dir() -> Path:
    return libp2p_discovery._state_dir()


def _atomic_report(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise RuntimeError("P2P_REPORT_SYMLINK_REFUSED")
    import tempfile
    fd, name = tempfile.mkstemp(prefix=".discovery-report-", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.unlink(name)
        except OSError:
            pass
        raise


def cycle(*, timeout: float = DEFAULT_TIMEOUT) -> dict:
    if not 0 < timeout <= MAX_TIMEOUT:
        raise ValueError("DISCOVERY_TIMEOUT_OUT_OF_RANGE")
    started = utc()
    try:
        result = libp2p_discovery.discover_sync(timeout=timeout)
        if not isinstance(result, dict):
            raise RuntimeError("DISCOVERY_RESULT_INVALID")
        status = str(result.get("status", "UNKNOWN"))[:80]
        peers = result.get("routing_peers_discovered", 0)
        added = result.get("persisted_new_peers", 0)
        if any(isinstance(x, bool) or not isinstance(x, int) or x < 0
               for x in (peers, added)):
            raise RuntimeError("DISCOVERY_COUNTS_INVALID")
        assimilation = assimilate_discovered_peers(
            result.get("peers", []), state_dir=state_dir()
        )
        report = {
            "schema": 1,
            "started_at": started,
            "completed_at": utc(),
            "status": status,
            "connected_bootstrappers": int(result.get("connected_bootstrappers", 0)),
            "routing_peers_discovered": peers,
            "persisted_new_peers": added,
            "auto_assimilation": "QUARANTINED_INVENTORY_ONLY",
            "auto_assimilated_new_peers": assimilation["new"],
            "auto_assimilated_observations": assimilation["observed"],
            "assimilated_registry_total": assimilation["total"],
            "identity_verification": "NOT_PERFORMED",
            "enrollment_performed": False,
            "capabilities_granted": [],
            "remote_code_executed": False,
            "listener_exposed": False,
        }
    except Exception as exc:
        report = {
            "schema": 1,
            "started_at": started,
            "completed_at": utc(),
            "status": "DISCOVERY_ERROR",
            "error_class": type(exc).__name__,
            "auto_assimilation": "NOT_COMPLETED",
            "enrollment_performed": False,
            "capabilities_granted": [],
            "remote_code_executed": False,
            "listener_exposed": False,
        }
    _atomic_report(state_dir() / "discovery-report.json", report)
    return report


def read_interval() -> int:
    configured = os.environ.get("IAO_LIBP2P_DISCOVERY_INTERVAL", str(DEFAULT_INTERVAL))
    try:
        value = int(configured)
    except (TypeError, ValueError):
        value = DEFAULT_INTERVAL
    return max(MIN_INTERVAL, min(MAX_INTERVAL, value))


def status() -> int:
    directory = state_dir()
    report_path = directory / "discovery-report.json"
    print("IAO_LIBP2P_DISCOVERY")
    print("MODE=OUTBOUND_KADEMLIA_CLIENT")
    print("INTERVAL_SECONDS=" + str(read_interval()))
    print("REPORT_PRESENT=" + str(report_path.is_file()).lower())
    print("AUTO_ASSIMILATION=QUARANTINED_INVENTORY_ONLY")
    print("AUTO_ENROLLMENT=DISABLED")
    print("REMOTE_CODE_EXECUTION=DISABLED")
    print("INBOUND_LISTENER=DISABLED")
    if report_path.is_file() and not report_path.is_symlink():
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
            print("LAST_STATUS=" + str(report.get("status", "UNKNOWN"))[:80])
            print("LAST_DISCOVERED=" + str(report.get("routing_peers_discovered", 0)))
            print("LAST_AUTO_ASSIMILATED=" + str(report.get("assimilated_registry_total", 0)))
        except Exception:
            print("LAST_STATUS=REPORT_INVALID")
    return 0


def run_loop() -> int:
    directory = state_dir()
    directory.mkdir(parents=True, exist_ok=True)
    lock_path = directory / "discovery.lock"
    if lock_path.is_symlink():
        print("LOCK_SYMLINK_REFUSED")
        return 2
    with lock_path.open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("DISCOVERY_SUPERVISOR_ALREADY_RUNNING", flush=True)
            return 0
        print("IAO_LIBP2P_DISCOVERY=RUNNING", flush=True)
        try:
            while True:
                report = cycle()
                print(
                    "CYCLE_STATUS=" + report["status"]
                    + " DISCOVERED=" + str(report.get("routing_peers_discovered", 0))
                    + " ASSIMILATED=" + str(report.get("auto_assimilated_new_peers", 0)),
                    flush=True,
                )
                time.sleep(read_interval())
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true")
    mode.add_argument("--run", action="store_true")
    mode.add_argument("--status", action="store_true")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    args = parser.parse_args()
    if args.once:
        print(json.dumps(cycle(timeout=args.timeout), indent=2, sort_keys=True))
        return 0
    if args.run:
        return run_loop()
    return status()


if __name__ == "__main__":
    raise SystemExit(main())
