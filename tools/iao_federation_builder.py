#!/usr/bin/env python3
"""Constructor autónomo de propuestas de evolución federada mediante PADGE."""
from __future__ import annotations

import fcntl
import json
import os
import signal
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

STATE = ROOT / ".state" / "iao-federation-builder"
LOCK = STATE / "builder.lock"
REPORT = STATE / "builder-status.json"
LOG = STATE / "builder-events.jsonl"
INTERVAL = max(900, int(os.environ.get("IAO_FEDERATION_BUILD_INTERVAL", "1800")))

shutdown = False


def utc():
    return datetime.now(timezone.utc).isoformat()


def record(event, **fields):
    STATE.mkdir(parents=True, exist_ok=True)
    item = {"timestamp": utc(), "event": event, **fields}
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(item, ensure_ascii=False) + "\n")
    tmp = REPORT.with_suffix(".tmp")
    tmp.write_text(
        json.dumps(item, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    os.chmod(tmp, 0o600)
    tmp.replace(REPORT)
    print(json.dumps(item, ensure_ascii=False), flush=True)


def stop(signum, frame):
    global shutdown
    shutdown = True


def cycle():
    from tools import iao_padge_bridge as bridge

    padge = bridge.load_padge()
    snapshot = bridge.validate_snapshot(padge.inspect())

    record(
        "FEDERATION_BUILD_STARTED",
        branch=snapshot["branch"],
        commit=snapshot["commit"],
        inspected_files=len(snapshot["files"]),
    )

    result = bridge.propose(padge)

    record(
        "FEDERATION_BUILD_CYCLE_FINISHED",
        bridge_return=result,
        execution="PROPOSAL_AND_PREFLIGHT_ONLY",
        integration="NOT_AUTOMATICALLY_PROMOTED",
    )


def main():
    STATE.mkdir(parents=True, exist_ok=True)
    with LOCK.open("a+", encoding="utf-8") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("FEDERATION_BUILDER_ALREADY_RUNNING=1", flush=True)
            return 0

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)

        record(
            "FEDERATION_BUILDER_STARTED",
            interval_seconds=INTERVAL,
            engine="PADGE",
            scope="FEDERATION_EVOLUTION",
        )

        while not shutdown:
            started = time.monotonic()
            try:
                cycle()
            except Exception as exc:
                record(
                    "FEDERATION_BUILD_CYCLE_ERROR",
                    error_class=type(exc).__name__,
                    error=str(exc)[:500],
                )
                traceback.print_exc()

            remaining = max(1, INTERVAL - int(time.monotonic() - started))
            while remaining > 0 and not shutdown:
                step = min(5, remaining)
                time.sleep(step)
                remaining -= step

        record("FEDERATION_BUILDER_STOPPED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
