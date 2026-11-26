#!/usr/bin/env python
import hashlib
import json
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB = Path.home() / ".local/share/iao/information-flow.sqlite3"
INGEST = ROOT / "tools/iao_ingest.py"
LOG = Path.home() / ".local/state/iao/ingest-watch.log"
INTERVAL = 60

def log(event, **fields):
    LOG.parent.mkdir(parents=True, exist_ok=True)
    row = {
        "time": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **fields,
    }
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(json.dumps(row, ensure_ascii=False), flush=True)

def signature():
    if not DB.is_file():
        return None
    uri = "file:" + str(DB.resolve()) + "?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=5) as con:
        rows = con.execute("""
            SELECT id, received_at
            FROM inbox
            ORDER BY received_at DESC, id DESC
            LIMIT 100
        """).fetchall()
        count = con.execute("SELECT COUNT(*) FROM inbox").fetchone()[0]
    payload = json.dumps(
        {"count": count, "rows": rows},
        ensure_ascii=False, separators=(",", ":")
    ).encode()
    return hashlib.sha256(payload).hexdigest()

def main():
    if not INGEST.is_file():
        log("BLOCKED", reason="ingest_script_missing")
        return 2
    try:
        previous = signature()
    except Exception as e:
        log("BLOCKED", reason="inbox_unavailable",
            error=type(e).__name__)
        return 2

    log("WATCH_STARTED", interval_seconds=INTERVAL,
        baseline_available=previous is not None)

    while True:
        time.sleep(INTERVAL)
        try:
            current = signature()
            if current is None or current == previous:
                continue
            result = subprocess.run(
                [sys.executable, str(INGEST)],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                timeout=120,
            )
            log(
                "INGEST_UPDATED" if result.returncode == 0 else "INGEST_FAILED",
                returncode=result.returncode,
                output=result.stdout[-2500:],
                error=result.stderr[-1000:],
            )
            if result.returncode == 0:
                previous = current
        except Exception as e:
            log("WATCH_ERROR", error=type(e).__name__)

if __name__ == "__main__":
    raise SystemExit(main())
