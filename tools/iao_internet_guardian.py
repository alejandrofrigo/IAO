#!/usr/bin/env python3
"""IAO Internet Guardian: connectivity, recovery and federated discovery."""

import json
import os
import sqlite3
import time
import urllib.request
import urllib.error
import urllib.parse
import hashlib
from pathlib import Path

CFG = Path.home() / ".config/iao/node-network.json"
DATA = Path.home() / ".local/share/iao/node-network"
DB = DATA / "network.sqlite3"
LOG = DATA / "internet-guardian.log"
REPORT = DATA / "internet-discovery-report.json"

CONNECTIVITY_URLS = [
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://www.google.com/generate_204",
]

USER_AGENT = "IAO-Internet-Guardian/1.0"

def log(message):
    DATA.mkdir(parents=True, exist_ok=True)
    line = time.strftime("%Y-%m-%d %H:%M:%S") + " " + message
    with LOG.open("a") as f:
        f.write(line + "\n")
    print(line, flush=True)

def load_config():
    return json.loads(CFG.read_text())

def save_report(report):
    DATA.mkdir(parents=True, exist_ok=True)
    tmp = REPORT.with_suffix(".tmp")
    tmp.write_text(json.dumps(report, indent=2))
    tmp.replace(REPORT)

def fetch(url, timeout=12):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT}
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.status, response.read(65536)

def internet_check():
    for url in CONNECTIVITY_URLS:
        try:
            code, _ = fetch(url)
            if 200 <= code < 400:
                return True, url
        except Exception:
            continue
    return False, None

def db_connection():
    if not DB.exists():
        raise RuntimeError("Network database does not exist")
    db = sqlite3.connect(DB, timeout=15)
    return db

def directories():
    db = db_connection()
    rows = db.execute(
        "SELECT endpoint FROM directories"
    ).fetchall()
    db.close()
    return [r[0] for r in rows]

def validate_endpoint(endpoint):
    parsed = urllib.parse.urlparse(endpoint)
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and not parsed.username
        and not parsed.password
    )

def verify_candidate(candidate):
    endpoint = candidate.get("endpoint", "").rstrip("/")
    node_id = candidate.get("node_id", "")
    caps = candidate.get("capabilities", [])

    if not node_id or not validate_endpoint(endpoint):
        return None

    try:
        code, raw = fetch(endpoint + "/health")
        if code != 200:
            return None

        health = json.loads(raw)
        if health.get("service") != "IAO_NODE_NETWORK":
            return None

        if health.get("node_id") != node_id:
            return None

        return {
            "node_id": node_id,
            "endpoint": endpoint,
            "capabilities": caps if isinstance(caps, list) else [],
            "verified_health": True,
            "discovered_at": int(time.time()),
        }
    except Exception:
        return None

def save_candidate(candidate):
    db = db_connection()
    trusted = db.execute(
        "SELECT 1 FROM peers WHERE node_id=? AND authorized=1",
        (candidate["node_id"],)
    ).fetchone()

    state = "authorized" if trusted else "candidate"

    db.execute("""
        INSERT INTO nodes(
            node_id,endpoint,capabilities,last_seen,status
        ) VALUES(?,?,?,?,?)
        ON CONFLICT(node_id) DO UPDATE SET
          endpoint=excluded.endpoint,
          capabilities=excluded.capabilities,
          last_seen=excluded.last_seen,
          status=excluded.status
    """, (
        candidate["node_id"],
        candidate["endpoint"],
        json.dumps(candidate["capabilities"]),
        int(time.time()),
        state,
    ))
    db.commit()
    db.close()

def discover_directory(directory):
    if not validate_endpoint(directory):
        log("DIRECTORY_REJECTED invalid HTTPS directory")
        return []

    try:
        code, raw = fetch(directory.rstrip("/") + "/v1/directory")
        if code != 200:
            return []

        data = json.loads(raw)
        results = []

        for item in data.get("nodes", []):
            candidate = verify_candidate(item)
            if candidate:
                save_candidate(candidate)
                results.append(candidate)
                log("NODE_CANDIDATE_VERIFIED " + candidate["node_id"])

        db = db_connection()
        db.execute(
            "UPDATE directories SET last_check=?,status='online' "
            "WHERE endpoint=?",
            (int(time.time()), directory)
        )
        db.commit()
        db.close()
        log("DIRECTORY_OK " + directory)

        return results

    except Exception as exc:
        log("DIRECTORY_FAILED " + type(exc).__name__)
        try:
            db = db_connection()
            db.execute(
                "UPDATE directories SET last_check=?,status='offline' "
                "WHERE endpoint=?",
                (int(time.time()), directory)
            )
            db.commit()
            db.close()
        except Exception:
            pass
        return []

def run_cycle():
    online, source = internet_check()

    report = {
        "timestamp": int(time.time()),
        "internet": {
            "connected": online,
            "verified_by": source
        },
        "directories_checked": [],
        "verified_candidates": [],
        "enrollment": "REQUIRES_AUTHORIZATION"
    }

    if not online:
        log("INTERNET_DISCONNECTED retry_pending")
        save_report(report)
        return report

    log("INTERNET_CONNECTED " + str(source))

    for directory in directories():
        report["directories_checked"].append(directory)
        found = discover_directory(directory)
        report["verified_candidates"].extend(found)

    save_report(report)
    log(
        "DISCOVERY_CYCLE_COMPLETE verified_candidates="
        + str(len(report["verified_candidates"]))
    )
    return report

def main():
    cfg = load_config()
    interval = max(60, int(cfg.get("discovery_interval", 300)))

    log("INTERNET_GUARDIAN_STARTED interval=" + str(interval))

    failures = 0

    while True:
        try:
            run_cycle()
            failures = 0
            time.sleep(interval)

        except KeyboardInterrupt:
            log("INTERNET_GUARDIAN_STOPPED")
            return

        except Exception as exc:
            failures += 1
            delay = min(900, 30 * (2 ** min(failures, 5)))
            log(
                "GUARDIAN_RECOVERY error="
                + type(exc).__name__
                + " retry_seconds=" + str(delay)
            )
            time.sleep(delay)

if __name__ == "__main__":
    main()
