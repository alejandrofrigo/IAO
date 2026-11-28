#!/usr/bin/env python3
"""Autonomous, authorization-gated IAO federation candidate discovery."""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from omega.federation_assimilation import CandidateRegistry  # noqa: E402

STATE = ROOT / ".state"
CONFIG = STATE / "iao-federation-sources.json"
REGISTRY_FILE = STATE / "iao-federation-candidates.json"
REPORT = STATE / "iao-federation-autonomy-report.json"
PIDFILE = STATE / "iao-federation-autonomy.pid"
LOCKFILE = STATE / "iao-federation-autonomy.lock"

TIMEOUT = 10
MAX_RESPONSE = 131072
MIN_INTERVAL = 60
MAX_INTERVAL = 86400


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect())


def utc():
    return datetime.now(timezone.utc).isoformat()


def read_config():
    if CONFIG.is_symlink():
        raise ValueError("CONFIG_SYMLINK_REFUSED")
    if not CONFIG.exists():
        return {"interval_seconds": 300, "feeds": []}
    data = json.loads(CONFIG.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("feeds"), list):
        raise ValueError("CONFIG_SCHEMA_INVALID")
    interval = data.get("interval_seconds", 300)
    if not isinstance(interval, int) or isinstance(interval, bool):
        raise ValueError("INTERVAL_INVALID")
    data["interval_seconds"] = max(MIN_INTERVAL, min(MAX_INTERVAL, interval))
    return data


def validate_feed(feed):
    if not isinstance(feed, dict):
        raise ValueError("FEED_RECORD_INVALID")
    if feed.get("enabled") is not True or feed.get("authorized") is not True:
        return None
    feed_id = feed.get("id")
    url = feed.get("url")
    if not isinstance(feed_id, str) or not feed_id or len(feed_id) > 80:
        raise ValueError("FEED_ID_INVALID")
    if not isinstance(url, str):
        raise ValueError("FEED_URL_INVALID")
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname
            or parsed.username or parsed.password
            or parsed.query or parsed.fragment):
        raise ValueError("FEED_URL_REJECTED")
    return feed_id, url


def fetch_feed(url):
    req = urllib.request.Request(
        url, headers={"Accept": "application/json"},
        method="GET"
    )
    with OPENER.open(req, timeout=TIMEOUT) as response:
        if response.geturl() != url:
            raise ValueError("FEED_REDIRECT_REFUSED")
        raw = response.read(MAX_RESPONSE + 1)
    if len(raw) > MAX_RESPONSE:
        raise ValueError("FEED_TOO_LARGE")
    data = json.loads(raw.decode("utf-8"))
    if isinstance(data, dict):
        data = data.get("endpoints")
    if not isinstance(data, list):
        raise ValueError("FEED_SCHEMA_INVALID")
    if len(data) > 500:
        raise ValueError("FEED_ENDPOINT_LIMIT_EXCEEDED")
    return data



def run_libp2p_discovery():
    """Discover public DHT peers only when direct egress is explicitly permitted."""
    if os.environ.get("IAO_P2P_ALLOW_DIRECT", "").strip().lower() != "true":
        return {
            "status": "DIRECT_P2P_DISABLED_PRIVACY_POLICY",
            "connected_bootstrappers": 0,
            "routing_peers_discovered": 0,
            "persisted_new_peers": 0,
            "enrollment_performed": False,
            "capabilities_granted": [],
            "remote_code_executed": False,
        }
    try:
        from omega.libp2p_discovery import discover_sync
    except ImportError:
        return {
            "status": "DEPENDENCY_UNAVAILABLE",
            "connected_bootstrappers": 0,
            "routing_peers_discovered": 0,
            "persisted_new_peers": 0,
        }
    try:
        result = discover_sync(timeout=30)
    except Exception as exc:
        return {
            "status": "DISCOVERY_ERROR",
            "error_class": type(exc).__name__,
            "connected_bootstrappers": 0,
            "routing_peers_discovered": 0,
            "persisted_new_peers": 0,
        }
    if not isinstance(result, dict):
        return {
            "status": "INVALID_DISCOVERY_RESULT",
            "connected_bootstrappers": 0,
            "routing_peers_discovered": 0,
            "persisted_new_peers": 0,
        }
    return {
        "status": str(result.get("status", "UNKNOWN"))[:64],
        "connected_bootstrappers": int(result.get("connected_bootstrappers", 0)),
        "routing_peers_discovered": int(result.get("routing_peers_discovered", 0)),
        "persisted_new_peers": int(result.get("persisted_new_peers", 0)),
        "enrollment_performed": False,
        "capabilities_granted": [],
        "remote_code_executed": False,
    }


def cycle():
    config = read_config()
    registry = CandidateRegistry(REGISTRY_FILE)
    results = []
    discovered = 0
    errors = 0
    active_feeds = 0
    p2p_discovery = run_libp2p_discovery()

    for feed in config["feeds"]:
        try:
            validated = validate_feed(feed)
            if validated is None:
                continue
            feed_id, url = validated
            active_feeds += 1
            endpoints = fetch_feed(url)
            feed_added = 0

            for item in endpoints:
                endpoint = item.get("endpoint") if isinstance(item, dict) else item
                if not isinstance(endpoint, str):
                    results.append({
                        "feed": feed_id, "result": "INVALID_ENDPOINT_RECORD"
                    })
                    errors += 1
                    continue
                try:
                    before = len(registry.list_candidates())
                    registry.discover(endpoint, source=feed_id)
                    after = len(registry.list_candidates())
                    if after > before:
                        discovered += 1
                        feed_added += 1
                except Exception as exc:
                    errors += 1
                    results.append({
                        "feed": feed_id,
                        "result": "ENDPOINT_REJECTED",
                        "error_class": type(exc).__name__,
                    })

            results.append({
                "feed": feed_id,
                "result": "FEED_PROCESSED",
                "announced": len(endpoints),
                "new_candidates": feed_added,
            })
        except Exception as exc:
            errors += 1
            results.append({
                "feed": str(feed.get("id", "unknown"))[:80]
                    if isinstance(feed, dict) else "invalid",
                "result": "FEED_ERROR",
                "error_class": type(exc).__name__,
            })

    report = {
        "created_utc": utc(),
        "active_authorized_feeds": active_feeds,
        "libp2p_discovery": p2p_discovery,
        "new_candidates": discovered,
        "errors": errors,
        "candidate_total": len(registry.list_candidates()),
        "results": results,
        "identity_verification_performed": False,
        "authorization_granted": False,
        "peer_enrollment_performed": False,
        "capability_exchange_performed": False,
    }
    temp = REPORT.with_suffix(".tmp")
    temp.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
    os.chmod(temp, 0o600)
    temp.replace(REPORT)
    return report


def status():
    config = read_config()
    registry = CandidateRegistry(REGISTRY_FILE)
    feeds = config["feeds"]
    authorized = sum(
        1 for f in feeds
        if isinstance(f, dict)
        and f.get("enabled") is True
        and f.get("authorized") is True
    )
    print("IAO FEDERATION AUTONOMY")
    print("FEED_COUNT=" + str(len(feeds)))
    print("AUTHORIZED_ENABLED_FEEDS=" + str(authorized))
    print("CANDIDATE_COUNT=" + str(len(registry.list_candidates())))
    print("INTERVAL_SECONDS=" + str(config["interval_seconds"]))
    print("AUTOMATIC_ENROLLMENT=DISABLED")
    print("UNAUTHORIZED_DISCOVERY=DISABLED")


def run_loop():
    STATE.mkdir(parents=True, exist_ok=True)
    with LOCKFILE.open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("SUPERVISOR_ALREADY_RUNNING")
            return 0

        PIDFILE.write_text(str(os.getpid()), encoding="ascii")
        os.chmod(PIDFILE, 0o600)
        print("IAO_FEDERATION_SUPERVISOR=RUNNING", flush=True)

        try:
            while True:
                try:
                    report = cycle()
                    print(
                        "CYCLE=" + utc()
                        + " CANDIDATES=" + str(report["candidate_total"])
                        + " NEW=" + str(report["new_candidates"])
                        + " ERRORS=" + str(report["errors"]),
                        flush=True,
                    )
                except Exception as exc:
                    print("CYCLE_ERROR=" + type(exc).__name__, flush=True)
                interval = read_config()["interval_seconds"]
                time.sleep(interval)
        finally:
            try:
                PIDFILE.unlink()
            except FileNotFoundError:
                pass
    return 0


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--status", action="store_true")
    group.add_argument("--once", action="store_true")
    group.add_argument("--run", action="store_true")
    args = parser.parse_args()

    STATE.mkdir(parents=True, exist_ok=True)
    if args.run:
        return run_loop()
    if args.once:
        report = cycle()
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    status()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
