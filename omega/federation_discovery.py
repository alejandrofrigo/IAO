from __future__ import annotations

import base64
import fcntl
import json
import os
import re
import sys
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

from omega.federation_transport import fetch_public_json

_INTERVAL = max(300, int(os.environ.get("IAO_FED_DISCOVERY_INTERVAL", "1800")))
_THREAD = None
_LOCK = threading.Lock()

QUERIES = (
    "iao-federation",
    '"iao federation" protocol',
)

MANIFEST_PATHS = (
    ".well-known/iao-federation.json",
    "iao-federation.json",
    "federation-node.json",
)


def _now():
    return datetime.now(timezone.utc).isoformat()


def _request_json(url, timeout=12):
    """Fetch bounded public JSON through the pinned federation transport."""
    return fetch_public_json(
        url, timeout=min(float(timeout), 30.0), max_bytes=1024 * 1024
    )


def _request_manifest(full_name, branch, path):
    """Read a repository manifest through GitHub's JSON Contents API.

    The Contents API returns base64 in application/json, allowing the same
    pinned HTTPS transport to protect both discovery and manifest retrieval.
    This avoids raw.githubusercontent.com's text/plain response path and
    urllib's ambient proxy/redirect behavior.
    """
    if not isinstance(full_name, str) or not re.fullmatch(
        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", full_name
    ):
        raise ValueError("INVALID_REPOSITORY_NAME")
    if not isinstance(branch, str) or not branch or len(branch) > 255:
        raise ValueError("INVALID_DEFAULT_BRANCH")
    encoded_path = urllib.parse.quote(path, safe="")
    url = (
        "https://api.github.com/repos/" + full_name + "/contents/"
        + encoded_path + "?" + urllib.parse.urlencode({"ref": branch})
    )
    result = _request_json(url)
    if (
        not isinstance(result, dict)
        or result.get("encoding") != "base64"
        or not isinstance(result.get("content"), str)
    ):
        raise ValueError("INVALID_GITHUB_CONTENTS_RESPONSE")
    try:
        raw = base64.b64decode(result["content"], validate=True)
        if len(raw) > 1024 * 1024:
            raise ValueError("MANIFEST_TOO_LARGE")
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("INVALID_FEDERATION_MANIFEST") from exc


def _append(state, event):
    state.mkdir(parents=True, exist_ok=True)
    path = state / "federation-discovery.jsonl"
    record = dict(event)
    record["timestamp"] = _now()
    data = (json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n").encode()
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def _valid_manifest(obj):
    if not isinstance(obj, dict):
        return False, "NOT_AN_OBJECT"

    node_id = obj.get("node_id")
    public_key = obj.get("public_key")
    origin = obj.get("origin")

    if obj.get("protocol") != "iao-federation":
        return False, "PROTOCOL_MISMATCH"
    if obj.get("version") != 1:
        return False, "VERSION_UNSUPPORTED"
    if obj.get("consent") is not True:
        return False, "NO_EXPLICIT_PEERING_CONSENT"
    if not isinstance(node_id, str) or not re.fullmatch(r"[0-9a-f]{16}", node_id):
        return False, "INVALID_NODE_ID"
    if not isinstance(public_key, str) or not re.fullmatch(r"[0-9a-f]{64}", public_key):
        return False, "INVALID_PUBLIC_KEY"

    if not isinstance(origin, str):
        return False, "INVALID_ORIGIN"

    parsed = urllib.parse.urlsplit(origin)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
        or parsed.port not in (None, 443)
    ):
        return False, "ORIGIN_NOT_ALLOWED"

    return True, "MANIFEST_UNVERIFIED"


def _inspect_repo(repo, state):
    full_name = repo.get("full_name")
    branch = repo.get("default_branch") or "main"
    if not isinstance(full_name, str) or "/" not in full_name:
        return

    _append(state, {
        "event": "REPOSITORY_DISCOVERED",
        "repository": full_name,
        "repository_url": repo.get("html_url"),
        "status": "UNVERIFIED_DISCOVERY_LEAD",
    })

    for path in MANIFEST_PATHS:
        try:
            manifest = _request_manifest(full_name, branch, path)
        except Exception:
            continue

        valid, reason = _valid_manifest(manifest)
        if not valid:
            _append(state, {
                "event": "MANIFEST_REJECTED",
                "repository": full_name,
                "reason": reason,
            })
            continue

        _append(state, {
            "event": "NODE_CANDIDATE_DISCOVERED",
            "repository": full_name,
            "node_id": manifest["node_id"],
            "origin": manifest["origin"],
            "public_key": manifest["public_key"],
            "capabilities": manifest.get("capabilities", []),
            "status": "MANIFEST_UNVERIFIED",
            "identity_verification": "NOT_PERFORMED",
            "enrollment": "NOT_PERFORMED",
            "granted_capabilities": [],
        })
        return


def discover_once(state_dir):
    state = Path(state_dir)
    totals = {"queries": 0, "repositories": 0, "errors": 0}

    _append(state, {
        "event": "DISCOVERY_CYCLE_STARTED",
        "source": "github_public_repository_search",
    })

    for query in QUERIES:
        totals["queries"] += 1
        url = "https://api.github.com/search/repositories?" + urllib.parse.urlencode({
            "q": query,
            "sort": "updated",
            "per_page": 20,
        })

        try:
            result = _request_json(url)
            repos = result.get("items", [])
            for repo in repos[:20]:
                totals["repositories"] += 1
                try:
                    _inspect_repo(repo, state)
                except Exception as exc:
                    totals["errors"] += 1
                    _append(state, {
                        "event": "REPOSITORY_INSPECTION_ERROR",
                        "repository": repo.get("full_name"),
                        "error_type": type(exc).__name__,
                    })
        except Exception as exc:
            totals["errors"] += 1
            _append(state, {
                "event": "DISCOVERY_SOURCE_ERROR",
                "source": "github",
                "query": query,
                "error_type": type(exc).__name__,
            })

    _append(state, {
        "event": "DISCOVERY_CYCLE_FINISHED",
        **totals,
    })
    return totals


def run_forever(state_dir):
    state = Path(state_dir)
    state.mkdir(parents=True, exist_ok=True)
    lock_path = state / "federation-discovery.lock"
    lock_file = open(lock_path, "a")

    try:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("DISCOVERY_ALREADY_RUNNING", flush=True)
        lock_file.close()
        return

    print("IAO_FEDERATION_DISCOVERY_STARTED", flush=True)
    try:
        while True:
            try:
                result = discover_once(state)
                print("DISCOVERY_CYCLE", json.dumps(result), flush=True)
            except Exception as exc:
                print("DISCOVERY_ERROR", type(exc).__name__, flush=True)
            time.sleep(_INTERVAL)
    finally:
        lock_file.close()


def start_federation_discovery(state_dir):
    global _THREAD
    with _LOCK:
        if _THREAD is not None and _THREAD.is_alive():
            return True
        _THREAD = threading.Thread(
            target=run_forever,
            args=(state_dir,),
            name="iao-federation-discovery",
            daemon=True,
        )
        _THREAD.start()
    return True


if __name__ == "__main__" and "--run" in sys.argv:
    run_forever(os.environ.get("OMEGA_STATE_DIR", ".state"))
