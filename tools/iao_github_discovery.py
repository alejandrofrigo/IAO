#!/usr/bin/env python3
"""Descubrimiento GitHub de candidatos IAO. Nunca enrola por sí solo."""
import argparse
import json
import os
import re
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".state"
OUTPUT = STATE / "iao-github-candidates.json"

SEARCHES = (
    "iao federation",
    "iao node",
    "iao protocol",
    "iao agent",
    "public API OpenAPI",
    "MCP server tools",
    "OpenAI compatible inference API",
    "self hosted AI agent",
    "distributed compute node API",
    "federated AI infrastructure",
    "GraphQL public API",
    "AI model serving API",
)
MAX_REPOS = 30
MAX_RESPONSE = 1024 * 1024
MAX_MANIFEST = 65536
TIMEOUT = 4
MAX_MANIFEST_CHECKS = 12
GLOBAL_BUDGET_SECONDS = 105
DEADLINE = 0.0

def get(url, limit):
    remaining = DEADLINE - time.monotonic()
    if remaining <= 0.25:
        raise TimeoutError("GLOBAL_DISCOVERY_DEADLINE")
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "IAO-Federation-Discovery/1.2",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    with urllib.request.urlopen(req, timeout=min(TIMEOUT, remaining)) as response:
        data = response.read(limit + 1)
        if len(data) > limit:
            raise ValueError("RESPONSE_TOO_LARGE")
        return data

def valid_endpoint(value):
    if not isinstance(value, str) or len(value) > 500:
        return False
    try:
        p = urlsplit(value)
        return (
            p.scheme == "https" and bool(p.hostname)
            and not p.username and not p.password
            and p.port in (None, 443)
            and p.path in ("", "/")
            and not p.query and not p.fragment
        )
    except ValueError:
        return False

def save_atomic(data):
    STATE.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".iao-github-", dir=str(STATE))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, OUTPUT)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def discover():
    global DEADLINE
    DEADLINE = time.monotonic() + GLOBAL_BUDGET_SECONDS
    repos = {}
    errors = []
    search_counts = {}

    for term in SEARCHES:
        if time.monotonic() >= DEADLINE:
            errors.append("GLOBAL_DISCOVERY_DEADLINE_SEARCH")
            break
        params = urllib.parse.urlencode({
            "q": term,
            "sort": "updated",
            "order": "desc",
            "per_page": str(MAX_REPOS),
        })
        try:
            data = json.loads(get(
                "https://api.github.com/search/repositories?" + params,
                MAX_RESPONSE
            ))
            items = data.get("items", [])
            search_counts[term] = len(items)
            for repo in items:
                name = repo.get("full_name")
                branch = repo.get("default_branch")
                if (
                    isinstance(name, str)
                    and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", name)
                    and isinstance(branch, str)
                ):
                    repos[name] = repo
        except urllib.error.HTTPError as exc:
            errors.append(term + ":HTTP_" + str(exc.code))
        except Exception as exc:
            errors.append(term + ":" + type(exc).__name__)

    candidates = {}
    checked = 0

    for name, repo in repos.items():
        if time.monotonic() >= DEADLINE:
            errors.append("GLOBAL_DISCOVERY_DEADLINE_MANIFESTS")
            break
        if checked >= MAX_MANIFEST_CHECKS:
            break
        checked += 1
        branch = urllib.parse.quote(repo["default_branch"], safe="")
        manifest_url = (
            "https://raw.githubusercontent.com/" + name + "/" + branch
            + "/.well-known/iao-federation.json"
        )
        try:
            manifest = json.loads(get(manifest_url, MAX_MANIFEST))
            endpoint = manifest.get("endpoint")
            if not valid_endpoint(endpoint):
                continue
            offer = manifest.get("service_offer")
            candidates[endpoint.rstrip("/")] = {
                "repository": name,
                "repository_url": repo.get("html_url"),
                "manifest_url": manifest_url,
                "endpoint": endpoint.rstrip("/"),
                "node_id": manifest.get("node_id"),
                "protocol": manifest.get("protocol"),
                "offer_present": isinstance(offer, dict),
                "offer": offer if isinstance(offer, dict) else None,
                "discovered_at": datetime.now(timezone.utc).isoformat(),
                "status": "DISCOVERED_UNVERIFIED",
                "enrolled": False,
                "capability_exchange": False,
            }
        except urllib.error.HTTPError as exc:
            if exc.code not in (404, 410):
                errors.append(name + ":HTTP_" + str(exc.code))
        except Exception as exc:
            errors.append(name + ":" + type(exc).__name__)

    previous = {}
    if OUTPUT.exists():
        try:
            old = json.loads(OUTPUT.read_text(encoding="utf-8"))
            for item in old.get("candidates", []):
                if isinstance(item, dict) and valid_endpoint(item.get("endpoint")):
                    previous[item["endpoint"].rstrip("/")] = item
        except Exception:
            errors.append("previous_registry_unreadable")

    previous.update(candidates)
    report = {
        "version": 3,
        "source": "GitHub public repository search",
        "searches": list(SEARCHES),
        "search_results": search_counts,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "repositories_found": len(repos),
        "repositories": [
            {
                "name": repo.get("full_name"),
                "url": repo.get("html_url"),
                "default_branch": repo.get("default_branch"),
                "description": repo.get("description"),
                "language": repo.get("language"),
                "topics": repo.get("topics", []),
                "source": "GitHub public repository search",
            }
            for repo in repos.values()
            if isinstance(repo.get("full_name"), str)
            and isinstance(repo.get("html_url"), str)
        ],
        "manifests_checked": checked,
        "discovery_budget_seconds": GLOBAL_BUDGET_SECONDS,
        "manifest_check_limit": MAX_MANIFEST_CHECKS,
        "manifest_candidates_this_run": len(candidates),
        "candidate_total_persisted": len(previous),
        "errors": errors[:40],
        "candidates": list(previous.values()),
        "enrollment_performed": False,
        "capability_exchange_performed": False,
    }
    save_atomic(report)
    return report

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--interval", type=int, default=43200)
    args = parser.parse_args()

    if args.status:
        print(OUTPUT.read_text(encoding="utf-8")
              if OUTPUT.exists() else "DISCOVERY_NOT_RUN")
        return 0

    if args.interval < 300:
        parser.error("interval mínimo: 300 segundos")

    if args.once:
        report = discover()
        print(json.dumps(
            {k: v for k, v in report.items() if k != "candidates"},
            ensure_ascii=False, indent=2
        ))
        print("REGISTRY:", OUTPUT)
        return 0

    while True:
        try:
            r = discover()
            print(
                datetime.now(timezone.utc).isoformat(),
                "repositorios=", r["repositories_found"],
                "manifiestos=", r["manifests_checked"],
                "candidatos=", r["manifest_candidates_this_run"],
                "errores=", len(r["errors"]),
                flush=True
            )
        except Exception as exc:
            print("DISCOVERY_ERROR:", type(exc).__name__, flush=True)
        time.sleep(args.interval)

if __name__ == "__main__":
    raise SystemExit(main())
