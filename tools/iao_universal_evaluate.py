#!/usr/bin/env python3
"""Evaluador seguro de repositorios GitHub. No ejecuta código externo."""
import json
import os
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / ".state/iao-universal-registry.json"
REPORT = ROOT / ".state/iao-universal-evaluation.json"
LIMIT = 12
TIMEOUT = 12

def utc():
    return datetime.now(timezone.utc).isoformat()

def read_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default

def save_atomic(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".iao-eval-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def api_get(url):
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "IAO-Universal-Evaluator/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
        if response.status != 200:
            raise RuntimeError("HTTP_" + str(response.status))
        return json.loads(response.read(1024 * 1024).decode("utf-8"))

def repo_path(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "github.com":
        return None
    parts = [x for x in parsed.path.strip("/").split("/") if x]
    if len(parts) < 2 or any(x in (".", "..") for x in parts[:2]):
        return None
    return parts[0], parts[1].removesuffix(".git")

def inspect(item):
    parts = repo_path(item.get("url", ""))
    if not parts:
        return {"status": "UNSUPPORTED_URL", "checked_at": utc()}

    owner, repo = parts
    base = "https://api.github.com/repos/" + urllib.parse.quote(owner) + "/" + urllib.parse.quote(repo)
    meta = api_get(base)
    root = api_get(base + "/contents")
    if not isinstance(root, list):
        root = []

    names = {
        str(x.get("name", "")).lower()
        for x in root if isinstance(x, dict)
    }
    hints = []
    if names & {"openapi.json", "openapi.yaml", "openapi.yml", "swagger.json", "swagger.yaml"}:
        hints.append("openapi_spec_present")
    if any("mcp" in x for x in names):
        hints.append("mcp_related_file_present")
    if names & {"dockerfile", "compose.yaml", "docker-compose.yml"}:
        hints.append("container_configuration_present")
    if names & {"pyproject.toml", "package.json", "go.mod", "cargo.toml"}:
        hints.append("project_source_present")
    if names & {"readme.md", "readme.rst", "readme"}:
        hints.append("readme_present")
    if names & {"server.py", "server.js", "main.py", "app.py", "index.js"}:
        hints.append("possible_service_entrypoint")

    return {
        "status": "REPOSITORY_ACCESSIBLE",
        "checked_at": utc(),
        "canonical_url": meta.get("html_url"),
        "default_branch": meta.get("default_branch"),
        "description": meta.get("description"),
        "language": meta.get("language"),
        "topics": meta.get("topics", []),
        "archived": bool(meta.get("archived")),
        "disabled": bool(meta.get("disabled")),
        "public": meta.get("private") is False,
        "root_files_checked": len(root),
        "integration_evidence": hints,
        "integration_status": "NEEDS_ADAPTER_TEST",
        "permission_status": "NOT_ESTABLISHED",
        "real_exchange_confirmed": False,
    }

def main():
    registry = read_json(REGISTRY, {})
    resources = registry.get("resources", [])
    report = read_json(REPORT, {
        "schema": "IAO_UNIVERSAL_EVALUATION_V1",
        "created_at": utc(),
        "updated_at": utc(),
        "evaluations": {},
    })
    evaluations = report.setdefault("evaluations", {})
    from datetime import datetime, timezone

    def age_seconds(record):
        try:
            stamp = datetime.fromisoformat(record["checked_at"].replace("Z", "+00:00"))
            return (datetime.now(timezone.utc) - stamp).total_seconds()
        except Exception:
            return 10**12

    retryable = {"HTTP_ERROR", "CHECK_ERROR"}
    batch = []
    retry_pending = 0
    stale_pending = 0
    for item in resources:
        if not isinstance(item, dict) or item.get("kind") != "repository":
            continue
        rid = item.get("id")
        previous = evaluations.get(rid)
        if previous is None:
            batch.append(item)
        elif previous.get("status") in retryable:
            if age_seconds(previous) >= 900:
                batch.append(item)
            else:
                retry_pending += 1
        elif age_seconds(previous) >= 604800:
            batch.append(item)
            stale_pending += 1
        if len(batch) >= LIMIT:
            break

    print("REGISTRY_REPOSITORIES:", sum(
        isinstance(x, dict) and x.get("kind") == "repository"
        for x in resources
    ))
    print("PREVIOUSLY_EVALUATED:", len(evaluations))
    print("RETRYABLE_WAITING_FOR_BACKOFF:", retry_pending)
    print("STALE_REFRESH_SELECTED:", stale_pending)
    print("BATCH_LIMIT:", LIMIT)

    checked = 0
    for item in batch:
        rid = item.get("id")
        print("CHECKING:", item.get("name", rid))
        try:
            result = inspect(item)
            evaluations[rid] = {
                "resource_id": rid,
                "name": item.get("name"),
                "url": item.get("url"),
                **result,
            }
            checked += 1
            print("RESULT:", result["status"],
                  "EVIDENCE:", len(result.get("integration_evidence", [])))
        except urllib.error.HTTPError as exc:
            if exc.code == 403 or exc.code == 429:
                print("GITHUB_RATE_LIMIT_OR_FORBIDDEN:", exc.code)
                break
            evaluations[rid] = {
                "resource_id": rid,
                "name": item.get("name"),
                "url": item.get("url"),
                "status": "HTTP_ERROR",
                "http_status": exc.code,
                "checked_at": utc(),
            }
            checked += 1
        except Exception as exc:
            evaluations[rid] = {
                "resource_id": rid,
                "name": item.get("name"),
                "url": item.get("url"),
                "status": "CHECK_ERROR",
                "error_type": type(exc).__name__,
                "checked_at": utc(),
            }
            checked += 1
        report["updated_at"] = utc()
        save_atomic(REPORT, report)
        time.sleep(0.4)

    report["updated_at"] = utc()
    save_atomic(REPORT, report)

    counts = {}
    evidence = {}
    for result in evaluations.values():
        status = result.get("status", "UNKNOWN")
        counts[status] = counts.get(status, 0) + 1
        for hint in result.get("integration_evidence", []):
            evidence[hint] = evidence.get(hint, 0) + 1

    print("BATCH_CHECKED:", checked)
    print("TOTAL_EVALUATED:", len(evaluations))
    print("STATUS_COUNTS:", json.dumps(counts, sort_keys=True))
    print("TECHNICAL_EVIDENCE:", json.dumps(evidence, sort_keys=True))
    print("REPORT:", REPORT.relative_to(ROOT))
    print("REGISTRY_MODIFIED: NO")
    print("CODE_EXECUTED_FROM_EXTERNAL_REPOSITORIES: NO")

if __name__ == "__main__":
    main()
