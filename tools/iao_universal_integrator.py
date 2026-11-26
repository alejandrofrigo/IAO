#!/usr/bin/env python3
"""Exploración documental profunda de APIs; no ejecuta código externo."""
import base64
import hashlib
import json
import os
import re
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".state"
REGISTRY = STATE / "iao-universal-registry.json"
EVALUATION = STATE / "iao-universal-evaluation.json"
REPORT = STATE / "iao-universal-integration-discovery.json"
LIMIT = 12
TIMEOUT = 15
HEADERS = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "IAO-Universal-Integrator/1.1",
    "X-GitHub-Api-Version": "2022-11-28",
}

def utc():
    return datetime.now(timezone.utc).isoformat()

def get_json(url):
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        if r.status != 200:
            raise RuntimeError("HTTP_" + str(r.status))
        return json.loads(r.read(2_000_000).decode("utf-8"))

def decode_blob(url):
    data = get_json(url)
    if data.get("encoding") != "base64":
        return ""
    return base64.b64decode(data.get("content", "")).decode("utf-8", "replace")

def valid_endpoint(value):
    if not isinstance(value, str) or len(value) > 1500:
        return False
    try:
        u = urllib.parse.urlparse(value.strip())
        return (
            u.scheme == "https" and bool(u.hostname)
            and not u.username and not u.password
            and not u.query and not u.fragment
        )
    except Exception:
        return False

def extract_openapi(content):
    found = []
    try:
        obj = json.loads(content)
        if isinstance(obj, dict):
            for server in obj.get("servers", []):
                if isinstance(server, dict) and valid_endpoint(server.get("url")):
                    found.append((server["url"].strip().rstrip("/"), "openapi_servers"))
    except Exception:
        active = False
        for line in content.splitlines():
            if re.match(r"^\s*servers\s*:\s*$", line):
                active = True
                continue
            if active and re.match(r"^\S", line):
                break
            if active:
                m = re.match(r"^\s*-\s*url\s*:\s*['\"]?([^'\"\s#]+)", line)
                if m and valid_endpoint(m.group(1)):
                    found.append((m.group(1).rstrip("/"), "openapi_yaml_servers"))
    return found

def extract_documented_urls(content):
    found = set()
    patterns = [
        r"(?i)(?:api\s*(?:base\s*)?url|base\s*url|endpoint|graphql)\s*[:=]\s*[`'\"]?(https://[^\s`'\"<>),]+)",
        r"(?i)(https://[a-z0-9.-]+(?::\d+)?/(?:api|v\d+|graphql)(?:/[a-z0-9_./{}-]*)?)",
    ]
    for pattern in patterns:
        for match in re.findall(pattern, content):
            value = match.rstrip(".,;)")
            if valid_endpoint(value):
                found.add(value.rstrip("/"))
    return [(x, "documented_api_url") for x in sorted(found)]

def atomic(path, data):
    fd, tmp = tempfile.mkstemp(prefix=".iao-deep-scan-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def main():
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    evaluation = json.loads(EVALUATION.read_text(encoding="utf-8"))
    resources = registry.get("resources", [])
    evaluations = evaluation.get("evaluations", {})
    candidates = [
        (rid, r) for rid, r in evaluations.items()
        if r.get("status") == "REPOSITORY_ACCESSIBLE"
        and r.get("public") is True and not r.get("archived")
        and not r.get("disabled")
    ][:LIMIT]

    known = {x.get("id") for x in resources if isinstance(x, dict)}
    discovered, errors = [], []
    scanned = 0

    print("REPOSITORIES_SELECTED:", len(candidates))
    for rid, result in candidates:
        parsed = urllib.parse.urlparse(result.get("url", ""))
        parts = [p for p in parsed.path.strip("/").split("/") if p]
        if parsed.hostname != "github.com" or len(parts) < 2:
            continue
        owner, repo = parts[0], parts[1].removesuffix(".git")
        base = "https://api.github.com/repos/" + owner + "/" + repo
        print("DEEP_SCAN:", owner + "/" + repo)
        try:
            meta = get_json(base)
            branch = urllib.parse.quote(meta.get("default_branch") or "main", safe="")
            tree = get_json(base + "/git/trees/" + branch + "?recursive=1")
            entries = tree.get("tree", [])
            if not isinstance(entries, list):
                entries = []
            files = [
                x for x in entries if isinstance(x, dict)
                and x.get("type") == "blob" and x.get("url")
            ]
            specs = [
                x for x in files
                if re.search(r"(openapi|swagger).*\.(json|ya?ml)$", x.get("path", ""), re.I)
            ][:6]
            docs = [
                x for x in files
                if re.search(r"(^|/)(readme|api|docs?)([^/]*\.(md|rst|txt))?$",
                             x.get("path", ""), re.I)
                and re.search(r"\.(md|rst|txt)$", x.get("path", ""), re.I)
            ][:5]

            found = []
            for spec in specs:
                try:
                    content = decode_blob(spec["url"])
                    for endpoint, method in extract_openapi(content):
                        found.append((endpoint, method, spec["path"]))
                except Exception as exc:
                    errors.append(owner + "/" + repo + ":SPEC_" + type(exc).__name__)

            for doc in docs:
                try:
                    content = decode_blob(doc["url"])
                    for endpoint, method in extract_documented_urls(content):
                        found.append((endpoint, method, doc["path"]))
                except Exception as exc:
                    errors.append(owner + "/" + repo + ":DOC_" + type(exc).__name__)

            for endpoint, method, source_file in found:
                eid = hashlib.sha256(("api|" + endpoint).encode()).hexdigest()[:20]
                if eid in known:
                    continue
                resources.append({
                    "id": eid,
                    "name": owner + "/" + repo + " documented API",
                    "kind": "api",
                    "url": endpoint,
                    "adapter": "rest_openapi" if "openapi" in method else "rest_documented",
                    "capabilities": [],
                    "permission_status": "unknown",
                    "stage": "DISCOVERED",
                    "checks": {
                        "identity_verified": False,
                        "permission_verified": False,
                        "adapter_tested": False,
                        "real_exchange_confirmed": False,
                    },
                    "evidence": [{
                        "type": method,
                        "repository": result.get("url"),
                        "source_file": source_file,
                        "observed_at": utc(),
                    }],
                    "integration_status": "ENDPOINT_DISCOVERED_NOT_PROBED",
                    "created_at": utc(),
                    "updated_at": utc(),
                })
                known.add(eid)
                discovered.append({
                    "resource_id": eid,
                    "repository": owner + "/" + repo,
                    "endpoint": endpoint,
                    "source_file": source_file,
                    "discovery_method": method,
                    "status": "DISCOVERED_NOT_ASIMILATED",
                })
                print("ENDPOINT_CANDIDATE:", endpoint, "|", source_file)
            scanned += 1
            print("FILES_INSPECTED:", len(files), "SPECS:", len(specs), "DOCS:", len(docs))
        except urllib.error.HTTPError as exc:
            errors.append(owner + "/" + repo + ":HTTP_" + str(exc.code))
            print("HTTP_ERROR:", exc.code)
            if exc.code in (403, 429):
                print("RATE_LIMIT; BATCH_STOPPED")
                break
        except Exception as exc:
            errors.append(owner + "/" + repo + ":" + type(exc).__name__)
            print("SCAN_ERROR:", type(exc).__name__)

    registry["resources"] = resources
    registry["updated_at"] = utc()
    atomic(REGISTRY, registry)
    report = {
        "schema": "IAO_UNIVERSAL_INTEGRATION_DISCOVERY_V2",
        "updated_at": utc(),
        "repositories_scanned": scanned,
        "api_endpoints_discovered": discovered,
        "errors": errors,
        "external_code_executed": False,
        "endpoints_probed": False,
        "resources_asimilated": 0,
    }
    atomic(REPORT, report)
    print("REPOSITORIES_SCANNED:", scanned)
    print("ENDPOINT_CANDIDATES:", len(discovered))
    print("RESOURCES_ASIMILATED: 0")
    print("EXTERNAL_CODE_EXECUTED: NO")
    print("REPORT_VALID: YES")

if __name__ == "__main__":
    main()
