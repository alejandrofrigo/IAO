#!/usr/bin/env python3
"""Pruebas HTTPS GET sin credenciales para APIs documentadas."""
import json
import tempfile
import os
import urllib.request
import urllib.error
import urllib.parse
import ssl
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / ".state/iao-universal-registry.json"
REPORT = ROOT / ".state/iao-api-endpoint-probes.json"
TIMEOUT = 10

def utc():
    return datetime.now(timezone.utc).isoformat()

class SameHostRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old = urllib.parse.urlparse(req.full_url)
        new = urllib.parse.urlparse(newurl)
        if new.scheme != "https" or new.hostname != old.hostname:
            raise urllib.error.URLError("REDIRECT_OUTSIDE_ORIGIN_BLOCKED")
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def atomic(path, data):
    fd, tmp = tempfile.mkstemp(prefix=".iao-api-probe-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def probe(item):
    base = item["url"].rstrip("/")
    url = base + "/models"
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return {"status": "REJECTED_INVALID_HTTPS_URL"}

    req = urllib.request.Request(url, headers={
        "Accept": "application/json",
        "User-Agent": "IAO-ReadOnly-API-Probe/1.0",
    }, method="GET")
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        SameHostRedirect(),
    )
    try:
        with opener.open(req, timeout=TIMEOUT) as response:
            body = response.read(2048).decode("utf-8", "replace")
            return {
                "status": "HTTP_RESPONSE",
                "http_status": response.status,
                "content_type": response.headers.get("Content-Type"),
                "body_preview": body[:500],
                "interface_evidence": "HTTP_GET_MODELS_RESPONSE",
            }
    except urllib.error.HTTPError as exc:
        try:
            preview = exc.read(1024).decode("utf-8", "replace")
        except Exception:
            preview = ""
        if exc.code in (401, 403):
            status = "REACHABLE_AUTH_REQUIRED"
        elif exc.code == 404:
            status = "REACHABLE_MODELS_PATH_NOT_FOUND"
        else:
            status = "HTTP_ERROR"
        return {
            "status": status,
            "http_status": exc.code,
            "content_type": exc.headers.get("Content-Type"),
            "body_preview": preview[:300],
        }
    except Exception as exc:
        return {
            "status": "CONNECTION_ERROR",
            "error_type": type(exc).__name__,
            "error": str(exc)[:180],
        }

def main():
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    targets = [
        x for x in registry.get("resources", [])
        if isinstance(x, dict) and x.get("kind") == "api"
        and x.get("stage") == "DISCOVERED"
    ]
    previous = {}
    if REPORT.exists():
        previous = json.loads(REPORT.read_text(encoding="utf-8")).get("results", {})
    results = previous.copy()

    print("API_CANDIDATES:", len(targets))
    for item in targets:
        rid = item.get("id")
        if not rid:
            continue
        print("PROBING:", item.get("url"))
        result = probe(item)
        results[rid] = {
            "resource_id": rid,
            "name": item.get("name"),
            "url": item.get("url"),
            "checked_at": utc(),
            **result,
            "credentials_used": False,
            "permission_established": False,
            "assimilation_confirmed": False,
        }
        print("RESULT:", result["status"],
              "HTTP:", result.get("http_status", "n/a"))

    report = {
        "schema": "IAO_API_ENDPOINT_PROBES_V1",
        "updated_at": utc(),
        "method": "HTTPS GET /models; no credentials; same-origin redirects only",
        "results": results,
        "assimilation_count": 0,
    }
    atomic(REPORT, report)
    print("PROBE_RESULTS:", len(results))
    print("ASSIMILATED:", 0)
    print("REPORT:", REPORT.relative_to(ROOT))

if __name__ == "__main__":
    main()
