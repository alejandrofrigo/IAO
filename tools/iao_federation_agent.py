#!/usr/bin/env python3
"""IAO federation agent: authorized discovery and Ed25519 identity verification."""
from __future__ import annotations

import hashlib
import json
import secrets
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".state"
NODES = STATE / "iao-external-nodes.json"
REPORT = STATE / "iao-federation-agent-report.json"
MAX_RESPONSE = 65536
TIMEOUT = 8.0

sys.path.insert(0, str(ROOT))
from omega.federation import verify_identity_challenge  # noqa: E402


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect())


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_nodes() -> dict:
    if not NODES.is_file():
        return {"status": "MISSING", "nodes": [], "ignored": 0}
    try:
        data = json.loads(NODES.read_text(encoding="utf-8"))
    except Exception:
        return {"status": "INVALID_JSON", "nodes": [], "ignored": 0}
    if not isinstance(data, dict) or not isinstance(data.get("nodes"), list):
        return {"status": "INVALID_SCHEMA", "nodes": [], "ignored": 0}

    safe, ignored = [], 0
    for item in data["nodes"]:
        if not isinstance(item, dict) or item.get("authorized") is not True:
            ignored += 1
            continue
        url = item.get("url") or item.get("endpoint") or item.get("base_url")
        expected = item.get("id", item.get("node_id"))
        if (
            not isinstance(url, str)
            or not isinstance(expected, str)
            or len(expected) != 16
            or any(ch not in "0123456789abcdef" for ch in expected)
        ):
            ignored += 1
            continue
        try:
            u = urlsplit(url)
            valid = (
                u.scheme == "https" and bool(u.hostname)
                and not u.username and not u.password
                and (u.port is None or u.port == 443)
                and not u.query and not u.fragment
                and u.path in ("", "/", "/fed/v1/message")
            )
        except ValueError:
            valid = False
        if not valid:
            safe.append({
                "url": url,
                "id": expected[:100],
                "authorized": True,
                "precheck": "URL_REJECTED",
            })
            continue
        origin = urlunsplit((u.scheme, u.netloc, "", "", ""))
        safe.append({
            "url": origin,
            "id": expected[:100],
            "authorized": True,
            "precheck": "URL_ACCEPTED",
        })
    return {"status": "VALID", "nodes": safe, "ignored": ignored}


def request_json(url: str, method: str = "GET", body: dict | None = None) -> dict:
    data = None if body is None else json.dumps(
        body, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={"Accept": "application/json",
                 "Content-Type": "application/json"},
    )
    with OPENER.open(req, timeout=TIMEOUT) as response:
        if not response.geturl().startswith("https://"):
            raise ValueError("HTTPS_REDIRECT_REFUSED")
        raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise ValueError("RESPONSE_TOO_LARGE")
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("INVALID_JSON_OBJECT")
        return value


def verify_node(node: dict) -> dict:
    if node.get("precheck") != "URL_ACCEPTED":
        return {"verdict": "REJECTED", "reason": "INVALID_CONFIGURED_URL"}

    origin = node["url"]
    result = {
        "configured_id": node["id"],
        "host": urlsplit(origin).hostname,
        "transport": "HTTPS_REQUIRED",
        "identity": "NOT_TESTED",
        "challenge": "NOT_TESTED",
        "enrollment": "NOT_PERFORMED",
    }
    try:
        identity = request_json(origin + "/fed/v1/identity")
        result["identity"] = "RECEIVED"

        requester_id = secrets.token_hex(8)
        nonce = secrets.token_hex(32)
        request_ts = datetime.now(timezone.utc).timestamp()
        challenge = {
            "v": 1,
            "from": requester_id,
            "to": identity.get("node_id"),
            "nonce": nonce,
            "ts": request_ts,
        }
        response = request_json(
            origin + "/fed/v1/handshake", "POST", challenge
        )

        verified = verify_identity_challenge(
            identity,
            response,
            requester_id=requester_id,
            nonce=nonce,
            request_ts=request_ts,
            now=datetime.now(timezone.utc).timestamp(),
            skew=60.0,
        )
        if not verified.get("ok"):
            result.update({
                "verdict": "IDENTITY_REJECTED",
                "challenge": "FAILED",
                "reason": verified.get("error", "IDENTITY_VERIFICATION_FAILED"),
            })
            return result

        actual_id = verified["peer_id"]
        expected = node["id"]
        if len(expected) == 16 and all(c in "0123456789abcdef" for c in expected):
            if expected != actual_id:
                result.update({
                    "verdict": "IDENTITY_MISMATCH",
                    "challenge": "PASSED",
                    "actual_node_id": actual_id,
                    "reason": "CONFIGURED_ID_DOES_NOT_MATCH_CRYPTOGRAPHIC_ID",
                })
                return result

        result.update({
            "verdict": "IDENTITY_VERIFIED",
            "challenge": "PASSED",
            "actual_node_id": actual_id,
            "protocol": identity.get("protocol"),
            "protocol_version": identity.get("version"),
            "enrollment": "NOT_PERFORMED",
            "capabilities": "NOT_TESTED",
        })
        return result

    except urllib.error.HTTPError as exc:
        result.update({"verdict": "HTTP_ERROR", "http_status": exc.code})
    except urllib.error.URLError as exc:
        result.update({
            "verdict": "UNREACHABLE",
            "error_class": type(exc.reason).__name__,
        })
    except Exception as exc:
        result.update({
            "verdict": "FAILED",
            "error_class": type(exc).__name__,
            "reason": str(exc)[:180],
        })
    return result


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "status"
    if mode not in ("status", "probe"):
        print("Uso: python tools/iao_federation_agent.py [status|probe]")
        return 2

    cfg = load_nodes()
    report = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "agent": "IAO Federation Identity Agent",
        "mode": mode.upper(),
        "config_status": cfg["status"],
        "authorized_node_count": len(cfg["nodes"]),
        "ignored_unauthorized_count": cfg["ignored"],
        "results": [],
        "enrollment_performed": False,
        "capability_exchange_performed": False,
        "secrets_printed": False,
    }

    if mode == "probe":
        for node in cfg["nodes"]:
            report["results"].append(verify_node(node))

    STATE.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    print("IAO FEDERATION IDENTITY AGENT")
    print("MODE=" + mode.upper())
    print("CONFIG_STATUS=" + cfg["status"])
    print("AUTHORIZED_NODE_COUNT=" + str(len(cfg["nodes"])))
    print("IGNORED_UNAUTHORIZED_COUNT=" + str(cfg["ignored"]))
    for index, item in enumerate(report["results"], 1):
        print("NODE_%d=%s" % (index, json.dumps(item, sort_keys=True)))
    print("ENROLLMENT_PERFORMED=False")
    print("REPORT_PATH=" + str(REPORT))
    print("REPORT_SHA256=" + sha(REPORT))
    return 0 if cfg["status"] == "VALID" else 2


if __name__ == "__main__":
    raise SystemExit(main())
