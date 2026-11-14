#!/usr/bin/env python3
"""Verify discovered IAO candidates against operator-pinned Ed25519 IDs."""
from __future__ import annotations

import argparse
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
sys.path.insert(0, str(ROOT))

from omega.federation_assimilation import CandidateRegistry  # noqa: E402
from tools.iao_federation_binding import verify_binding  # noqa: E402

STATE = ROOT / ".state"
REGISTRY = STATE / "iao-federation-candidates.json"
PIN_FILE = STATE / "iao-federation-expected.json"
REPORT = STATE / "iao-federation-candidate-verification.json"
TIMEOUT = 8
MAX_RESPONSE = 65536


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect())


def load_pins() -> dict[str, str]:
    if not PIN_FILE.is_file():
        return {}
    if PIN_FILE.is_symlink():
        raise ValueError("PIN_FILE_SYMLINK_REFUSED")

    data = json.loads(PIN_FILE.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("nodes"), list):
        raise ValueError("PIN_FILE_SCHEMA_INVALID")

    pins = {}
    for item in data["nodes"]:
        if not isinstance(item, dict):
            raise ValueError("PIN_RECORD_INVALID")
        endpoint = item.get("endpoint")
        expected = item.get("expected_node_id")
        if not isinstance(endpoint, str) or not isinstance(expected, str):
            raise ValueError("PIN_RECORD_FIELDS_INVALID")
        if len(expected) != 16 or any(c not in "0123456789abcdef" for c in expected):
            raise ValueError("PIN_EXPECTED_ID_INVALID")
        if endpoint in pins:
            raise ValueError("DUPLICATE_PIN_ENDPOINT")
        pins[endpoint] = expected
    return pins


def request_json(url: str, method: str = "GET", body: dict | None = None) -> dict:
    data = None if body is None else json.dumps(
        body, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    with OPENER.open(req, timeout=TIMEOUT) as response:
        if response.geturl() != url:
            raise ValueError("REDIRECT_OR_URL_CHANGE_REFUSED")
        raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise ValueError("RESPONSE_TOO_LARGE")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("INVALID_JSON_OBJECT")
    return value


def verify_candidate(candidate: dict, expected_id: str, registry: CandidateRegistry) -> dict:
    endpoint = candidate["endpoint"]
    parsed = urlsplit(endpoint)
    origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))

    result = {
        "candidate_id": candidate["candidate_id"],
        "endpoint_sha256": hashlib.sha256(endpoint.encode()).hexdigest(),
        "expected_node_id": expected_id,
        "verdict": "NOT_VERIFIED",
        "enrollment_performed": False,
        "authorization_granted": False,
    }

    try:
        identity = request_json(origin + "/fed/v1/identity")
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
            origin + "/fed/v1/handshake",
            "POST",
            challenge,
        )
        checked = verify_binding(
            identity,
            response,
            expected_node_id=expected_id,
            requester_id=requester_id,
            nonce=nonce,
            request_ts=request_ts,
            now=datetime.now(timezone.utc).timestamp(),
            skew=60.0,
        )
        if checked.get("ok"):
            evidence = {
                "identity": identity,
                "response": response,
                "requester_id": requester_id,
                "nonce": nonce,
                "request_ts": request_ts,
                "transport": {
                    "https_verified": True,
                    "redirected": False,
                },
            }
            saved = registry.record_verified_identity(
                candidate["candidate_id"],
                expected_node_id=expected_id,
                evidence=evidence,
            )
            result.update({
                "verdict": "IDENTITY_VERIFIED_PENDING_AUTHORIZATION",
                "actual_node_id": checked["peer_id"],
                "protocol": identity.get("protocol"),
                "protocol_version": identity.get("version"),
                "registry_status": saved["status"],
                "authorized": saved["authorized"],
                "authorized_by": saved["authorized_by"],
                "policy_decision": saved["authorization_policy"]["decision"],
                "evidence_sha256": saved["verification_evidence"]["evidence_sha256"],
                "authorization_granted": False,
                "enrollment_performed": False,
            })
        else:
            result.update({
                "verdict": "IDENTITY_REJECTED",
                "reason": checked.get("error", "VERIFICATION_FAILED"),
            })
    except urllib.error.HTTPError as exc:
        result.update({
            "verdict": "HTTP_ERROR",
            "http_status": exc.code,
        })
    except urllib.error.URLError as exc:
        result.update({
            "verdict": "UNREACHABLE",
            "error_class": type(exc.reason).__name__,
        })
    except Exception as exc:
        result.update({
            "verdict": "FAILED",
            "error_class": type(exc).__name__,
            "reason": str(exc)[:160],
        })
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode",
        choices=("status", "probe"),
        nargs="?",
        default="status",
    )
    args = parser.parse_args()

    STATE.mkdir(parents=True, exist_ok=True)
    registry = CandidateRegistry(REGISTRY)
    candidates = registry.list_candidates()
    pins = load_pins()

    print("IAO FEDERATION CANDIDATE VERIFIER")
    print("MODE=" + args.mode.upper())
    print("CANDIDATE_COUNT=" + str(len(candidates)))
    print("PINNED_ENDPOINT_COUNT=" + str(len(pins)))

    if args.mode == "status":
        for item in candidates:
            print(json.dumps({
                "candidate_id": item["candidate_id"],
                "status": item["status"],
                "authorized": item["authorized"],
                "has_expected_identity": item["endpoint"] in pins,
            }, sort_keys=True))
        print("NETWORK_PROBES=0")
        return 0

    results = []
    for candidate in candidates:
        expected = pins.get(candidate["endpoint"])
        if expected is None:
            results.append({
                "candidate_id": candidate["candidate_id"],
                "verdict": "SKIPPED_NO_OPERATOR_PIN",
                "enrollment_performed": False,
                "authorization_granted": False,
            })
            continue
        results.append(verify_candidate(candidate, expected, registry))

    report = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "mode": "PROBE",
        "results": results,
        "enrollment_performed": False,
        "authorization_granted": False,
        "capability_exchange_performed": False,
    }
    temp = REPORT.with_suffix(".tmp")
    temp.write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    temp.replace(REPORT)

    for index, item in enumerate(results, 1):
        print("RESULT_%d=" % index + json.dumps(item, sort_keys=True))

    print("REPORT_PATH=" + str(REPORT))
    print("IDENTITY_VERIFIED_PENDING_AUTHORIZATION_COUNT=" + str(sum(
        x.get("verdict") == "IDENTITY_VERIFIED_PENDING_AUTHORIZATION"
        for x in results
    )))
    print("ENROLLMENT_PERFORMED=False")
    print("AUTHORIZATION_GRANTED=False")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
