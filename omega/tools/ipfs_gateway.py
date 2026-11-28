"""Verified, read-only IPFS DAG-JSON retrieval through explicitly trusted gateways.

This adapter accepts only CIDv1 DAG-JSON blocks using sha2-256. Gateway hosts
are operator-configured and fetched through the shared SSRF-safe egress layer.
Retrieved bytes remain untrusted content; this tool grants no peer authority.
"""
from __future__ import annotations

import base64
import hashlib
import re
from typing import Any
from urllib.parse import urlsplit

from omega.tools.registry import ToolSpec

_MAX_BYTES = 512_000
_MAX_GATEWAYS = 8
_CID_RE = re.compile(r"^b[a-z2-7]{20,120}$")


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while offset < len(data) and shift <= 63:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
    raise ValueError("INVALID_CID")


def _cid_digest(cid: str) -> bytes:
    if not isinstance(cid, str) or not _CID_RE.fullmatch(cid):
        raise ValueError("CIDV1_DAG_JSON_REQUIRED")
    try:
        raw = base64.b32decode(cid[1:].upper() + "=" * ((8 - len(cid[1:]) % 8) % 8))
        version, offset = _read_varint(raw, 0)
        codec, offset = _read_varint(raw, offset)
        hash_code, offset = _read_varint(raw, offset)
        digest_len, offset = _read_varint(raw, offset)
    except (ValueError, base64.binascii.Error):
        raise ValueError("INVALID_CID") from None
    if (version != 1 or codec != 0x0129 or hash_code != 0x12
            or digest_len != 32 or len(raw) != offset + digest_len):
        raise ValueError("CIDV1_DAG_JSON_SHA256_REQUIRED")
    return raw[offset:]


def _gateway_hosts(values: Any) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        raise ValueError("INVALID_GATEWAY_CONFIGURATION")
    hosts: list[str] = []
    for value in values[:_MAX_GATEWAYS]:
        if not isinstance(value, str) or not value or len(value) > 253:
            continue
        parsed = urlsplit("https://" + value)
        host = (parsed.hostname or "").lower().rstrip(".")
        if (parsed.scheme == "https" and parsed.netloc.lower() == value.lower()
                and host and parsed.port in (None, 443)
                and not parsed.username and not parsed.password
                and parsed.path == "" and not parsed.query and not parsed.fragment
                and re.fullmatch(r"[a-z0-9.-]+", host)):
            if host not in hosts:
                hosts.append(host)
    if not hosts:
        raise ValueError("NO_VALID_IPFS_GATEWAYS")
    return tuple(hosts)


def make_ipfs_fetch(gateway_hosts: Any) -> ToolSpec:
    """Build the optional ipfs.fetch read-only tool for configured HTTPS gateways."""
    hosts = _gateway_hosts(gateway_hosts)

    def validate(raw: Any) -> dict[str, str]:
        if not isinstance(raw, dict) or set(raw) != {"cid"}:
            raise ValueError("INVALID_INPUT")
        cid = raw.get("cid")
        _cid_digest(cid)
        return {"cid": cid}

    def run(inp: dict[str, Any]) -> dict[str, Any]:
        from omega.egress import EgressDenied, EgressPolicy, fetch

        expected = _cid_digest(inp["cid"])
        policy = EgressPolicy(
            allow_hosts=frozenset(hosts),
            max_bytes=_MAX_BYTES,
            total_timeout=8.0,
            max_redirects=0,
            content_types=("application/vnd.ipld.dag-json", "application/json"),
        )
        failures: list[str] = []
        for host in hosts:
            url = f"https://{host}/ipfs/{inp['cid']}?format=dag-json"
            try:
                result = fetch(url, policy)
                if result.get("status") != 200:
                    failures.append("HTTP_STATUS")
                    continue
                if result.get("content_type") not in (
                    "application/vnd.ipld.dag-json", "application/json"
                ):
                    failures.append("CONTENT_TYPE")
                    continue
                actual = hashlib.sha256(result["body"].encode("utf-8")).digest()
                # The egress layer's digest is over the original response bytes.
                if result.get("sha256") != "sha256:" + expected.hex():
                    failures.append("CID_MISMATCH")
                    continue
                if actual != expected:
                    failures.append("BODY_ENCODING_MISMATCH")
                    continue
                return {
                    "tool": "ipfs.fetch",
                    "tool_version": "1.0.0",
                    "status": "SUCCEEDED",
                    "cid": inp["cid"],
                    "gateway": host,
                    "content_type": result["content_type"],
                    "sha256": result["sha256"],
                    "body": result["body"],
                    "untrusted": True,
                }
            except EgressDenied as exc:
                failures.append(exc.code)
            except Exception:
                failures.append("FETCH_FAILED")
        reason = failures[-1] if failures else "NO_GATEWAY_RESULT"
        return {
            "tool": "ipfs.fetch",
            "tool_version": "1.0.0",
            "status": "DENIED",
            "error": reason,
            "cid": inp["cid"],
        }

    def verify(output: Any) -> str:
        if not isinstance(output, dict):
            return "FAIL"
        if output.get("status") == "DENIED":
            return "PASS" if isinstance(output.get("error"), str) else "FAIL"
        try:
            expected = _cid_digest(output["cid"])
            body_digest = hashlib.sha256(output["body"].encode("utf-8")).digest()
            return "PASS" if (
                output.get("tool") == "ipfs.fetch"
                and output.get("untrusted") is True
                and output.get("sha256") == "sha256:" + expected.hex()
                and body_digest == expected
            ) else "FAIL"
        except (KeyError, TypeError, ValueError):
            return "FAIL"

    return ToolSpec(
        "ipfs.fetch", "1.0.0", "ipfs.fetch", "READ_ONLY", 10.0,
        validate, run, verify,
    )
