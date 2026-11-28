"""SSRF-safe HTTPS JSON POST transport for configured LLM gateways.

Uses IAO's DNS-pinned egress connection primitives. Redirects are rejected:
provider credentials and prompts must never be forwarded to another origin.
"""
from __future__ import annotations

import json
from urllib.parse import urlsplit

from omega.egress import EgressDenied, EgressPolicy, _SConn, _check_url, _resolve

MAX_RESPONSE_BYTES = 2_000_000
MAX_REQUEST_BYTES = 1_000_000


class ProviderTransportError(Exception):
    """Sanitized provider transport failure."""


def post_json(
    url: str,
    payload: dict,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 25.0,
    max_response_bytes: int = MAX_RESPONSE_BYTES,
) -> dict:
    """POST JSON to one explicitly configured global HTTPS host.

    DNS is resolved once and the socket connects to the pinned IP while TLS
    verifies the original hostname. Redirects, private IPs, credentials in
    URLs, non-JSON responses, and oversized bodies are rejected.
    """
    if not isinstance(url, str) or len(url) > 2048:
        raise ProviderTransportError("INVALID_PROVIDER_URL")
    if not 0 < float(timeout) <= 120:
        raise ProviderTransportError("INVALID_PROVIDER_TIMEOUT")
    if not 1 <= int(max_response_bytes) <= MAX_RESPONSE_BYTES:
        raise ProviderTransportError("INVALID_PROVIDER_RESPONSE_LIMIT")
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise ProviderTransportError("INVALID_PROVIDER_HOST")
    policy = EgressPolicy(
        allow_hosts=frozenset({host}),
        allowed_ports=frozenset({443}),
        max_bytes=int(max_response_bytes),
        total_timeout=float(timeout),
        max_redirects=0,
        content_types=("application/json",),
    )
    try:
        scheme, checked_host, port, path, _ = _check_url(url, policy)
        if scheme != "https" or checked_host != host:
            raise EgressDenied("PROVIDER_HTTPS_REQUIRED")
        ip = _resolve(host, port, policy)
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(body) > MAX_REQUEST_BYTES:
            raise EgressDenied("REQUEST_TOO_LARGE")
        request_headers = {
            "Host": host,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "IAO-LLM-Router/1",
            "Connection": "close",
        }
        if headers:
            for name, value in headers.items():
                if (not isinstance(name, str) or not isinstance(value, str)
                        or name.lower() in {"host", "content-length", "connection"}
                        or any(ch in name + value for ch in "\r\n")):
                    raise EgressDenied("INVALID_PROVIDER_HEADER")
                request_headers[name] = value
        conn = _SConn(host, port, ip, float(timeout))
        try:
            conn.request("POST", path, body=body, headers=request_headers)
            response = conn.getresponse()
            if 300 <= response.status < 400:
                raise EgressDenied("PROVIDER_REDIRECT_REJECTED")
            if response.status < 200 or response.status >= 300:
                raise EgressDenied("PROVIDER_HTTP_ERROR")
            if response.getheader("Content-Encoding"):
                raise EgressDenied("PROVIDER_ENCODED_RESPONSE_REJECTED")
            content_type = (response.getheader("Content-Type") or "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                raise EgressDenied("PROVIDER_CONTENT_TYPE_REJECTED")
            declared = response.getheader("Content-Length")
            if declared is not None:
                if not declared.isascii() or not declared.isdigit():
                    raise EgressDenied("PROVIDER_CONTENT_LENGTH_INVALID")
                if int(declared) > max_response_bytes:
                    raise EgressDenied("PROVIDER_RESPONSE_TOO_LARGE")
            raw = response.read(max_response_bytes + 1)
            if len(raw) > max_response_bytes:
                raise EgressDenied("PROVIDER_RESPONSE_TOO_LARGE")
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict):
                raise EgressDenied("PROVIDER_JSON_OBJECT_REQUIRED")
            return data
        finally:
            conn.close()
    except (EgressDenied, OSError, ValueError, UnicodeError, TimeoutError):
        raise ProviderTransportError("PROVIDER_TRANSPORT_REJECTED") from None
