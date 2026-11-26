"""Pinned, bounded HTTPS transport for public federation discovery.

This module deliberately performs no redirects, never uses ambient HTTP proxies,
pins the socket to a DNS answer checked as globally routable, and validates TLS
against the original hostname. It is for public read-only discovery only; it
does not grant peer identity, mTLS, or federation enrollment.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
from urllib.parse import urlsplit

MAX_DISCOVERY_BYTES = 1_000_000


class FederationTransportError(RuntimeError):
    """Safe transport failure with a stable machine-readable reason."""


def validate_discovery_url(url: str) -> tuple[str, str, int, str]:
    if not isinstance(url, str) or not 1 <= len(url) <= 2048:
        raise FederationTransportError("INVALID_DISCOVERY_URL")
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise FederationTransportError("INVALID_DISCOVERY_URL") from exc
    if (
        parsed.scheme != "https"
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or not parsed.path.startswith("/")
        or parsed.fragment
        or any(ord(ch) < 33 or ord(ch) == 127 for ch in url)
    ):
        raise FederationTransportError("PUBLIC_HTTPS_REQUIRED")
    try:
        host.encode("idna")
    except UnicodeError as exc:
        raise FederationTransportError("INVALID_DISCOVERY_HOST") from exc
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    return host, host.encode("idna").decode("ascii"), 443, target


def resolve_public_addresses(host: str, port: int = 443) -> list[str]:
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise FederationTransportError("DNS_RESOLUTION_FAILED") from exc
    addresses: list[str] = []
    for answer in answers:
        address = answer[4][0]
        try:
            parsed = ipaddress.ip_address(address.split("%", 1)[0])
        except ValueError as exc:
            raise FederationTransportError("DNS_RETURNED_INVALID_ADDRESS") from exc
        if not parsed.is_global:
            raise FederationTransportError("DNS_RESOLVED_NON_PUBLIC_ADDRESS")
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise FederationTransportError("DNS_NO_ADDRESSES")
    return addresses


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname: str, address: str, *, timeout: float, context: ssl.SSLContext):
        super().__init__(hostname, 443, timeout=timeout, context=context)
        self._pinned_address = address

    def connect(self) -> None:
        raw = socket.create_connection(
            (self._pinned_address, self.port),
            self.timeout,
            self.source_address,
        )
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def fetch_public_json(url: str, *, timeout: float = 8.0, max_bytes: int = MAX_DISCOVERY_BYTES):
    """GET one public JSON URL; reject redirects, non-200, and oversized bodies."""
    if not 1 <= max_bytes <= MAX_DISCOVERY_BYTES:
        raise FederationTransportError("INVALID_RESPONSE_LIMIT")
    hostname, tls_hostname, port, target = validate_discovery_url(url)
    addresses = resolve_public_addresses(tls_hostname, port)
    context = ssl.create_default_context()
    last_error: Exception | None = None
    for address in addresses:
        connection = _PinnedHTTPSConnection(
            tls_hostname, address, timeout=timeout, context=context
        )
        try:
            connection.request(
                "GET",
                target,
                headers={
                    "Host": hostname,
                    "Accept": "application/json",
                    "Connection": "close",
                    "User-Agent": "IAO-federation-discovery/1",
                },
            )
            response = connection.getresponse()
            if 300 <= response.status < 400:
                raise FederationTransportError("REDIRECT_REFUSED")
            if response.status != 200:
                raise FederationTransportError("HTTP_STATUS_NOT_OK")
            content_type = (response.getheader("Content-Type") or "").split(";", 1)[0].strip().lower()
            if content_type != "application/json" and not content_type.endswith("+json"):
                raise FederationTransportError("JSON_CONTENT_TYPE_REQUIRED")
            length = response.getheader("Content-Length")
            if length is not None:
                try:
                    if int(length) < 0 or int(length) > max_bytes:
                        raise FederationTransportError("RESPONSE_TOO_LARGE")
                except ValueError as exc:
                    raise FederationTransportError("INVALID_CONTENT_LENGTH") from exc
            body = response.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise FederationTransportError("RESPONSE_TOO_LARGE")
            try:
                return json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise FederationTransportError("INVALID_JSON_RESPONSE") from exc
        except FederationTransportError:
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            last_error = exc
        finally:
            connection.close()
    raise FederationTransportError("HTTPS_REQUEST_FAILED") from last_error
