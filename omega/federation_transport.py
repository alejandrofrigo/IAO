"""Pinned, bounded HTTPS transport for IAO federation.

Public HTTPS requests pin a globally-routable DNS answer, validate TLS against
the original hostname, reject redirects, and never use ambient proxies. Plain
HTTP is restricted to literal loopback addresses for local integration tests.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import os
import socket
import ssl
import stat
from pathlib import Path
from urllib.parse import urlsplit

MAX_DISCOVERY_BYTES = 1_000_000


class FederationTransportError(RuntimeError):
    """Safe transport failure with a stable machine-readable reason."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _parse_https_url(url: str) -> tuple[str, str, int, str]:
    if not isinstance(url, str) or not 1 <= len(url) <= 2048:
        raise FederationTransportError("INVALID_URL")
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise FederationTransportError("INVALID_URL") from exc
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
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise FederationTransportError("INVALID_HOST") from exc
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    return ascii_host, ascii_host, 443, target


def validate_discovery_url(url: str) -> tuple[str, str, int, str]:
    """Compatibility wrapper for callers validating public HTTPS feeds."""
    return _parse_https_url(url)


def validate_message_endpoint(url: str) -> tuple[str, str, int, str, str]:
    """Accept public HTTPS peers or literal-loopback HTTP integration peers."""
    if not isinstance(url, str) or not 1 <= len(url) <= 2048:
        raise FederationTransportError("INVALID_ENDPOINT")
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise FederationTransportError("INVALID_ENDPOINT") from exc
    if (
        not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/fed/v1/message"
        or parsed.query
        or parsed.fragment
        or any(ord(ch) < 33 or ord(ch) == 127 for ch in url)
    ):
        raise FederationTransportError("INVALID_ENDPOINT")
    if parsed.scheme == "https":
        tunnel_hosts = {"bore.pub", "loca.lt"}
        tunnel_suffixes = (
            ".ngrok-free.app", ".ngrok.io",
            ".trycloudflare.com", ".loca.lt",
        )
        normalized_host = host.lower().rstrip(".")
        is_tunnel = (
            normalized_host in tunnel_hosts
            or any(normalized_host.endswith(suffix) for suffix in tunnel_suffixes)
        )
        if port not in (None, 443) and not (
            os.environ.get("IAO_TLS_CA_FILE") or is_tunnel
        ):
            raise FederationTransportError("INVALID_ENDPOINT")
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise FederationTransportError("INVALID_ENDPOINT") from exc
        return "https", ascii_host, port or 443, parsed.path, ascii_host
    if parsed.scheme == "http" and port is not None:
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise FederationTransportError("LOOPBACK_IP_LITERAL_REQUIRED") from exc
        if not address.is_loopback:
            raise FederationTransportError("LOOPBACK_ONLY_HTTP")
        return "http", host, port, parsed.path, host
    raise FederationTransportError("PUBLIC_HTTPS_REQUIRED")


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


def _resolve_loopback(host: str, port: int) -> list[str]:
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise FederationTransportError("LOOPBACK_RESOLUTION_FAILED") from exc
    addresses: list[str] = []
    for answer in answers:
        address = answer[4][0]
        try:
            parsed = ipaddress.ip_address(address.split("%", 1)[0])
        except ValueError as exc:
            raise FederationTransportError("DNS_RETURNED_INVALID_ADDRESS") from exc
        if not parsed.is_loopback:
            raise FederationTransportError("NON_LOOPBACK_RESOLUTION_REFUSED")
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise FederationTransportError("DNS_NO_ADDRESSES")
    return addresses


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self, hostname: str, address: str, *, port: int = 443,
        timeout: float, context: ssl.SSLContext,
    ):
        super().__init__(hostname, port, timeout=timeout, context=context)
        self._pinned_address = address

    def connect(self) -> None:
        raw = socket.create_connection(
            (self._pinned_address, self.port), self.timeout, self.source_address
        )
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, hostname: str, address: str, port: int, *, timeout: float):
        super().__init__(hostname, port, timeout=timeout)
        self._pinned_address = address

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._pinned_address, self.port), self.timeout, self.source_address
        )


def _client_tls_context() -> ssl.SSLContext:
    ca_file = os.environ.get("IAO_TLS_CA_FILE") or None
    try:
        context = ssl.create_default_context(cafile=ca_file)
    except (OSError, ssl.SSLError) as exc:
        raise FederationTransportError("TLS_CA_CONFIGURATION_INVALID") from exc
    cert_file = os.environ.get("IAO_TLS_CLIENT_CERT_FILE")
    key_file = os.environ.get("IAO_TLS_CLIENT_KEY_FILE")
    require_client_cert = os.environ.get("IAO_TLS_REQUIRE_CLIENT_CERT", "").lower() in {
        "1", "true", "yes",
    }
    if bool(cert_file) != bool(key_file):
        raise FederationTransportError("INCOMPLETE_CLIENT_CERT_CONFIGURATION")
    if require_client_cert and not cert_file:
        raise FederationTransportError("CLIENT_CERT_REQUIRED")
    if cert_file and key_file:
        cert_path, key_path = Path(cert_file), Path(key_file)
        for path, is_private in ((cert_path, False), (key_path, True)):
            try:
                if path.is_symlink() or not path.is_file():
                    raise FederationTransportError("CLIENT_CERT_PATH_REFUSED")
                mode = stat.S_IMODE(path.stat().st_mode)
            except OSError as exc:
                raise FederationTransportError("CLIENT_CERT_PATH_REFUSED") from exc
            if is_private and mode & 0o077:
                raise FederationTransportError("CLIENT_KEY_PERMISSIONS_TOO_OPEN")
        try:
            context.load_cert_chain(str(cert_path), str(key_path))
        except (OSError, ssl.SSLError) as exc:
            raise FederationTransportError("CLIENT_CERT_INVALID") from exc
    return context


def _request_json(
    method: str,
    url: str,
    payload: dict | None,
    *,
    timeout: float,
    max_bytes: int,
    allow_loopback_http: bool,
) -> tuple[int, object]:
    if not 0 < timeout <= 30 or not 1 <= max_bytes <= MAX_DISCOVERY_BYTES:
        raise FederationTransportError("INVALID_TRANSPORT_LIMIT")
    if method == "GET":
        tls_host, host, port, target = _parse_https_url(url)
        scheme = "https"
    else:
        scheme, host, port, target, tls_host = validate_message_endpoint(url)
        if scheme == "http" and not allow_loopback_http:
            raise FederationTransportError("LOOPBACK_HTTP_NOT_ALLOWED")
    if scheme == "https":
        addresses = resolve_public_addresses(host, port)
        context = _client_tls_context()
    else:
        addresses = _resolve_loopback(host, port)
        context = None

    body = None if payload is None else json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    last_error: Exception | None = None
    for address in addresses:
        if scheme == "https":
            connection = _PinnedHTTPSConnection(
                tls_host, address, port=port, timeout=timeout, context=context
            )
        else:
            connection = _PinnedHTTPConnection(
                host, address, port, timeout=timeout
            )
        try:
            host_header = f"[{host}]" if ":" in host else host
            if port != 443:
                host_header = f"{host_header}:{port}"
            headers = {
                "Host": host_header,
                "Accept": "application/json",
                "Connection": "close",
                "User-Agent": "IAO-federation-transport/1",
            }
            if body is not None:
                headers["Content-Type"] = "application/json"
            connection.request(method, target, body=body, headers=headers)
            response = connection.getresponse()
            if 300 <= response.status < 400:
                raise FederationTransportError("REDIRECT_REFUSED")
            content_type = (
                response.getheader("Content-Type") or ""
            ).split(";", 1)[0].strip().lower()
            if content_type != "application/json" and not content_type.endswith("+json"):
                raise FederationTransportError("JSON_CONTENT_TYPE_REQUIRED")
            length = response.getheader("Content-Length")
            if length is not None:
                try:
                    if int(length) < 0 or int(length) > max_bytes:
                        raise FederationTransportError("RESPONSE_TOO_LARGE")
                except ValueError as exc:
                    raise FederationTransportError("INVALID_CONTENT_LENGTH") from exc
            raw = response.read(max_bytes + 1)
            if len(raw) > max_bytes:
                raise FederationTransportError("RESPONSE_TOO_LARGE")
            try:
                decoded = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise FederationTransportError("INVALID_JSON_RESPONSE") from exc
            return response.status, decoded
        except FederationTransportError:
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            last_error = exc
        finally:
            connection.close()
    raise FederationTransportError("HTTPS_REQUEST_FAILED") from last_error


def fetch_public_json(
    url: str, *, timeout: float = 8.0, max_bytes: int = MAX_DISCOVERY_BYTES
):
    """GET public JSON; reject redirects, non-200 responses, and oversized bodies."""
    status, data = _request_json(
        "GET", url, None, timeout=timeout, max_bytes=max_bytes,
        allow_loopback_http=False,
    )
    if status != 200:
        raise FederationTransportError("HTTP_STATUS_NOT_OK")
    return data


def post_federation_json(
    url: str,
    payload: dict,
    *,
    timeout: float = 5.0,
    max_bytes: int = 262_144,
) -> tuple[int, object]:
    """POST a signed federation envelope over pinned HTTPS or literal loopback HTTP."""
    return _request_json(
        "POST", url, payload, timeout=timeout, max_bytes=max_bytes,
        allow_loopback_http=True,
    )
