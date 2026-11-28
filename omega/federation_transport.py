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


def _json_without_duplicate_keys(raw: bytes):
    """Decode JSON and reject duplicate keys at every object depth."""
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("DUPLICATE_JSON_KEY")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=unique_object)


def _certificate_node_id(certificate: dict | None) -> str | None:
    if not isinstance(certificate, dict):
        return None
    names = certificate.get("subjectAltName")
    if not isinstance(names, tuple):
        return None
    values = [
        value[len("urn:iao:node:"):]
        for kind, value in names
        if kind == "URI" and isinstance(value, str)
        and value.startswith("urn:iao:node:")
    ]
    if len(values) != 1:
        return None
    value = values[0]
    if len(value) != 16 or any(ch not in "0123456789abcdef" for ch in value):
        return None
    return value


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



def validate_public_federation_origin(origin: str) -> str:
    """Validate an exact HTTPS or Tor v3 onion origin for publication."""
    if not isinstance(origin, str) or not 1 <= len(origin) <= 255:
        raise FederationTransportError("INVALID_PUBLIC_ORIGIN")
    try:
        parsed = urlsplit(origin)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise FederationTransportError("INVALID_PUBLIC_ORIGIN") from exc
    if (not host or parsed.username or parsed.password or parsed.path
            or parsed.query or parsed.fragment):
        raise FederationTransportError("INVALID_PUBLIC_ORIGIN")
    if parsed.scheme == "https" and port in (None, 443):
        return origin
    if (parsed.scheme == "http" and host.endswith(".onion")
            and len(host) == 62
            and all(char in "abcdefghijklmnopqrstuvwxyz234567" for char in host[:-6])
            and port in (None, 80)):
        return origin
    raise FederationTransportError("INVALID_PUBLIC_ORIGIN")

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
    # Onion services are valid only as explicit Tor v3 HTTP endpoints.
    # Reject HTTPS or malformed onion hosts before the generic HTTPS branch.
    if host.lower().endswith(".onion") and not (
        parsed.scheme == "http"
        and len(host) == 62
        and all(char in "abcdefghijklmnopqrstuvwxyz234567" for char in host[:-6])
        and port in (None, 80)
    ):
        raise FederationTransportError("INVALID_ONION_ENDPOINT")
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
    if (parsed.scheme == "http" and host.endswith(".onion")
            and len(host) == 62
            and all(char in "abcdefghijklmnopqrstuvwxyz234567" for char in host[:-6])
            and port in (None, 80)):
        return "onion", host, 80, parsed.path, host
    if parsed.scheme == "http" and port is not None and 1 <= port <= 65535:
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
        expected_peer_id: str | None = None,
    ):
        super().__init__(hostname, port, timeout=timeout, context=context)
        self._pinned_address = address
        self._expected_peer_id = expected_peer_id

    def connect(self) -> None:
        raw = socket.create_connection(
            (self._pinned_address, self.port), self.timeout, self.source_address
        )
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
            if self._expected_peer_id is not None:
                peer_id = _certificate_node_id(self.sock.getpeercert())
                if peer_id != self._expected_peer_id:
                    raise FederationTransportError("TLS_SERVER_NODE_ID_MISMATCH")
        except Exception:
            if self.sock is not None:
                self.sock.close()
                self.sock = None
            else:
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


def _client_tls_context(*, require_client_cert: bool = False) -> ssl.SSLContext:
    ca_file = os.environ.get("IAO_TLS_CA_FILE") or None
    try:
        context = ssl.create_default_context(cafile=ca_file)
    except (OSError, ssl.SSLError) as exc:
        raise FederationTransportError("TLS_CA_CONFIGURATION_INVALID") from exc
    cert_file = os.environ.get("IAO_TLS_CLIENT_CERT_FILE")
    key_file = os.environ.get("IAO_TLS_CLIENT_KEY_FILE")
    require_client_cert = require_client_cert or os.environ.get(
        "IAO_TLS_REQUIRE_CLIENT_CERT", ""
    ).lower() in {"1", "true", "yes"}
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
    allow_public_post: bool = False,
    require_client_cert: bool = False,
    expected_peer_id: str | None = None,
) -> tuple[int, object]:
    if not 0 < timeout <= 30 or not 1 <= max_bytes <= MAX_DISCOVERY_BYTES:
        raise FederationTransportError("INVALID_TRANSPORT_LIMIT")
    if method == "GET" or (method == "POST" and allow_public_post):
        tls_host, host, port, target = _parse_https_url(url)
        scheme = "https"
    else:
        scheme, host, port, target, tls_host = validate_message_endpoint(url)
        if scheme == "http" and not allow_loopback_http:
            raise FederationTransportError("LOOPBACK_HTTP_NOT_ALLOWED")
    if scheme == "https":
        addresses = resolve_public_addresses(host, port)
        context = _client_tls_context(require_client_cert=require_client_cert)
    elif scheme == "onion":
        # Onion hostnames must be resolved remotely by Tor, never via local DNS.
        _tor_proxy()
        try:
            import socks  # noqa: F401 - fail closed before network activity
        except ImportError as exc:
            raise FederationTransportError("TOR_SOCKS_DEPENDENCY_MISSING") from exc
        addresses = ["tor-socks"]
        context = None
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
                tls_host, address, port=port, timeout=timeout, context=context,
                expected_peer_id=expected_peer_id,
            )
        elif scheme == "onion":
            proxy_host, proxy_port = _tor_proxy()
            connection = _TorOnionHTTPConnection(
                host, timeout=timeout, proxy_host=proxy_host, proxy_port=proxy_port
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
                decoded = _json_without_duplicate_keys(raw)
            except (UnicodeDecodeError, ValueError) as exc:
                raise FederationTransportError("INVALID_JSON_RESPONSE") from exc
            return response.status, decoded
        except FederationTransportError:
            raise
        except ssl.SSLError as exc:
            raise FederationTransportError("TLS_HANDSHAKE_FAILED") from exc
        except (OSError, http.client.HTTPException) as exc:
            last_error = exc
        finally:
            connection.close()
    raise FederationTransportError("HTTPS_REQUEST_FAILED") from last_error



def _parse_onion_url(url: str) -> tuple[str, int, str]:
    """Accept only Tor v3 onion HTTP endpoints; never resolve onion names locally."""
    if not isinstance(url, str) or not 1 <= len(url) <= 2048:
        raise FederationTransportError("INVALID_ONION_URL")
    try:
        parsed = urlsplit(url)
        host, port = parsed.hostname, parsed.port
    except ValueError as exc:
        raise FederationTransportError("INVALID_ONION_URL") from exc
    if (
        parsed.scheme != "http" or not isinstance(host, str)
        or not host.endswith(".onion")
        or len(host) != 62
        or any(char not in "abcdefghijklmnopqrstuvwxyz234567" for char in host[:-6])
        or parsed.username is not None or parsed.password is not None
        or port not in (None, 80) or not parsed.path.startswith("/")
        or parsed.fragment or parsed.query
        or any(ord(char) < 33 or ord(char) == 127 for char in url)
    ):
        raise FederationTransportError("V3_ONION_HTTP_ENDPOINT_REQUIRED")
    return host, 80, parsed.path or "/"


def _tor_proxy() -> tuple[str, int]:
    host = os.environ.get("IAO_TOR_SOCKS_HOST", "127.0.0.1")
    raw_port = os.environ.get("IAO_TOR_SOCKS_PORT", "9050")
    try:
        address = ipaddress.ip_address(host)
        port = int(raw_port)
    except (ValueError, TypeError) as exc:
        raise FederationTransportError("TOR_SOCKS_PROXY_INVALID") from exc
    if not address.is_loopback or not 1 <= port <= 65535:
        raise FederationTransportError("TOR_SOCKS_PROXY_MUST_BE_LOOPBACK")
    return str(address), port


class _TorOnionHTTPConnection(http.client.HTTPConnection):
    def __init__(self, hostname: str, *, timeout: float, proxy_host: str, proxy_port: int):
        super().__init__(hostname, 80, timeout=timeout)
        self._proxy_host = proxy_host
        self._proxy_port = proxy_port

    def connect(self) -> None:
        try:
            import socks
        except ImportError as exc:
            raise FederationTransportError("TOR_SOCKS_DEPENDENCY_MISSING") from exc
        # PySocks SOCKS5 remote DNS: the .onion name is sent through Tor,
        # never resolved by the local DNS resolver.
        self.sock = socks.create_connection(
            (self.host, self.port), timeout=self.timeout,
            proxy_type=socks.SOCKS5, proxy_addr=self._proxy_host,
            proxy_port=self._proxy_port, proxy_rdns=True,
        )


def fetch_onion_json(
    url: str, *, timeout: float = 15.0, max_bytes: int = MAX_DISCOVERY_BYTES
):
    """Fetch bounded JSON from a v3 onion service via a local SOCKS5 Tor proxy."""
    if not 0 < timeout <= 30 or not 1 <= max_bytes <= MAX_DISCOVERY_BYTES:
        raise FederationTransportError("INVALID_TRANSPORT_LIMIT")
    host, port, target = _parse_onion_url(url)
    proxy_host, proxy_port = _tor_proxy()
    try:
        import socks  # noqa: F401 - fail closed before opening a connection
    except ImportError as exc:
        raise FederationTransportError("TOR_SOCKS_DEPENDENCY_MISSING") from exc
    connection = _TorOnionHTTPConnection(
        host, timeout=timeout, proxy_host=proxy_host, proxy_port=proxy_port
    )
    try:
        connection.request("GET", target, headers={
            "Host": host, "Accept": "application/json",
            "Connection": "close", "User-Agent": "IAO-tor-discovery/1",
        })
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
        raw = response.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise FederationTransportError("RESPONSE_TOO_LARGE")
        try:
            return _json_without_duplicate_keys(raw)
        except (UnicodeDecodeError, ValueError) as exc:
            raise FederationTransportError("INVALID_JSON_RESPONSE") from exc
    except FederationTransportError:
        raise
    except (OSError, http.client.HTTPException) as exc:
        raise FederationTransportError("TOR_ONION_REQUEST_FAILED") from exc
    finally:
        connection.close()


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


def post_public_json(
    url: str,
    payload: dict,
    *,
    timeout: float = 8.0,
    max_bytes: int = 65_536,
) -> tuple[int, object]:
    """POST bounded JSON to a public HTTPS endpoint with pinned DNS and no redirects."""
    return _request_json(
        "POST", url, payload, timeout=timeout, max_bytes=max_bytes,
        allow_loopback_http=False, allow_public_post=True,
    )


def post_federation_json(
    url: str,
    payload: dict,
    *,
    timeout: float = 5.0,
    max_bytes: int = 262_144,
    expected_peer_id: str | None = None,
) -> tuple[int, object]:
    """POST a signed envelope over pinned HTTPS, Tor onion, or explicit loopback."""
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise FederationTransportError("INVALID_ENDPOINT") from exc
    if parsed.hostname and parsed.hostname.endswith(".onion"):
        return post_onion_federation_json(
            url, payload, timeout=timeout, max_bytes=max_bytes
        )
    return _request_json(
        "POST", url, payload, timeout=timeout, max_bytes=max_bytes,
        allow_loopback_http=True, require_client_cert=True,
        expected_peer_id=expected_peer_id,
    )


def post_onion_federation_json(
    url: str,
    payload: dict,
    *,
    timeout: float = 8.0,
    max_bytes: int = 262_144,
) -> tuple[int, object]:
    """POST signed federation envelopes through Tor SOCKS5 with remote onion DNS."""
    if not 0 < timeout <= 30 or not 1 <= max_bytes <= MAX_DISCOVERY_BYTES:
        raise FederationTransportError("INVALID_TRANSPORT_LIMIT")
    host, port, target = _parse_onion_url(url)
    if target != "/fed/v1/message":
        raise FederationTransportError("INVALID_ONION_FEDERATION_PATH")
    proxy_host, proxy_port = _tor_proxy()
    try:
        import socks
    except ImportError as exc:
        raise FederationTransportError("TOR_SOCKS_DEPENDENCY_MISSING") from exc
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(body) > max_bytes:
        raise FederationTransportError("REQUEST_TOO_LARGE")
    connection = _TorOnionHTTPConnection(
        host, timeout=timeout, proxy_host=proxy_host, proxy_port=proxy_port
    )
    try:
        connection.request("POST", target, body=body, headers={
            "Host": host, "Accept": "application/json",
            "Content-Type": "application/json", "Connection": "close",
            "User-Agent": "IAO-tor-federation/1",
        })
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise FederationTransportError("REDIRECT_REFUSED")
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
        raw = response.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise FederationTransportError("RESPONSE_TOO_LARGE")
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise FederationTransportError("INVALID_JSON_RESPONSE") from exc
        return response.status, decoded
    except FederationTransportError:
        raise
    except (OSError, http.client.HTTPException) as exc:
        raise FederationTransportError("TOR_ONION_REQUEST_FAILED") from exc
    finally:
        connection.close()
