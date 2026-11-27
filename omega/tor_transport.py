"""Explicit, fail-closed SOCKS5 transport for IAO onion services.

No direct-connect fallback is provided. Hostnames are sent to the SOCKS proxy
as domain names (SOCKS5 remote DNS), preventing local DNS leakage.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlsplit

_ONION_V3 = re.compile(r"^[a-z2-7]{56}\\.onion$", re.IGNORECASE)
_FED_PATH = "/fed/v1/message"


class TorTransportError(OSError):
    """SOCKS5 transport failed; callers must not retry directly."""


def validate_onion_endpoint(endpoint: str) -> tuple[str, int]:
    if not isinstance(endpoint, str) or not 1 <= len(endpoint) <= 2048:
        raise ValueError("INVALID_ONION_ENDPOINT")
    try:
        u = urlsplit(endpoint)
        host = (u.hostname or "").lower()
        port = u.port or 80
        valid = (
            u.scheme == "http"
            and bool(_ONION_V3.fullmatch(host))
            and not u.username and not u.password
            and port in (80, 443, 8443)
            and u.path == _FED_PATH
            and not u.query and not u.fragment
            and not any(ord(c) < 33 or ord(c) == 127 for c in endpoint)
        )
    except ValueError:
        valid = False
        host, port = "", 0
    if not valid:
        raise ValueError("ONION_V3_HTTP_ENDPOINT_REQUIRED")
    return host, port


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < count:
        part = sock.recv(count - len(chunks))
        if not part:
            raise TorTransportError("SOCKS5_PROXY_CLOSED")
        chunks.extend(part)
    return bytes(chunks)


def open_tor_socket(
    host: str,
    port: int,
    *,
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 9050,
    timeout: float = 10.0,
) -> socket.socket:
    """Open TCP through a local SOCKS5 proxy, using remote DNS.

    Only the configured proxy is contacted. Any error raises and never falls
    back to a direct socket connection.
    """
    if not isinstance(host, str) or not host or len(host.encode("idna")) > 255:
        raise ValueError("INVALID_TARGET_HOST")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("INVALID_TARGET_PORT")
    if not isinstance(timeout, (int, float)) or timeout <= 0 or timeout > 120:
        raise ValueError("INVALID_TIMEOUT")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("TOR_TARGET_MUST_USE_HOSTNAME")

    encoded_host = host.encode("idna")
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall(b"\\x05\\x01\\x00")
        if _recv_exact(sock, 2) != b"\\x05\\x00":
            raise TorTransportError("SOCKS5_NO_AUTH_METHOD_REJECTED")
        request = (
            b"\\x05\\x01\\x00\\x03"
            + bytes((len(encoded_host),))
            + encoded_host
            + port.to_bytes(2, "big")
        )
        sock.sendall(request)
        header = _recv_exact(sock, 4)
        if header[0] != 5:
            raise TorTransportError("SOCKS5_INVALID_VERSION")
        if header[1] != 0:
            raise TorTransportError(f"SOCKS5_CONNECT_FAILED_{header[1]}")
        atyp = header[3]
        if atyp == 1:
            _recv_exact(sock, 4)
        elif atyp == 3:
            length = _recv_exact(sock, 1)[0]
            _recv_exact(sock, length)
        elif atyp == 4:
            _recv_exact(sock, 16)
        else:
            raise TorTransportError("SOCKS5_INVALID_BOUND_ADDRESS")
        _recv_exact(sock, 2)
        return sock
    except Exception:
        sock.close()
        raise
