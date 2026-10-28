"""Mediated egress (F3): the ONLY place IAO fetches remote content for tools.
Deny-by-default allowlist, SSRF defence (all resolved addresses must be globally routable),
DNS pinning, redirect re-validation, size/time/content-type limits, no credentials in URLs."""
import hashlib
import http.client
import ipaddress
import socket
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit


class EgressDenied(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class EgressPolicy:
    allow_hosts: frozenset[str]
    allow_http: bool = False                      # plain http only for tests / explicit opt-in
    allowed_ports: frozenset[int] = frozenset({443})
    max_bytes: int = 1_000_000
    total_timeout: float = 8.0
    max_redirects: int = 3
    content_types: tuple[str, ...] = ("text/", "application/json")
    allow_private: bool = False                   # TESTS ONLY: permit loopback targets
    resolver: Callable[..., Any] = field(default=socket.getaddrinfo)


def _forbidden(ip_s: str) -> bool:
    ip = ipaddress.ip_address(ip_s.split("%")[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return not ip.is_global or ip.is_multicast


class _Conn(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, ip: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _SConn(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, ip: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._ip = ip

    def connect(self) -> None:
        raw = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)  # type: ignore[attr-defined]


def _check_url(url: str, pol: EgressPolicy) -> tuple[str, str, int, str, str]:
    if len(url) > 2048 or any(c in url for c in "\r\n\t \x00"):
        raise EgressDenied("INVALID_URL")
    u = urlsplit(url)
    if u.scheme not in ("https", "http") or (u.scheme == "http" and not pol.allow_http):
        raise EgressDenied("SCHEME_NOT_ALLOWED")
    if u.username or u.password or "@" in u.netloc:
        raise EgressDenied("CREDENTIALS_IN_URL")
    host = (u.hostname or "").lower().rstrip(".")
    if not host or host not in pol.allow_hosts:
        raise EgressDenied("HOST_NOT_ALLOWED")
    try:
        port = u.port or (443 if u.scheme == "https" else 80)
    except ValueError:
        raise EgressDenied("INVALID_URL") from None
    if port not in pol.allowed_ports:
        raise EgressDenied("PORT_NOT_ALLOWED")
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    return u.scheme, host, port, path, url


def _resolve(host: str, port: int, pol: EgressPolicy) -> str:
    try:
        infos = pol.resolver(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise EgressDenied("DNS_FAILURE") from None
    ips = sorted({i[4][0] for i in infos})
    if not ips:
        raise EgressDenied("DNS_FAILURE")
    if not pol.allow_private and any(_forbidden(ip) for ip in ips):  # ANY bad address => deny (anti-rebinding)
        raise EgressDenied("PRIVATE_ADDRESS")
    return ips[0]  # pinned: we connect to this IP, never re-resolve


def fetch(url: str, pol: EgressPolicy) -> dict[str, Any]:
    deadline = time.monotonic() + pol.total_timeout
    hops = 0
    while True:
        scheme, host, port, path, cur = _check_url(url, pol)
        ip = _resolve(host, port, pol)
        left = deadline - time.monotonic()
        if left <= 0:
            raise EgressDenied("TIMEOUT")
        conn = (_SConn if scheme == "https" else _Conn)(host, port, ip, left)
        try:
            conn.request("GET", path, headers={"Host": host if port in (80, 443) else f"{host}:{port}",
                                               "User-Agent": "so-omega-egress/1", "Accept": "text/*, application/json",
                                               "Connection": "close"})
            r = conn.getresponse()
            if r.status in (301, 302, 303, 307, 308):
                loc = r.getheader("Location")
                if not loc:
                    raise EgressDenied("BAD_REDIRECT")
                hops += 1
                if hops > pol.max_redirects:
                    raise EgressDenied("TOO_MANY_REDIRECTS")
                url = urljoin(cur, loc)  # re-validated against allowlist + SSRF on next loop
                continue
            if r.getheader("Content-Encoding"):
                raise EgressDenied("ENCODED_CONTENT_NOT_ALLOWED")
            ctype = (r.getheader("Content-Type") or "").split(";")[0].strip().lower()
            if not any(ctype.startswith(p) for p in pol.content_types):
                raise EgressDenied("CONTENT_TYPE_NOT_ALLOWED")
            declared = r.getheader("Content-Length")
            if declared and declared.isdigit() and int(declared) > pol.max_bytes:
                raise EgressDenied("TOO_LARGE")
            body = r.read(pol.max_bytes + 1)
            if len(body) > pol.max_bytes:
                raise EgressDenied("TOO_LARGE")
            if time.monotonic() > deadline:
                raise EgressDenied("TIMEOUT")
            return {"url": cur, "status": r.status, "content_type": ctype, "ip": ip,
                    "sha256": "sha256:" + hashlib.sha256(body).hexdigest(),
                    "body": body.decode("utf-8", "replace"), "untrusted": True}
        except EgressDenied:
            raise
        except ssl.SSLCertVerificationError:
            raise EgressDenied("TLS_VERIFY_FAILED") from None
        except (socket.timeout, TimeoutError):
            raise EgressDenied("TIMEOUT") from None
        except (OSError, http.client.HTTPException):
            raise EgressDenied("CONNECT_FAILED") from None
        finally:
            conn.close()
