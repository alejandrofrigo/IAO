"""Transporte seguro para conexiones federadas dinámicas.

- HTTPS público: DNS completo validado y conexión fijada a IP.
- HTTP loopback: solo con IAO_ALLOW_LOOPBACK_HTTP=1.
- Sin redirecciones automáticas.
- TLS valida certificado y hostname.
- Respuestas JSON limitadas en tamaño y tiempo.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
import time
from urllib.parse import urlsplit


class TransportError(OSError):
    """Conexión federada rechazada o fallida."""


_TUNNEL_SUFFIXES = (
    ".trycloudflare.com",
    ".ngrok-free.app",
    ".ngrok.io",
    ".loca.lt",
)

_LOOPBACK_NAMES = {"127.0.0.1", "::1", "localhost"}


def _parse_target(url: str, allow_loopback: bool = False):
    if not isinstance(url, str) or not url or len(url) > 2048:
        raise TransportError("INVALID_URL")

    if any(ord(c) < 33 or ord(c) == 127 for c in url):
        raise TransportError("INVALID_URL")

    try:
        u = urlsplit(url)
        scheme = u.scheme.lower()
        host = (u.hostname or "").lower().rstrip(".")
        port = u.port
    except ValueError:
        raise TransportError("INVALID_URL") from None

    if not host or u.username is not None or u.password is not None:
        raise TransportError("INVALID_URL")

    if "@" in u.netloc or u.fragment:
        raise TransportError("INVALID_URL")

    if scheme not in ("https", "http"):
        raise TransportError("SCHEME_NOT_ALLOWED")

    loopback = host in _LOOPBACK_NAMES

    if scheme == "http":
        if not (allow_loopback and loopback):
            raise TransportError("HTTP_NOT_ALLOWED")
    elif scheme != "https":
        raise TransportError("SCHEME_NOT_ALLOWED")

    if port is None:
        port = 443 if scheme == "https" else 80

    if not 1 <= port <= 65535:
        raise TransportError("INVALID_PORT")

    if not loopback and scheme == "https" and port != 443:
        if not any(host.endswith(s) for s in _TUNNEL_SUFFIXES):
            raise TransportError("PORT_NOT_ALLOWED")

    try:
        host_ascii = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise TransportError("INVALID_HOST") from None

    path = u.path or "/"
    if u.query:
        path += "?" + u.query

    return scheme, host_ascii, port, path, loopback


def _is_global_address(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.split("%")[0])
    except ValueError:
        return False

    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    return bool(ip.is_global and not ip.is_multicast)


def _resolve(
    host: str,
    port: int,
    *,
    allow_loopback: bool = False,
    resolver=socket.getaddrinfo,
) -> str:
    try:
        answers = resolver(host, port, type=socket.SOCK_STREAM)
    except Exception:
        raise TransportError("DNS_FAILURE") from None

    addresses = set()

    for answer in answers:
        try:
            raw = answer[4][0]
            ip = ipaddress.ip_address(raw.split("%")[0])
            addresses.add(str(ip))
        except (IndexError, TypeError, ValueError, AttributeError):
            raise TransportError("DNS_INVALID_ADDRESS") from None

    if not addresses:
        raise TransportError("DNS_FAILURE")

    # Loopback es una excepción explícita y exclusiva para HTTP local.
    if allow_loopback and all(
        ipaddress.ip_address(x).is_loopback for x in addresses
    ):
        return sorted(addresses)[0]

    # Se rechaza la resolución completa si UNA sola respuesta no es pública.
    if any(not _is_global_address(x) for x in addresses):
        raise TransportError("PRIVATE_ADDRESS")

    return sorted(addresses)[0]


class _PinnedConnection(http.client.HTTPConnection):
    def __init__(self, host, port, ip, timeout, context=None):
        super().__init__(host, port, timeout=timeout)
        self._pinned_ip = ip
        self._tls_context = context

    def connect(self):
        raw = socket.create_connection(
            (self._pinned_ip, self.port),
            timeout=self.timeout,
        )

        if self._tls_context is not None:
            try:
                self.sock = self._tls_context.wrap_socket(
                    raw,
                    server_hostname=self.host,
                )
            except Exception:
                raw.close()
                raise
        else:
            self.sock = raw


def request_json(
    url: str,
    *,
    method: str = "GET",
    payload=None,
    timeout: float = 8.0,
    max_bytes: int = 1_000_000,
    ssl_context=None,
    allow_loopback: bool = False,
    resolver=socket.getaddrinfo,
):
    if method not in ("GET", "POST"):
        raise TransportError("METHOD_NOT_ALLOWED")

    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TransportError("INVALID_TIMEOUT")

    if timeout <= 0 or timeout > 60:
        raise TransportError("INVALID_TIMEOUT")

    if not isinstance(max_bytes, int) or not 1 <= max_bytes <= 2_000_000:
        raise TransportError("INVALID_RESPONSE_LIMIT")

    scheme, host, port, path, loopback = _parse_target(
        url, allow_loopback=allow_loopback
    )

    # No se permite HTTP fuera de loopback, ni aunque DNS apunte a una IP privada.
    if scheme == "http" and not loopback:
        raise TransportError("HTTP_NOT_ALLOWED")

    ip = _resolve(
        host,
        port,
        allow_loopback=(allow_loopback and scheme == "http" and loopback),
        resolver=resolver,
    )

    body = None
    if payload is not None:
        try:
            body = json.dumps(
                payload,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        except (TypeError, ValueError):
            raise TransportError("INVALID_REQUEST_JSON") from None

        if len(body) > 256_000:
            raise TransportError("REQUEST_TOO_LARGE")

    context = None
    if scheme == "https":
        context = ssl_context or ssl.create_default_context()

    deadline = time.monotonic() + float(timeout)
    conn = _PinnedConnection(host, port, ip, float(timeout), context)

    headers = {
        "Host": f"[{host}]:{port}" if ":" in host else (
            host if port in (80, 443) else f"{host}:{port}"
        ),
        "Accept": "application/json",
        "Accept-Encoding": "identity",
        "User-Agent": "IAO-Federation-Transport/1",
        "Connection": "close",
    }

    if body is not None:
        headers["Content-Type"] = "application/json"

    try:
        conn.request(method, path, body=body, headers=headers)

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TransportError("TIMEOUT")

        if conn.sock is not None:
            conn.sock.settimeout(remaining)

        response = conn.getresponse()

        # No seguir redirects: el destino tendría que pasar una validación nueva.
        if 300 <= response.status < 400:
            raise TransportError("REDIRECT_NOT_ALLOWED")

        if response.status < 200 or response.status >= 300:
            raise TransportError(f"HTTP_STATUS_{response.status}")

        encoding = response.getheader("Content-Encoding")
        if encoding and encoding.lower() != "identity":
            raise TransportError("ENCODED_RESPONSE_NOT_ALLOWED")

        content_type = (
            response.getheader("Content-Type") or ""
        ).split(";")[0].strip().lower()

        if content_type and not (
            content_type == "application/json"
            or content_type.endswith("+json")
        ):
            raise TransportError("CONTENT_TYPE_NOT_ALLOWED")

        declared = response.getheader("Content-Length")
        if declared:
            try:
                if int(declared) > max_bytes:
                    raise TransportError("RESPONSE_TOO_LARGE")
            except ValueError:
                raise TransportError("INVALID_CONTENT_LENGTH") from None

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TransportError("TIMEOUT")

        if conn.sock is not None:
            conn.sock.settimeout(remaining)

        raw = response.read(max_bytes + 1)

        if len(raw) > max_bytes:
            raise TransportError("RESPONSE_TOO_LARGE")

        if time.monotonic() > deadline:
            raise TransportError("TIMEOUT")

        try:
            return json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            raise TransportError("INVALID_JSON_RESPONSE") from None

    except TransportError:
        raise
    except ssl.SSLCertVerificationError:
        raise TransportError("TLS_VERIFY_FAILED") from None
    except (socket.timeout, TimeoutError):
        raise TransportError("TIMEOUT") from None
    except (OSError, http.client.HTTPException):
        raise TransportError("CONNECTION_FAILED") from None
    finally:
        conn.close()
