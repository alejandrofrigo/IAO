"""HTTP transport for approved .onion LLM endpoints through local Tor SOCKS5."""
from __future__ import annotations

import http.client
import json
import socket
import struct
from urllib.parse import urlsplit

SOCKS_HOST = "127.0.0.1"
SOCKS_PORT = 9050

ALLOWED_ONION_HOSTS = frozenset({
    "shannonmd773o5vxz75byha5rkea7nzr3srotw46uwythq3pjl6y4cad.onion",
    "nanogpt5wwal7shnauuilouj3gaewmk7lskqxdmxlbfz5ho4tdqeh2id.onion",
    "vplomjjsd3hicadr6inrzu2uyykrqw4yc7wxjnjooj5smctmmpbhnkad.onion",
    "bf7hn23jgyo5umvbi2lzzkb62ts3glxd2pnfksecqmyi4yglgdevs2ad.onion",
})
MAX_RESPONSE_BYTES = 2_000_000


class TorTransportError(RuntimeError):
    pass


class _TorHTTPConnection(http.client.HTTPConnection):
    def connect(self):
        target = self.host
        if target not in ALLOWED_ONION_HOSTS:
            raise TorTransportError("Tor transport only accepts .onion hosts")

        sock = socket.create_connection(
            (SOCKS_HOST, SOCKS_PORT),
            timeout=self.timeout,
            source_address=self.source_address,
        )
        try:
            sock.settimeout(self.timeout)
            sock.sendall(b"\x05\x01\x00")
            greeting = _recv_exact(sock, 2)
            if greeting != b"\x05\x00":
                raise TorTransportError("SOCKS5 authentication negotiation failed")

            host_bytes = target.encode("idna")
            if len(host_bytes) > 255:
                raise TorTransportError("Invalid onion hostname")

            # SOCKS5 CONNECT with domain-name address: DNS resolves inside Tor.
            packet = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes
            packet += struct.pack("!H", self.port or 80)
            sock.sendall(packet)

            head = _recv_exact(sock, 4)
            if head[0] != 5 or head[1] != 0:
                raise TorTransportError("Tor SOCKS5 connection to onion host failed")

            atyp = head[3]
            if atyp == 1:
                _recv_exact(sock, 4)
            elif atyp == 3:
                n = _recv_exact(sock, 1)[0]
                _recv_exact(sock, n)
            elif atyp == 4:
                _recv_exact(sock, 16)
            else:
                raise TorTransportError("Invalid SOCKS5 address type")
            _recv_exact(sock, 2)
            self.sock = sock
        except Exception:
            sock.close()
            raise


def _recv_exact(sock, count):
    chunks = bytearray()
    while len(chunks) < count:
        part = sock.recv(count - len(chunks))
        if not part:
            raise TorTransportError("Unexpected EOF during SOCKS5 handshake")
        chunks.extend(part)
    return bytes(chunks)


def request_json(url, body=None, headers=None, timeout=25, method=None):
    parsed = urlsplit(url)
    if (
        parsed.scheme != "http"
        or not parsed.hostname
        or parsed.hostname not in ALLOWED_ONION_HOSTS
        or parsed.port not in (None, 80)
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise TorTransportError("Only plain HTTP .onion URLs on port 80 are allowed")

    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    payload = None if body is None else json.dumps(body).encode("utf-8")
    request_headers = {
        "Accept": "application/json",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    if payload is not None:
        request_headers["Content-Type"] = "application/json"
    if headers:
        for key, value in headers.items():
            if key.lower() not in ("host", "connection", "transfer-encoding"):
                request_headers[key] = value

    conn = _TorHTTPConnection(parsed.hostname, port=80, timeout=timeout)
    try:
        conn.request(method or ("POST" if payload is not None else "GET"),
                     path, body=payload, headers=request_headers)
        response = conn.getresponse()
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise TorTransportError("Onion response exceeds size limit")
        if response.status < 200 or response.status >= 300:
            raise TorTransportError(f"Onion HTTP status {response.status}")
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TorTransportError("Onion endpoint returned invalid JSON") from exc
    finally:
        conn.close()
