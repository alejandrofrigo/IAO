"""SO-OMEGA's own network plane (diagnostic client). Runs from the SO-OMEGA process.

Verdict DIRECT_INTERNET_CONNECTED is only issued for a fully verified TLS+HTTP exchange
with a non-loopback address. Errors are classified separately and never reported as success.
"""
import ipaddress
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any


def probe_https(
    host: str, port: int = 443, timeout: float = 5.0, cafile: str | None = None, path: str = "/"
) -> dict[str, Any]:
    r: dict[str, Any] = {
        "host": host, "port": port, "timestamp": datetime.now(timezone.utc).isoformat(),
        "dns": None, "address": None, "scope": None, "tls": None, "http_status": None,
        "latency_ms": None, "error_class": None, "error": None,
        "verdict": "BLOCKED_NETWORK",
    }
    t0 = time.monotonic()
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        addr = infos[0][4][0]
        r["dns"] = "OK"
        r["address"] = addr
        r["scope"] = "loopback" if ipaddress.ip_address(addr).is_loopback else "external"
    except socket.gaierror as e:
        r.update(dns="FAIL", error_class="DNS_FAILURE", error=str(e))
        return r
    ctx = ssl.create_default_context(cafile=cafile)
    try:
        with socket.create_connection((addr, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                r["tls"] = {"version": tls.version(), "verified": True}
                req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                tls.sendall(req.encode())
                line = tls.recv(256).split(b"\r\n", 1)[0].decode("latin-1")
                parts = line.split()
                if len(parts) >= 2 and parts[0].startswith("HTTP/") and parts[1].isdigit():
                    r["http_status"] = int(parts[1])
    except ssl.SSLCertVerificationError as e:
        r.update(error_class="TLS_VERIFY_FAILED", error=str(e))
    except ssl.SSLError as e:
        r.update(error_class="TLS_ERROR", error=str(e))
    except (socket.timeout, TimeoutError) as e:
        r.update(error_class="TIMEOUT", error=str(e))
    except OSError as e:
        r.update(error_class="CONNECT_FAILED", error=str(e))
    r["latency_ms"] = round((time.monotonic() - t0) * 1000, 2)
    if r["error_class"] is None and r["http_status"] is not None:
        r["verdict"] = "DIRECT_INTERNET_CONNECTED" if r["scope"] == "external" else "LOCAL_TLS_OK"
    return r
