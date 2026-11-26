"""IAO's own network plane (diagnostic client). Runs from the IAO process.

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
        r["dns"] = "OK"
    except socket.gaierror as e:
        r.update(dns="FAIL", error_class="DNS_FAILURE", error=str(e))
        return r

    ctx = ssl.create_default_context(cafile=cafile)
    last_error: OSError | None = None
    for family, socktype, proto, _canonname, sockaddr in infos:
        addr = sockaddr[0]
        r["address"] = addr
        r["scope"] = "loopback" if ipaddress.ip_address(addr).is_loopback else "external"
        raw = socket.socket(family, socktype, proto)
        raw.settimeout(timeout)
        try:
            raw.connect(sockaddr)
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                r["tls"] = {"version": tls.version(), "verified": True}
                req = f"GET {path} HTTP/1.1\\r\\nHost: {host}\\r\\nConnection: close\\r\\n\\r\\n"
                tls.sendall(req.encode())
                line = tls.recv(256).split(b"\\r\\n", 1)[0].decode("latin-1")
                parts = line.split()
                if len(parts) >= 2 and parts[0].startswith("HTTP/") and parts[1].isdigit():
                    r["http_status"] = int(parts[1])
                r["error_class"] = None
                r["error"] = None
                break
        except ssl.SSLCertVerificationError as e:
            r.update(error_class="TLS_VERIFY_FAILED", error=str(e))
            break
        except ssl.SSLError as e:
            r.update(error_class="TLS_ERROR", error=str(e))
            break
        except (socket.timeout, TimeoutError) as e:
            last_error = e
            r.update(error_class="TIMEOUT", error=str(e))
        except OSError as e:
            last_error = e
            r.update(error_class="CONNECT_FAILED", error=str(e))
        finally:
            try:
                raw.close()
            except OSError:
                pass
    else:
        if last_error is not None and len(infos) > 1:
            r["error"] = str(last_error)
    r["latency_ms"] = round((time.monotonic() - t0) * 1000, 2)
    if r["error_class"] is None and r["http_status"] is not None:
        r["verdict"] = "DIRECT_INTERNET_CONNECTED" if r["scope"] == "external" else "LOCAL_TLS_OK"
    return r
