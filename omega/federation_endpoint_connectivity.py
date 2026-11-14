# -*- coding: utf-8 -*-
"""omega.federation_endpoint_connectivity
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Utility module that provides a deterministic, resource‑limited check of the
network connectivity of a federation candidate endpoint.

The function *does not* perform a full HTTP request; it only attempts a TCP
connection to the host and port derived from the candidate's URL. This keeps the
operation fast, side‑effect‑free and suitable for offline unit‑testing with
mocked sockets.

Typical usage::

    from omega.federation_endpoint_connectivity import check_endpoint_connectivity

    reachable = check_endpoint_connectivity("https://example.com:443")
    if not reachable:
        # handle unreachable candidate
        ...
"""

from __future__ import annotations

import socket
import urllib.parse
from typing import Tuple

__all__: Tuple[str, ...] = ("check_endpoint_connectivity",)


def _parse_endpoint(url: str) -> Tuple[str, int]:
    """Parse *url* and return a (host, port) tuple.

    The URL must use the ``https`` scheme. If the port is omitted, the default
    HTTPS port (443) is assumed. A :class:`ValueError` is raised for unsupported
    schemes or malformed URLs.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() != "https":
        raise ValueError(f"Only HTTPS URLs are supported, got scheme '{parsed.scheme}'")
    host = parsed.hostname
    if not host:
        raise ValueError("URL must contain a hostname")
    port = parsed.port or 443
    return host, port


def check_endpoint_connectivity(url: str, timeout: float = 3.0) -> bool:
    """Return ``True`` if a TCP connection can be established to *url* within *timeout* seconds.

    The function performs a lightweight socket connection; no TLS handshake or
    HTTP request is executed. This makes the check safe for automated tests and
    for environments where external traffic is restricted.

    Parameters
    ----------
    url: str
        The HTTPS endpoint of the candidate, e.g. ``"https://peer.example.org"``.
    timeout: float, optional
        Maximum number of seconds to wait for the connection. Defaults to ``3.0``.

    Returns
    -------
    bool
        ``True`` if the connection succeeds, ``False`` otherwise.
    """
    try:
        host, port = _parse_endpoint(url)
        # ``socket.create_connection`` performs DNS resolution and attempts the
        # TCP handshake. It raises ``OSError`` (including ``socket.timeout``) on
        # failure which we capture and translate to a simple ``False``.
        with socket.create_connection((host, port), timeout):
            return True
    except Exception:
        # Any parsing error, DNS failure, timeout, or connection refusal is
        # treated as a non‑reachable endpoint.
        return False
