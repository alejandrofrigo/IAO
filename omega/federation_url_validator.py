"""Utilities for validating HTTPS endpoint URLs.

The federation stack needs to ensure that candidate endpoints are well‑formed
and reachable before proposals are generated. This module provides a single
public function ``validate_https_endpoint`` that performs:

1. Scheme validation – only ``https`` is accepted.
2. Host validation – the host part must be either a valid domain name or a
   literal IPv4/IPv6 address.
3. Port validation – if a port is supplied it must be an integer between 1
   and 65535. If omitted, the default HTTPS port 443 is assumed.
4. DNS resolution – the host is resolved using ``socket.getaddrinfo`` with a
   short timeout to guarantee that the endpoint is reachable on the network.

The function raises ``ValueError`` with an explanatory message when a check
fails, otherwise it returns a normalized ``(scheme, host, port)`` tuple.
"""

import re
import socket
from urllib.parse import urlparse
from typing import Tuple

# Regular expression for a simple domain name (does not cover all edge cases but
# is sufficient for federation validation). Allows punycode (xn--) prefixes.
_DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$|^xn--[a-zA-Z0-9-]+$"
)

# Regular expression for IPv4 address.
_IPV4_REGEX = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

# Regular expression for IPv6 address (simplified, relies on socket validation).
_IPV6_REGEX = re.compile(r"^(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")


def _is_valid_host(host: str) -> bool:
    """Return ``True`` if *host* looks like a domain name or an IP address.
    """
    if _DOMAIN_REGEX.fullmatch(host):
        return True
    if _IPV4_REGEX.fullmatch(host):
        return True
    if _IPV6_REGEX.fullmatch(host):
        return True
    return False


def _resolve_host(host: str) -> None:
    """Attempt to resolve *host* using ``socket.getaddrinfo``.

    A ``socket.gaierror`` is raised if the host cannot be resolved. The function
    does not return the addresses – the mere success of the call is sufficient
    for validation purposes.
    """
    # ``0`` as the port allows the OS to select any port for the resolution
    # attempt. ``socket.getaddrinfo`` respects both IPv4 and IPv6.
    socket.getaddrinfo(host, 0, proto=socket.IPPROTO_TCP)


def validate_https_endpoint(url: str) -> Tuple[str, str, int]:
    """Validate that *url* is a well‑formed, resolvable HTTPS endpoint.

    Parameters
    ----------
    url: str
        The endpoint URL to validate.

    Returns
    -------
    tuple(str, str, int)
        Normalised ``(scheme, host, port)`` where ``scheme`` is always ``'https'``.

    Raises
    ------
    ValueError
        If any validation step fails.
    """
    if not isinstance(url, str) or not url:
        raise ValueError("URL must be a non‑empty string")

    parsed = urlparse(url)

    # 1. Scheme validation
    if parsed.scheme.lower() != "https":
        raise ValueError(f"Invalid scheme '{parsed.scheme}': only 'https' is allowed")

    # 2. Host validation
    host = parsed.hostname
    if not host:
        raise ValueError("URL must contain a hostname")
    if not _is_valid_host(host):
        raise ValueError(f"Hostname '{host}' is not a valid domain or IP address")

    # 3. Port validation (default to 443 if omitted)
    port = parsed.port if parsed.port is not None else 443
    if not (1 <= port <= 65535):
        raise ValueError(f"Port '{port}' is out of the valid range 1‑65535")

    # 4. DNS resolution – any resolution error propagates as ValueError.
    try:
        _resolve_host(host)
    except socket.gaierror as exc:
        raise ValueError(f"Hostname '{host}' could not be resolved: {exc}") from exc

    return (parsed.scheme.lower(), host, port)
