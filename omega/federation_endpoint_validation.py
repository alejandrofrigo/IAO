"""Utilities for validating federation endpoint URLs.

This module provides a lightweight, pure‑Python validator that checks:
- The URL uses the ``https`` scheme.
- The host component is either a valid domain name or a valid IPv4/IPv6 address.
- An optional port, if present, is within the TCP/UDP valid range (1‑65535).

The validator deliberately avoids network I/O (DNS look‑up, TLS handshake)
so it can be used safely in sandboxed environments and unit‑tests.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse
from typing import Tuple

# Regular expression for a simple but reasonably strict domain validation.
# Allows punycode (xn--) and typical sub‑domain structures.
_DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+(?:[A-Za-z]{2,})$",
    re.IGNORECASE,
)

def _is_valid_domain(host: str) -> bool:
    """Return ``True`` if *host* matches a conventional DNS hostname.

    The regex enforces length limits, prevents labels that start or end with a hyphen,
    and requires at least one dot separating the top‑level domain.
    """
    return bool(_DOMAIN_REGEX.fullmatch(host))

def _is_valid_ip(host: str) -> bool:
    """Return ``True`` if *host* is a valid IPv4 or IPv6 address.

    IPv6 literals must be supplied without surrounding brackets – those are stripped
    by :func:`urllib.parse.urlparse` when present.
    """
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def validate_https_endpoint(url: str) -> Tuple[bool, str]:
    """Validate that *url* is a well‑formed HTTPS endpoint.

    Parameters
    ----------
    url: str
        The endpoint URL to validate.

    Returns
    -------
    Tuple[bool, str]
        ``(True, "")`` if the URL passes all checks, otherwise ``(False, <reason>)``
        where *reason* explains the first failure encountered.

    Validation steps
    ----------------
    1. Parse the URL with :func:`urllib.parse.urlparse`.
    2. Ensure the scheme is ``https``.
    3. Verify a non‑empty host component exists.
    4. If the host is an IP address, validate it with :mod:`ipaddress`.
       If it is not an IP, validate it as a DNS domain using a regex.
    5. If a port is provided, ensure it is an integer between 1 and 65535.

    The function performs no network operations; it is safe to run in any
    sandboxed or offline context.
    """
    if not isinstance(url, str) or not url:
        return False, "URL must be a non‑empty string"

    parsed = urlparse(url)
    # Scheme check
    if parsed.scheme.lower() != "https":
        return False, f"Invalid scheme '{parsed.scheme}'. Expected 'https'."

    host = parsed.hostname
    if not host:
        return False, "Missing host in URL"

    # IPv6 hosts are returned without brackets by urlparse, which is fine.
    if not (_is_valid_ip(host) or _is_valid_domain(host)):
        return False, f"Host '{host}' is not a valid IP address or domain name"

    # Port validation (optional)
    if parsed.port is not None:
        if not (1 <= parsed.port <= 65535):
            return False, f"Port {parsed.port} out of valid range (1‑65535)"

    # All checks passed
    return True, ""
