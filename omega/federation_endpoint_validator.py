# -*- coding: utf-8 -*-
"""Utility for validating HTTPS endpoints declared by federation participants.

The function :func:`validate_https_endpoint` performs static checks on a URL
string:

* Ensures the scheme is ``https``.
* Confirms the presence of a hostname.
* Validates that the hostname is either a syntactically correct DNS name or an IPv4 address.
* Checks that an optional port, if present, is within the valid TCP port range.

No network I/O is performed; the validation is purely syntactic and therefore
safe for deterministic testing and offline operation.
"""

import re
import urllib.parse
from typing import Tuple

# Regular expression for a simple IPv4 address (e.g., 192.168.1.1)
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
# Regular expression for a permissive DNS hostname (RFC 1035 label rules, simplified)
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}$")


def _is_valid_ipv4(address: str) -> bool:
    """Return True if *address* looks like a valid IPv4 address.

    The check is syntactic only; octet range (0‑255) is not enforced because the
    validator is intended for offline use and stricter checks would require
    additional parsing logic.
    """
    return bool(_IPV4_RE.fullmatch(address))


def _is_valid_hostname(hostname: str) -> bool:
    """Return True if *hostname* conforms to a simplified DNS hostname pattern.

    This pattern accepts typical hostnames such as ``example.com`` or
    ``sub.domain.example``. It deliberately excludes internationalised domain names
    (IDNs) because those are usually represented in Punycode when used in URLs.
    """
    return bool(_HOSTNAME_RE.fullmatch(hostname))


def validate_https_endpoint(url: str) -> Tuple[bool, str]:
    """Validate that *url* is a well‑formed HTTPS endpoint.

    Parameters
    ----------
    url: str
        The endpoint URL to validate.

    Returns
    -------
    Tuple[bool, str]
        A ``(is_valid, error_message)`` pair. ``is_valid`` is ``True`` when the
        URL passes all checks; otherwise ``False`` and *error_message* describes
        the first encountered problem.
    """
    if not isinstance(url, str) or not url:
        return False, "URL must be a non‑empty string"

    parsed = urllib.parse.urlparse(url)

    # Scheme must be https
    scheme = parsed.scheme.lower()
    if scheme != "https":
        return False, f"Invalid scheme '{parsed.scheme}': only 'https' is allowed"

    # Hostname must be present and syntactically valid
    hostname = parsed.hostname
    if not hostname:
        return False, "URL lacks a hostname"
    if not (_is_valid_ipv4(hostname) or _is_valid_hostname(hostname)):
        return False, f"Hostname '{hostname}' is not a valid DNS name or IPv4 address"

    # Port, if given, must be within the TCP range (1‑65535). The default HTTPS
    # port (443) is allowed implicitly when omitted.
    if parsed.port is not None:
        if not (1 <= parsed.port <= 65535):
            return False, f"Port {parsed.port} is out of the valid range 1‑65535"

    # Path, query, fragment are optional and not validated here.
    return True, ""

__all__ = ["validate_https_endpoint"]
