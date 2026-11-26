"""DNS validation utilities for federation candidates.

This module provides a deterministic, side‑effect‑free function to validate that the
hostname part of a candidate's endpoint resolves to at least one IP address. It is
used by the high‑level candidate validation workflow before a federation proposal
is generated.

The implementation relies only on the Python standard library, making it safe to
run in constrained environments and easy to unit‑test.
"""

from __future__ import annotations

import socket
import urllib.parse
from typing import Iterable, Optional

__all__ = ["validate_candidate_dns"]


def _extract_hostname(endpoint: str) -> str:
    """Extract the hostname from a URL or raw hostname.

    The function accepts typical endpoint strings such as:
    - ``https://example.com:443/path``
    - ``example.com``
    - ``example.com:8080``

    It returns the hostname component without port information.
    """
    # If the string looks like a URL, use urllib to parse it.
    if "://" in endpoint:
        parsed = urllib.parse.urlparse(endpoint)
        hostname = parsed.hostname
    else:
        # Split on port delimiter if present.
        hostname = endpoint.split(":", 1)[0]
    if not hostname:
        raise ValueError(f"Unable to extract hostname from endpoint '{endpoint}'.")
    return hostname


def _resolve_hostname(hostname: str) -> list[str]:
    """Resolve *hostname* to a list of IPv4/IPv6 addresses.

    ``socket.getaddrinfo`` is used instead of ``gethostbyname`` to support both
    IPv4 and IPv6. The function returns a list of string representations of the
    resolved addresses. If resolution fails, ``socket.gaierror`` is translated
    into a ``ValueError`` for a cleaner public API.
    """
    try:
        addrinfo = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"DNS resolution failed for hostname '{hostname}': {exc}") from exc

    # Deduplicate the address strings while preserving order.
    seen: set[str] = set()
    results: list[str] = []
    for family, _, _, _, sockaddr in addrinfo:
        ip = sockaddr[0]
        if ip not in seen:
            seen.add(ip)
            results.append(ip)
    return results


def _tld_allowed(hostname: str, allowed_tlds: Optional[Iterable[str]]) -> bool:
    """Return ``True`` if the hostname's top‑level domain is in *allowed_tlds*.

    ``allowed_tlds`` may be ``None`` (no restriction) or an iterable of lower‑case
    TLD strings without the leading dot (e.g. ``["com", "org"]``).
    """
    if not allowed_tlds:
        return True
    # Split on '.' and get the last component.
    tld = hostname.rsplit(".", 1)[-1].lower()
    return tld in {t.lower() for t in allowed_tlds}


def validate_candidate_dns(
    candidate: dict,
    *,
    endpoint_key: str = "endpoint",
    allowed_tlds: Optional[Iterable[str]] = None,
) -> bool:
    """Validate the DNS configuration of a federation *candidate*.

    Parameters
    ----------
    candidate:
        Mapping that must contain an ``endpoint`` (or the custom ``endpoint_key``)
        pointing to a URL or hostname string.
    endpoint_key:
        Key used to locate the endpoint value in ``candidate``. Defaults to
        ``"endpoint"``.
    allowed_tlds:
        Optional iterable of accepted top‑level domains. If supplied, the
        candidate's hostname must end with one of the provided TLDs.

    Returns
    -------
    bool
        ``True`` if the hostname resolves and satisfies the optional TLD policy.
        Raises ``ValueError`` with a descriptive message otherwise.
    """
    if endpoint_key not in candidate:
        raise ValueError(f"Candidate missing required key '{endpoint_key}'.")
    raw_endpoint = str(candidate[endpoint_key]).strip()
    if not raw_endpoint:
        raise ValueError("Candidate endpoint value is empty.")

    hostname = _extract_hostname(raw_endpoint)
    # Enforce optional TLD whitelist before performing a network lookup.
    if not _tld_allowed(hostname, allowed_tlds):
        raise ValueError(
            f"Hostname '{hostname}' does not match allowed TLDs {list(allowed_tlds)}."
        )

    # Perform the resolution; any failure bubbles up as ValueError.
    resolved_ips = _resolve_hostname(hostname)
    if not resolved_ips:
        raise ValueError(f"Hostname '{hostname}' resolved to an empty address list.")

    # Successful validation.
    return True
