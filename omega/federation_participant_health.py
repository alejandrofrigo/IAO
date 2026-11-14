# -*- coding: utf-8 -*-
"""Utilities for checking the operational health of a federation participant.

This module implements a deterministic, testable function that validates the
network readiness of a participant's advertised endpoint. It performs:

1. DNS resolution of the host component of the URL.
2. An HTTPS GET request with a configurable timeout and strict certificate
   verification.
3. Structured reporting of the results, including any raised exceptions.

The function is deliberately side‑effect free and does not modify any global
state. It can be used by operators, automated tests, or higher‑level orchestration
code to ensure that a participant is reachable before invoking federation
operations such as proposal creation or assimilation.
"""

from __future__ import annotations

import socket
import urllib.request
import urllib.error
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urlparse

__all__: list[str] = ["ParticipantHealthResult", "check_participant_health"]


@dataclass(frozen=True)
class ParticipantHealthResult:
    """Result of a health‑check for a federation participant.

    Attributes
    ----------
    participant_id: str
        Identifier of the participant that was checked.
    endpoint: str
        The original endpoint URL supplied for the check.
    dns_resolved: bool
        ``True`` if the host could be resolved to an IP address.
    https_reachable: bool
        ``True`` if an HTTPS GET request succeeded (status 200‑299).
    error: Optional[str]
        Human‑readable error message when either DNS resolution or HTTPS
        connectivity failed. ``None`` when both checks succeed.
    """

    participant_id: str
    endpoint: str
    dns_resolved: bool
    https_reachable: bool
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the dataclass to a plain dictionary for logging or JSON output."""
        return {
            "participant_id": self.participant_id,
            "endpoint": self.endpoint,
            "dns_resolved": self.dns_resolved,
            "https_reachable": self.https_reachable,
            "error": self.error,
        }


def _resolve_host(host: str) -> bool:
    """Attempt to resolve *host* using the system DNS resolver.

    Returns ``True`` if resolution succeeds, ``False`` otherwise.
    """
    try:
        socket.gethostbyname(host)
        return True
    except socket.gaierror:
        return False


def _check_https(url: str, timeout: float = 5.0) -> bool:
    """Perform a simple HTTPS GET request to *url*.

    The request follows redirects and verifies TLS certificates. It returns
    ``True`` when the final response has a status code in the 200‑299 range.
    Any exception (including SSL errors, time‑outs, HTTP errors) results in
    ``False``.
    """
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "IAO-Federation-HealthCheck/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError):
        return False


def check_participant_health(participant: Dict[str, Any], *, timeout: float = 5.0) -> ParticipantHealthResult:
    """Validate DNS and HTTPS connectivity for a registered federation participant.

    Parameters
    ----------
    participant:
        Mapping that must contain at least the keys ``"id"`` (a unique identifier
        string) and ``"endpoint"`` (a fully qualified HTTPS URL).
    timeout:
        Network timeout in seconds for the HTTPS request. Defaults to 5 seconds.

    Returns
    -------
    ParticipantHealthResult
        Structured result indicating which checks succeeded and an optional error
        description when they fail.
    """
    participant_id: str = str(participant.get("id", "<unknown>"))
    endpoint: str = str(participant.get("endpoint", ""))

    if not endpoint:
        return ParticipantHealthResult(
            participant_id=participant_id,
            endpoint=endpoint,
            dns_resolved=False,
            https_reachable=False,
            error="Missing endpoint URL",
        )

    parsed = urlparse(endpoint)
    if parsed.scheme.lower() != "https":
        return ParticipantHealthResult(
            participant_id=participant_id,
            endpoint=endpoint,
            dns_resolved=False,
            https_reachable=False,
            error="Endpoint must use HTTPS scheme",
        )

    host = parsed.hostname or ""
    dns_ok = _resolve_host(host)
    if not dns_ok:
        return ParticipantHealthResult(
            participant_id=participant_id,
            endpoint=endpoint,
            dns_resolved=False,
            https_reachable=False,
            error=f"DNS resolution failed for host '{host}'",
        )

    https_ok = _check_https(endpoint, timeout=timeout)
    if not https_ok:
        return ParticipantHealthResult(
            participant_id=participant_id,
            endpoint=endpoint,
            dns_resolved=True,
            https_reachable=False,
            error="HTTPS connectivity test failed",
        )

    # All checks passed
    return ParticipantHealthResult(
        participant_id=participant_id,
        endpoint=endpoint,
        dns_resolved=True,
        https_reachable=True,
        error=None,
    )
