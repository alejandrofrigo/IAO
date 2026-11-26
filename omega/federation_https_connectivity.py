"""Utilities for verifying HTTPS connectivity of federation candidates.

This module provides a single, minimal helper that attempts to establish an HTTPS
connection to a given host (optionally a specific port) and performs a HEAD
request. The function returns ``True`` if the request succeeds with a status
code lower than 400, indicating that the endpoint is reachable and appears to
serve HTTP(S) content. Any exception (network error, SSL verification failure,
timeout, etc.) results in ``False``.

The implementation uses the standard library only (``http.client`` and
``ssl``) to avoid external dependencies and to work in constrained execution
environments. It respects the global SSL verification settings and uses a
reasonable default timeout.
"""

from __future__ import annotations

import ssl
import http.client
from typing import Optional

__all__ = ["check_https_connectivity"]


def check_https_connectivity(host: str, *, port: int = 443, timeout: float = 5.0, path: str = "/", verify_ssl: bool = True) -> bool:
    """Return ``True`` if an HTTPS ``HEAD`` request to *host*/*path* succeeds.

    Parameters
    ----------
    host: str
        The DNS name or IP address of the target server.
    port: int, optional
        TCP port to connect to (default ``443``).
    timeout: float, optional
        Seconds to wait for the connection and response (default ``5.0``).
    path: str, optional
        The request path used for the ``HEAD`` request (default ``"/"``).
    verify_ssl: bool, optional
        Whether to verify the server's TLS certificate. Setting this to ``False``
        disables verification – useful for testing against self‑signed
        certificates – but should be ``True`` in production.

    Returns
    -------
    bool
        ``True`` if the server responded with a status code < 400, otherwise
        ``False``.
    """
    try:
        context: Optional[ssl.SSLContext] = None
        if verify_ssl:
            context = ssl.create_default_context()
        else:
            # Create an unverified context – only for non‑production use.
            context = ssl._create_unverified_context()

        conn = http.client.HTTPSConnection(host, port=port, timeout=timeout, context=context)
        conn.request("HEAD", path)
        response = conn.getresponse()
        # Consider any 2xx or 3xx status as successful connectivity.
        success = response.status < 400
        conn.close()
        return success
    except Exception:
        # Any networking or SSL error is treated as lack of connectivity.
        return False
