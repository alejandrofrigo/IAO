'''Utility for validating HTTPS endpoint reachability.

This module provides a single function `check_https_endpoint` that performs:
1. Scheme validation (must be ``https``).
2. DNS resolution of the hostname.
3. A ``HEAD`` request over TLS with proper verification.
4. Returns a tuple ``(bool, str)`` where the boolean indicates success and the
   string contains an error message when the check fails.

The implementation deliberately avoids external dependencies beyond the
standard library, ensuring it can be used in constrained environments and
during unit‑test execution without performing real network calls unless the
function is invoked.
''' 

import socket
import ssl
import urllib.parse
import urllib.request
from typing import Tuple


def check_https_endpoint(url: str, timeout: float = 5.0) -> Tuple[bool, str]:
    """Verify that an HTTPS URL is reachable and presents a valid TLS certificate.

    The function performs lightweight checks without downloading the full
    response body:

    * Ensures the URL uses the ``https`` scheme.
    * Resolves the hostname via DNS to catch obvious misconfigurations.
    * Issues a ``HEAD`` request over a verified SSL/TLS context.
    * Considers any 2xx or 3xx HTTP status as a successful connectivity check.

    Parameters
    ----------
    url: str
        The HTTPS endpoint to validate.
    timeout: float, optional
        Network timeout in seconds for DNS resolution and the HTTP request.
        Defaults to ``5.0`` seconds.

    Returns
    -------
    Tuple[bool, str]
        ``(True, '')`` if the endpoint is reachable and the TLS handshake
        succeeded; otherwise ``(False, <error_message>)`` describing the failure.
    """
    try:
        # Parse and validate scheme
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme.lower() != 'https':
            return False, f"URL scheme must be 'https', got '{parsed.scheme}'"

        # Hostname must be present for DNS resolution
        host = parsed.hostname
        if not host:
            return False, "URL does not contain a hostname"

        # DNS resolution (raises socket.gaierror on failure)
        socket.gethostbyname(host)

        # Prepare a HEAD request with a verified SSL context
        context = ssl.create_default_context()
        request = urllib.request.Request(url, method='HEAD')
        with urllib.request.urlopen(request, context=context, timeout=timeout) as response:
            # Accept any 2xx or 3xx status as reachable
            if 200 <= response.status < 400:
                return True, ''
            else:
                return False, f"Unexpected HTTP status {response.status}"
    except Exception as exc:
        # Catch all exceptions and return a readable message
        return False, str(exc)
