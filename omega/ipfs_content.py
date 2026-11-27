"""Bounded retrieval of content-addressed data through a local Kubo API."""
from __future__ import annotations

import http.client
import ipaddress
import re
from urllib.parse import quote, urlsplit

CID_V0 = re.compile(r"Qm[1-9A-HJ-NP-Za-km-z]{44}\\Z")
CID_V1_BASE32 = re.compile(r"b[a-z2-7]{20,118}\\Z")
DEFAULT_API = "http://127.0.0.1:5001"
MAX_CONTENT_BYTES = 2_000_000


class IPFSContentError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def validate_cid(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 120:
        return None
    if CID_V0.fullmatch(value) or CID_V1_BASE32.fullmatch(value):
        return value
    return None


def _local_api(value: str) -> tuple[str, int]:
    if not isinstance(value, str) or len(value) > 512:
        raise IPFSContentError("LOCAL_IPFS_API_REQUIRED")
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
        address = ipaddress.ip_address(host or "")
    except (ValueError, TypeError) as exc:
        raise IPFSContentError("LOCAL_IPFS_API_INVALID") from exc
    if (
        parsed.scheme != "http"
        or not address.is_loopback
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or port not in (None, 5001)
    ):
        raise IPFSContentError("LOCAL_IPFS_API_REQUIRED")
    return str(address), port or 5001


def fetch_public_cid(
    cid: str,
    *,
    api_url: str = DEFAULT_API,
    timeout: float = 15.0,
    max_bytes: int = MAX_CONTENT_BYTES,
) -> bytes:
    """Fetch a public CID via an operator-local Kubo API; never executes content."""
    normalized = validate_cid(cid)
    if normalized is None:
        raise IPFSContentError("INVALID_CID")
    if not 0 < timeout <= 30 or not 1 <= max_bytes <= MAX_CONTENT_BYTES:
        raise IPFSContentError("INVALID_CONTENT_LIMIT")
    host, port = _local_api(api_url)
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    target = "/api/v0/cat?arg=" + quote(normalized, safe="")
    try:
        connection.request(
            "POST", target, body=b"",
            headers={
                "Host": f"{host}:{port}",
                "Accept": "application/octet-stream",
                "Content-Length": "0",
                "Connection": "close",
                "User-Agent": "IAO-ipfs-content/1",
            },
        )
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise IPFSContentError("REDIRECT_REFUSED")
        if response.status != 200:
            raise IPFSContentError("IPFS_CONTENT_UNAVAILABLE")
        length = response.getheader("Content-Length")
        if length is not None:
            try:
                if int(length) < 0 or int(length) > max_bytes:
                    raise IPFSContentError("CONTENT_TOO_LARGE")
            except ValueError as exc:
                raise IPFSContentError("INVALID_CONTENT_LENGTH") from exc
        body = response.read(max_bytes + 1)
        if not isinstance(body, bytes) or len(body) > max_bytes:
            raise IPFSContentError("CONTENT_TOO_LARGE")
        return body
    except IPFSContentError:
        raise
    except (OSError, http.client.HTTPException) as exc:
        raise IPFSContentError("IPFS_LOCAL_API_REQUEST_FAILED") from exc
    finally:
        connection.close()
