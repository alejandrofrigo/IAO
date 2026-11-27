#!/usr/bin/env python3
"""Termux delegated agent: local key custody and read-only status polling only."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import stat
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

PROTOCOL = "IAO-AGENT-REQUEST-V1"
MAX_RESPONSE = 8192
_STOP = False


class AgentClientError(RuntimeError):
    pass


def _private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or not path.is_dir():
        raise AgentClientError("UNSAFE_AGENT_STATE_DIRECTORY")
    os.chmod(path, 0o700)


def _write_private(path: Path, data: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise AgentClientError("AGENT_KEY_ALREADY_EXISTS")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise AgentClientError("AGENT_KEY_PATH_NOT_REGULAR_FILE")
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def init_key(state_dir: Path) -> dict[str, str]:
    _private_dir(state_dir)
    key_path = state_dir / "agent-ecdsa-p256.key"
    key = ec.generate_private_key(ec.SECP256R1())
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    _write_private(key_path, private)
    der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return {"private_key_path": str(key_path), "public_key_pem": public.decode("ascii"), "fingerprint_sha256": hashlib.sha256(der).hexdigest(), "algorithm": "ECDSA-P256-SHA256"}


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise AgentClientError("INVALID_HTTPS_API_ORIGIN")
    if parsed.port not in (None, 443):
        raise AgentClientError("NONSTANDARD_API_PORT_REFUSED")
    return "https://" + parsed.netloc


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AgentClientError("API_REDIRECT_REFUSED")


def _request(origin: str, path: str, method: str, body: bytes = b"") -> dict:
    request = urllib.request.Request(origin + path, data=body if method == "POST" else None, method=method, headers={"Accept": "application/json", "Content-Type": "application/json", "Cache-Control": "no-store"})
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=15) as response:
            if response.status < 200 or response.status >= 300:
                raise AgentClientError("API_REQUEST_REJECTED")
            raw = response.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as exc:
        raise AgentClientError("API_HTTP_" + str(exc.code)) from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise AgentClientError("API_CONNECTION_FAILED") from None
    if len(raw) > MAX_RESPONSE:
        raise AgentClientError("API_RESPONSE_TOO_LARGE")
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise AgentClientError("INVALID_API_RESPONSE") from None
    if not isinstance(result, dict):
        raise AgentClientError("INVALID_API_RESPONSE")
    if "error" in result:
        raise AgentClientError("API_" + str(result["error"])[:80])
    return result


def read_status(origin_value: str, agent_id: str, key_path: Path) -> dict:
    if len(agent_id) != 32 or any(ch not in "0123456789abcdef" for ch in agent_id):
        raise AgentClientError("INVALID_AGENT_ID")
    if key_path.is_symlink() or not key_path.is_file():
        raise AgentClientError("AGENT_PRIVATE_KEY_UNAVAILABLE")
    mode = stat.S_IMODE(key_path.stat().st_mode)
    if mode & 0o077:
        raise AgentClientError("AGENT_PRIVATE_KEY_PERMISSIONS_TOO_OPEN")
    try:
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    except (ValueError, TypeError):
        raise AgentClientError("AGENT_PRIVATE_KEY_INVALID") from None
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise AgentClientError("AGENT_PRIVATE_KEY_UNSUPPORTED")
    origin = _origin(origin_value)
    challenge = _request(origin, "/v1/agent/challenge", "POST", json.dumps({"agent_id": agent_id}, separators=(",", ":")).encode())
    nonce = challenge.get("nonce")
    if challenge.get("protocol") != PROTOCOL or not isinstance(nonce, str) or len(nonce) != 64 or any(ch not in "0123456789abcdef" for ch in nonce):
        raise AgentClientError("INVALID_AGENT_CHALLENGE")
    timestamp = int(time.time())
    payload = json.dumps({"body_sha256": hashlib.sha256(b"").hexdigest(), "method": "GET", "nonce": nonce, "path": "/v1/agent/status", "protocol": PROTOCOL, "timestamp": timestamp}, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    signature = key.sign(b"IAO-AGENT-REQUEST-V1\x00" + payload, ec.ECDSA(hashes.SHA256()))
    import base64
    encoded = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    request = urllib.request.Request(origin + "/v1/agent/status", method="GET", headers={"Accept": "application/json", "Cache-Control": "no-store", "X-IAO-Agent-ID": agent_id, "X-IAO-Agent-Nonce": nonce, "X-IAO-Agent-Timestamp": str(timestamp), "X-IAO-Agent-Signature": encoded})
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=15) as response:
            raw = response.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as exc:
        raise AgentClientError("API_HTTP_" + str(exc.code)) from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise AgentClientError("API_CONNECTION_FAILED") from None
    if len(raw) > MAX_RESPONSE:
        raise AgentClientError("API_RESPONSE_TOO_LARGE")
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise AgentClientError("INVALID_API_RESPONSE") from None
    if not isinstance(result, dict) or "error" in result:
        raise AgentClientError("INVALID_API_RESPONSE")
    return result


def _stop(_signum, _frame):
    global _STOP
    _STOP = True


def main() -> int:
    parser = argparse.ArgumentParser(description="IAO delegated Termux agent (read-only status only)")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="create a local P-256 keypair")
    init.add_argument("--state-dir", default=str(Path.home() / ".local/share/iao-agent"))
    status = sub.add_parser("status", help="perform one signed read-only status request")
    status.add_argument("--origin", required=True)
    status.add_argument("--agent-id", required=True)
    status.add_argument("--key", required=True)
    watch = sub.add_parser("watch", help="repeat signed read-only status requests")
    watch.add_argument("--origin", required=True)
    watch.add_argument("--agent-id", required=True)
    watch.add_argument("--key", required=True)
    watch.add_argument("--interval", type=int, default=60)
    args = parser.parse_args()
    try:
        if args.command == "init":
            result = init_key(Path(args.state_dir).expanduser())
            print(json.dumps(result, ensure_ascii=True, indent=2))
            return 0
        if args.command == "status":
            print(json.dumps(read_status(args.origin, args.agent_id, Path(args.key).expanduser()), ensure_ascii=True))
            return 0
        if not 30 <= args.interval <= 3600:
            raise AgentClientError("WATCH_INTERVAL_OUT_OF_RANGE")
        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)
        while not _STOP:
            try:
                print(json.dumps(read_status(args.origin, args.agent_id, Path(args.key).expanduser()), ensure_ascii=True), flush=True)
            except AgentClientError as exc:
                print(json.dumps({"status": "unavailable", "reason": str(exc)}), flush=True)
            for _ in range(args.interval):
                if _STOP:
                    break
                time.sleep(1)
        return 0
    except AgentClientError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())