"""IAO Federated Public Node v1.

Identity and authenticated peer discovery.
No remote command execution is implemented.
"""
from __future__ import annotations

import hmac
import ipaddress
import json
import os
import re
import secrets
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".state" / "federation-public"
PEERS_FILE = STATE / "peers.json"
KEY_FILE = STATE / "bootstrap.key"
NODE_FILE = STATE / "node-id"
MAX_BODY = 16_384
NODE_RE = re.compile(r"^[A-Za-z0-9._-]{8,80}$")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _private_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(content)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def load_identity(state: Path = STATE) -> tuple[str, str]:
    state.mkdir(parents=True, exist_ok=True)
    key_path = state / "bootstrap.key"
    node_path = state / "node-id"

    if not key_path.exists():
        try:
            _private_file(key_path, secrets.token_urlsafe(48))
        except FileExistsError:
            pass
    if not node_path.exists():
        try:
            _private_file(node_path, "iao-" + uuid.uuid4().hex)
        except FileExistsError:
            pass

    os.chmod(key_path, 0o600)
    os.chmod(node_path, 0o600)
    key = key_path.read_text(encoding="utf-8").strip()
    node_id = node_path.read_text(encoding="utf-8").strip()

    if len(key) < 40 or not NODE_RE.fullmatch(node_id):
        raise RuntimeError("Federation identity files are invalid")
    return node_id, key


def valid_base_url(value: str) -> bool:
    """Accept only unambiguous HTTPS URLs with public IPs or DNS names.

    DNS resolution must be checked again at connection time to prevent
    DNS rebinding. This function deliberately does not resolve hostnames.
    """
    if not isinstance(value, str) or not value or len(value) > 500:
        return False
    if any(ord(char) <= 32 or ord(char) == 127 for char in value):
        return False
    if "\\\\" in value:
        return False

    try:
        parsed = urlparse(value)
        if parsed.scheme.lower() != "https":
            return False
        if not parsed.netloc or parsed.username or parsed.password:
            return False
        if parsed.query or parsed.fragment or parsed.path not in ("", "/"):
            return False

        host = parsed.hostname
        port = parsed.port
        if not host or (port is not None and not 1 <= port <= 65535):
            return False

        if host.endswith("."):
            return False

        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            # A DNS name must be fully qualified, syntactically valid,
            # and not belong to a local-only namespace.
            hostname = host.encode("idna").decode("ascii").lower()
            blocked_suffixes = (
                ".localhost", ".local", ".internal",
                ".lan", ".home", ".test",
            )
            if (
                "." not in hostname
                or hostname == "localhost"
                or hostname.endswith(blocked_suffixes)
            ):
                return False

            labels = hostname.split(".")
            if any(
                not label
                or len(label) > 63
                or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
                for label in labels
            ):
                return False
            return True

        return address.is_global

    except (ValueError, UnicodeError):
        return False


class PeerRegistry:
    def __init__(self, path: Path, own_node_id: str):
        self.path = Path(path)
        self.own_node_id = own_node_id
        self.lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _read(self) -> dict:
        if not self.path.exists():
            return {"schema": 1, "peers": {}}
        data = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("peers"), dict):
            raise RuntimeError("Peer registry is malformed")
        return data

    def list_peers(self) -> list[dict]:
        with self.lock:
            data = self._read()
            return sorted(data["peers"].values(), key=lambda item: item["node_id"])

    def register(self, node_id: str, base_url: str) -> dict:
        if not isinstance(node_id, str) or not NODE_RE.fullmatch(node_id):
            raise ValueError("Invalid node_id")
        if node_id == self.own_node_id:
            raise ValueError("A node cannot register itself")
        if not valid_base_url(base_url):
            raise ValueError("Peer URL must use a public HTTPS destination")

        peer = {
            "node_id": node_id,
            "base_url": base_url.rstrip("/"),
            "registered_at": utc_now(),
            "status": "REGISTERED_UNVERIFIED",
            "capabilities": ["identity", "peer_discovery"],
        }

        with self.lock:
            data = self._read()
            data["peers"][node_id] = peer
            temp = self.path.with_suffix(".tmp")
            with temp.open("w", encoding="utf-8") as stream:
                json.dump(data, stream, indent=2, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, self.path)
        return peer


def make_handler(node_id: str, key: str, registry: PeerRegistry):
    class Handler(BaseHTTPRequestHandler):
        server_version = "IAO-Federation/1.0"

        def _send(self, status: int, payload: dict) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _authorized(self) -> bool:
            header = self.headers.get("Authorization", "")
            supplied = header.removeprefix("Bearer ").strip()
            return header.startswith("Bearer ") and hmac.compare_digest(
                supplied.encode(), key.encode()
            )

        def do_GET(self):
            if self.path == "/health/live":
                return self._send(200, {
                    "status": "alive",
                    "node_id": node_id,
                    "service": "iao-federation",
                    "protocol": "v1",
                    "capabilities": ["identity", "peer_discovery"],
                    "remote_execution": False,
                })

            if self.path == "/v1/federation/peers":
                if not self._authorized():
                    return self._send(401, {"error": "authentication_required"})
                return self._send(200, {
                    "node_id": node_id,
                    "peers": registry.list_peers(),
                })

            return self._send(404, {"error": "not_found"})

        def do_POST(self):
            if self.path != "/v1/federation/peers":
                return self._send(404, {"error": "not_found"})
            if not self._authorized():
                return self._send(401, {"error": "authentication_required"})

            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > MAX_BODY:
                    return self._send(413, {"error": "invalid_body_size"})
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict):
                    raise ValueError("JSON object required")
                peer = registry.register(
                    payload.get("node_id"), payload.get("base_url")
                )
                return self._send(201, {
                    "result": "peer_registered",
                    "peer": peer,
                })
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                return self._send(400, {"error": str(exc)})
            except Exception:
                return self._send(500, {"error": "registry_error"})

        def log_message(self, _format, *_args):
            # Avoid logging authorization headers or request bodies.
            return

    return Handler


def serve() -> None:
    node_id, key = load_identity()
    registry = PeerRegistry(PEERS_FILE, node_id)
    bind = os.environ.get("IAO_FEDERATION_BIND", "127.0.0.1")
    port = int(os.environ.get("IAO_FEDERATION_PORT", "8765"))
    if not 1 <= port <= 65535:
        raise ValueError("Invalid federation port")

    server = ThreadingHTTPServer(
        (bind, port), make_handler(node_id, key, registry)
    )
    server.daemon_threads = True
    print("IAO_FEDERATION=RUNNING", flush=True)
    print(f"NODE_ID={node_id}", flush=True)
    print(f"BIND={bind}:{port}", flush=True)
    print(f"PEER_COUNT={len(registry.list_peers())}", flush=True)
    print("PUBLIC_HEALTH=/health/live", flush=True)
    print("AUTHENTICATED_API=/v1/federation/peers", flush=True)
    print("REMOTE_EXECUTION=DISABLED", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    serve()
