"""Autonomous multi-source discovery and inventory for IAO.

Discovery never grants trust, enrollment, permissions, private-data access or
remote execution. Public peers remain unverified inventory records.
"""
from __future__ import annotations

import fcntl
import hashlib
import ipaddress
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

MAX_CANDIDATES = 5000
MAX_ITEMS = 1000
DEFAULT_INTERVAL = 1800
STALE_AFTER_SECONDS = 7 * 24 * 60 * 60
PRUNE_AFTER_SECONDS = 30 * 24 * 60 * 60
_LOCK = threading.Lock()
_THREAD: threading.Thread | None = None


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _state_dir() -> Path:
    configured = os.environ.get("OMEGA_STATE_DIR")
    return Path(configured).expanduser() / "external-network" if configured else Path(".state/external-network")


def _config_path() -> Path:
    configured = os.environ.get("IAO_NETWORK_DISCOVERY_CONFIG")
    return Path(configured).expanduser() if configured else Path.home() / ".config/iao/network-discovery.json"


def _safe_feed_url(value: Any) -> str | None:
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        return None
    try:
        from omega.federation_transport import validate_discovery_url
        validate_discovery_url(value)
        parsed = urlsplit(value)
        if parsed.query or parsed.fragment or parsed.username or parsed.password:
            return None
        return value
    except Exception:
        return None


def _safe_origin(value: Any) -> str | None:
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        return None
    try:
        parsed = urlsplit(value)
        if (parsed.scheme == "http" and parsed.hostname
                and parsed.hostname.endswith(".onion")
                and len(parsed.hostname) == 62
                and all(char in "abcdefghijklmnopqrstuvwxyz234567"
                        for char in parsed.hostname[:-6])
                and parsed.port in (None, 80)
                and not parsed.username and not parsed.password
                and parsed.path in ("", "/")
                and not parsed.query and not parsed.fragment):
            return "http://" + parsed.hostname
        from omega.federation_transport import validate_discovery_url
        validate_discovery_url(value if parsed.path else value + "/")
        if (parsed.query or parsed.fragment or parsed.username or parsed.password
                or parsed.path not in ("", "/")):
            return None
        try:
            if not ipaddress.ip_address(parsed.hostname).is_global:
                return None
        except ValueError:
            pass
        return f"https://{parsed.netloc}"
    except Exception:
        return None


def _candidate(raw: Any, source: str) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    node_id = raw.get("node_id") or raw.get("peer_id") or raw.get("id")
    origin = raw.get("origin") or raw.get("endpoint") or raw.get("url")
    if (not isinstance(node_id, str) or not 8 <= len(node_id) <= 160
            or any(ord(char) < 33 or ord(char) > 126 for char in node_id)):
        return None
    safe = _safe_origin(origin)
    if safe is None:
        return None
    advertised = raw.get("capabilities", [])
    if isinstance(advertised, dict):
        advertised = list(advertised)
    if not isinstance(advertised, list):
        advertised = []
    capabilities = sorted({
        item for item in advertised[:64]
        if isinstance(item, str) and 1 <= len(item) <= 80
        and all(char.isalnum() or char in "._-" for char in item)
    })
    candidate_id = hashlib.sha256((node_id + "\0" + safe).encode()).hexdigest()
    return {
        "candidate_id": candidate_id,
        "node_id": node_id,
        "origin": safe,
        "source": source[:64],
        "advertised_capabilities": capabilities,
        "status": "DISCOVERED_UNVERIFIED",
        "identity_verified": False,
        "enrolled": False,
        "granted_capabilities": [],
        "remote_code_execution": False,
        "private_data_access": False,
    }


class DiscoverySource(Protocol):
    name: str

    def discover(self) -> list[dict[str, Any]]:
        """Return untrusted discovery records."""


class ConfiguredHTTPSFeeds:
    name = "https_feeds"

    def __init__(self, urls: list[str]):
        self.urls = urls[:MAX_ITEMS]

    def discover(self) -> list[dict[str, Any]]:
        from omega.federation_transport import fetch_public_json
        found: list[dict[str, Any]] = []
        for url in self.urls:
            if _safe_feed_url(url) is None:
                continue
            try:
                payload = fetch_public_json(url, timeout=10, max_bytes=500_000)
            except Exception:
                continue
            items = payload.get("peers", []) if isinstance(payload, dict) else payload
            if isinstance(items, list):
                found.extend(item for item in items[:MAX_ITEMS] if isinstance(item, dict))
        return found


class SignedHTTPSDirectories:
    name = "signed_https_directories"

    def __init__(self, entries: list[dict[str, Any]]):
        self.entries = entries[:MAX_ITEMS]

    def discover(self) -> list[dict[str, Any]]:
        import base64
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from omega.federation_transport import fetch_public_json
        found: list[dict[str, Any]] = []
        for entry in self.entries:
            if not isinstance(entry, dict):
                continue
            url, key_hex = entry.get("url"), entry.get("pubkey_hex")
            if (_safe_feed_url(url) is None or not isinstance(key_hex, str)
                    or len(key_hex) != 64):
                continue
            try:
                document = fetch_public_json(url, timeout=12, max_bytes=1_000_000)
                if not isinstance(document, dict):
                    continue
                signature = document.get("sig")
                body = {key: value for key, value in document.items() if key != "sig"}
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex)).verify(
                    base64.b64decode(signature, validate=True),
                    json.dumps(body, sort_keys=True, separators=(",", ":")).encode(),
                )
                peers = body.get("peers", [])
                if isinstance(peers, list):
                    found.extend(item for item in peers[:MAX_ITEMS] if isinstance(item, dict))
            except Exception:
                continue
        return found


class TorOnionDirectories:
    """Read public peer advertisements from v3 onion directories over Tor."""
    name = "tor_onion_directories"

    def __init__(self, urls: list[str]):
        self.urls = urls[:MAX_ITEMS]

    def discover(self) -> list[dict[str, Any]]:
        from omega.federation_transport import fetch_onion_json
        found: list[dict[str, Any]] = []
        for url in self.urls:
            try:
                payload = fetch_onion_json(url, timeout=15, max_bytes=500_000)
            except Exception:
                continue
            items = payload.get("peers", []) if isinstance(payload, dict) else payload
            if isinstance(items, list):
                found.extend(item for item in items[:MAX_ITEMS] if isinstance(item, dict))
        return found



class IPFSSwarmDiscovery:
    """Read the local IPFS daemon's connected swarm peers; never contact remote APIs."""
    name = "ipfs_swarm"

    def __init__(self, api: str):
        self.api = api

    def discover(self) -> list[dict[str, Any]]:
        import urllib.request
        try:
            parsed = urlsplit(self.api)
            host = (parsed.hostname or "").lower()
            if (parsed.scheme != "http" or host not in {"127.0.0.1", "localhost", "::1"}
                    or parsed.username or parsed.password or parsed.path not in ("", "/")
                    or parsed.query or parsed.fragment or parsed.port not in (None, 5001)):
                return []
            request = urllib.request.Request(
                self.api.rstrip("/") + "/api/v0/swarm/peers",
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            class _NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, new_url):
                    return None
            opener = urllib.request.build_opener(_NoRedirect)
            with opener.open(request, timeout=8) as response:
                payload = json.loads(response.read(500_001))
            if not isinstance(payload, dict):
                return []
            peers = payload.get("Peers", [])
            if not isinstance(peers, list):
                return []
            found = []
            seen = set()
            for peer in peers[:MAX_CANDIDATES]:
                if not isinstance(peer, dict):
                    continue
                peer_id, address = peer.get("Peer"), peer.get("Addr")
                if (not isinstance(peer_id, str) or not 20 <= len(peer_id) <= 100
                        or not peer_id.isalnum() or not isinstance(address, str)
                        or not address.startswith("/") or len(address) > 512
                        or any(ord(ch) < 33 or ord(ch) > 126 for ch in address)
                        or peer_id in seen):
                    continue
                seen.add(peer_id)
                found.append({"peer_id": peer_id, "multiaddr": [address]})
            return found
        except Exception:
            return []


class NostrAuthorizationDiscovery:
    """Verify explicit Nostr bridge authorization events; never treat relays as nodes."""
    name = "nostr_authorizations"

    def __init__(self, relays: list[str] | None = None):
        self.relays = relays

    def discover(self) -> list[dict[str, Any]]:
        import asyncio
        from omega.federation_protocols.nostr_bridge import discover_nostr_authorizations
        try:
            events = asyncio.run(discover_nostr_authorizations(self.relays))
        except RuntimeError:
            # If called from an event-loop thread, do not nest or bypass the loop.
            return []
        return [
            {
                "event_id": event.get("id"),
                "author_pubkey": event.get("pubkey"),
                "created_at": event.get("created_at"),
                "kind": 1,
                "source": "nostr_signed_authorization",
                "authorization_event_verified": True,
            }
            for event in events[:MAX_ITEMS]
            if isinstance(event, dict)
            and isinstance(event.get("id"), str)
            and isinstance(event.get("pubkey"), str)
        ]


class GitHubPublicDiscovery:
    """GitHub is an optional discovery adapter, not the network's authority."""
    name = "github_public_search"

    def __init__(self, state_dir: Path):
        self.state_dir = state_dir

    def discover(self) -> list[dict[str, Any]]:
        # Reuse the independent worker's evidence log; avoid duplicate GitHub API searches.
        log_path = self.state_dir.parent / "federation-discovery.jsonl"
        if not log_path.is_file() or log_path.is_symlink():
            return []
        with log_path.open("rb") as stream:
            stream.seek(max(0, log_path.stat().st_size - 2_000_000))
            lines = stream.read(2_000_000).splitlines()
        records = []
        for line in lines:
            try:
                event = json.loads(line)
            except (ValueError, UnicodeDecodeError):
                continue
            if event.get("event") == "NODE_CANDIDATE_DISCOVERED":
                records.append(event)
        return records


class Libp2pDHTDiscovery:
    """Actively join the public Kademlia DHT in outbound-only client mode."""
    name = "libp2p_kad_dht"

    def __init__(self, bootstrap_addrs: list[str] | None = None):
        self.bootstrap_addrs = bootstrap_addrs

    def discover(self) -> list[dict[str, Any]]:
        from omega.libp2p_discovery import discover_sync
        result = discover_sync(self.bootstrap_addrs, timeout=25)
        peers = result.get("peers", []) if isinstance(result, dict) else []
        return [
            {"peer_id": peer.get("peer_id"), "multiaddr": peer.get("multiaddrs", [])}
            for peer in peers[:MAX_CANDIDATES] if isinstance(peer, dict)
        ]


class LocalP2PInventory:
    """Import libp2p peer IDs and multiaddrs without fabricating HTTPS endpoints."""
    name = "local_p2p_inventory"

    def __init__(self, state_dir: Path):
        self.state_dir = state_dir.parent if state_dir.name == "external-network" else state_dir

    def discover(self) -> list[dict[str, Any]]:
        path = self.state_dir / "federation" / "libp2p" / "peers.json"
        if path.is_symlink() or not path.is_file():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        peers = data.get("peers", {}) if isinstance(data, dict) else {}
        if not isinstance(peers, dict):
            return []
        return [
            {"peer_id": peer_id, "multiaddr": item.get("multiaddrs", [])}
            for peer_id, item in list(peers.items())[:MAX_CANDIDATES]
            if isinstance(peer_id, str) and isinstance(item, dict)
        ]


class ExternalNetwork:
    def __init__(self, state_dir: str | Path, sources: list[DiscoverySource]):
        self.state_dir = Path(state_dir)
        self.registry_path = self.state_dir / "registry.json"
        self.audit_path = self.state_dir / "events.jsonl"
        self.sources = sources

    def _audit(self, event: str, **details: Any) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.state_dir, 0o700)
        entry = {"timestamp": _utc(), "event": event, **details}
        fd = os.open(self.audit_path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        try:
            os.write(fd, (json.dumps(entry, sort_keys=True) + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)

    def _load_registry(self) -> dict[str, Any]:
        if self.registry_path.is_symlink():
            raise RuntimeError("EXTERNAL_NETWORK_REGISTRY_SYMLINK_REFUSED")
        if not self.registry_path.exists():
            return {"schema": 1, "candidates": {}, "p2p_peers": {}, "protocol_peers": {}}
        data = json.loads(self.registry_path.read_text(encoding="utf-8"))
        if (not isinstance(data, dict) or data.get("schema") != 1
                or not isinstance(data.get("candidates"), dict)
                or len(data["candidates"]) > MAX_CANDIDATES
                or not isinstance(data.get("p2p_peers", {}), dict)
                or len(data.get("p2p_peers", {})) > MAX_CANDIDATES
                or not isinstance(data.get("protocol_peers", {}), dict)
                or len(data.get("protocol_peers", {})) > MAX_CANDIDATES):
            raise RuntimeError("EXTERNAL_NETWORK_REGISTRY_INVALID")
        return data

    def _save_registry(self, data: dict[str, Any]) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.state_dir, 0o700)
        temporary = self.registry_path.with_suffix(".json.tmp")
        fd = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        try:
            payload = (json.dumps(data, sort_keys=True, ensure_ascii=False) + "\n").encode()
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, self.registry_path)
        directory_fd = os.open(self.state_dir, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def run_cycle(self) -> dict[str, Any]:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        with (self.state_dir / "cycle.lock").open("a") as lock:
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return {"status": "ALREADY_RUNNING", "sources": 0,
                        "discovered": 0, "added": 0}
            registry = self._load_registry()
            candidates = registry["candidates"]
            p2p_peers = registry.setdefault("p2p_peers", {})
            protocol_peers = registry.setdefault("protocol_peers", {})
            totals = {"status": "COMPLETED", "sources": 0, "source_errors": 0,
                      "discovered": 0, "added": 0, "refreshed": 0}
            for source in self.sources:
                totals["sources"] += 1
                try:
                    found = source.discover()
                    if not isinstance(found, list):
                        raise TypeError("SOURCE_RESULT_MUST_BE_LIST")
                    for raw in found[:MAX_CANDIDATES]:
                        if source.name == "nostr_authorizations":
                            if not isinstance(raw, dict):
                                continue
                            event_id, author = raw.get("event_id"), raw.get("author_pubkey")
                            if (not isinstance(event_id, str) or not 16 <= len(event_id) <= 128
                                    or not isinstance(author, str) or len(author) != 64
                                    or any(ch not in "0123456789abcdef" for ch in author)
                                    or raw.get("authorization_event_verified") is not True):
                                continue
                            now = _utc()
                            previous = protocol_peers.get(event_id, {})
                            protocol_peers[event_id] = {
                                "event_id": event_id, "author_pubkey": author,
                                "source": source.name,
                                "status": "AUTHORIZATION_EVENT_VERIFIED",
                                "identity_verified": False, "enrolled": False,
                                "granted_capabilities": [],
                                "first_seen": previous.get("first_seen", now),
                                "last_seen": now,
                            }
                            totals["discovered"] += 1
                            totals["refreshed" if previous else "added"] += 1
                            continue
                        if source.name in {"local_p2p_inventory", "libp2p_kad_dht", "ipfs_swarm"}:
                            if not isinstance(raw, dict):
                                continue
                            peer_id, addrs = raw.get("peer_id"), raw.get("multiaddr")
                            if (not isinstance(peer_id, str) or not 20 <= len(peer_id) <= 120
                                    or not isinstance(addrs, list) or not addrs
                                    or len(addrs) > 16
                                    or any(not isinstance(addr, str) or not addr.startswith("/")
                                           or len(addr) > 512 for addr in addrs)):
                                continue
                            previous = p2p_peers.get(peer_id, {})
                            now = _utc()
                            p2p_peers[peer_id] = {
                                "peer_id": peer_id, "multiaddrs": addrs,
                                "source": source.name, "status": "DISCOVERED_UNVERIFIED",
                                "first_seen": previous.get("first_seen", now),
                                "last_seen": now, "granted_capabilities": [],
                                "remote_code_execution": False, "private_data_access": False,
                            }
                            totals["discovered"] += 1
                            totals["refreshed" if previous else "added"] += 1
                            continue
                        item = _candidate(raw, source.name)
                        if item is None:
                            continue
                        totals["discovered"] += 1
                        previous = candidates.get(item["candidate_id"])
                        now = _utc()
                        item["first_seen"] = previous.get("first_seen", now) if previous else now
                        item["last_seen"] = now
                        item["observations"] = min(1_000_000, int(previous.get("observations", 1)) + 1) if previous else 1
                        # Discovery refreshes observations, never overwrites locally
                        # verified identity/enrollment state for the same node+origin.
                        if previous and previous.get("node_id") == item["node_id"] and previous.get("origin") == item["origin"]:
                            for field in (
                                "status", "identity_verified", "enrolled",
                            ):
                                if field in previous:
                                    item[field] = previous[field]
                            if item.get("status") == "STALE_UNVERIFIED":
                                item["status"] = "DISCOVERED_UNVERIFIED"
                            previous_caps = previous.get("granted_capabilities", [])
                            if isinstance(previous_caps, list):
                                item["granted_capabilities"] = sorted(
                                    set(previous_caps) & {"knowledge.search"}
                                )
                        candidates[item["candidate_id"]] = item
                        totals["refreshed" if previous else "added"] += 1
                    self._audit("DISCOVERY_SOURCE_COMPLETED", source=source.name,
                                candidates=len(found))
                except Exception as exc:
                    totals["source_errors"] += 1
                    self._audit("DISCOVERY_SOURCE_FAILED", source=source.name,
                                error_type=type(exc).__name__)
            # Age only unverified inventory. Enrolled/verified records are retained
            # for explicit lifecycle/revocation handling, never silently deleted.
            now_epoch = time.time()
            aged = {"stale": 0, "pruned": 0}
            for collection in (candidates, p2p_peers, protocol_peers):
                for key, item in list(collection.items()):
                    try:
                        seen = datetime.fromisoformat(
                            str(item.get("last_seen", "")).replace("Z", "+00:00")
                        ).timestamp()
                    except (TypeError, ValueError, OverflowError):
                        seen = 0.0
                    age = max(0.0, now_epoch - seen)
                    untrusted = (
                        item.get("status", "DISCOVERED_UNVERIFIED") in {
                            "DISCOVERED_UNVERIFIED", "STALE_UNVERIFIED"
                        }
                        and item.get("identity_verified") is not True
                        and item.get("enrolled") is not True
                    )
                    if untrusted and age >= PRUNE_AFTER_SECONDS:
                        del collection[key]
                        aged["pruned"] += 1
                    elif untrusted and age >= STALE_AFTER_SECONDS:
                        if item.get("status") != "STALE_UNVERIFIED":
                            item["status"] = "STALE_UNVERIFIED"
                            aged["stale"] += 1
            totals.update(aged)
            ordered = sorted(candidates.values(),
                             key=lambda item: item.get("last_seen", ""), reverse=True)
            registry["candidates"] = {
                item["candidate_id"]: item for item in ordered[:MAX_CANDIDATES]
            }
            registry["p2p_peers"] = dict(list(p2p_peers.items())[-MAX_CANDIDATES:])
            registry["protocol_peers"] = dict(list(protocol_peers.items())[-MAX_CANDIDATES:])
            registry["updated_at"] = _utc()
            self._save_registry(registry)
            self._audit("EXTERNAL_NETWORK_CYCLE_COMPLETED", **totals)
            return totals


def build_network(state_dir: str | Path | None = None) -> ExternalNetwork:
    state = Path(state_dir) if state_dir is not None else _state_dir()
    config_path = _config_path()
    config: dict[str, Any] = {}
    if config_path.is_file() and not config_path.is_symlink():
        loaded = json.loads(config_path.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            raise RuntimeError("NETWORK_DISCOVERY_CONFIG_INVALID")
        config = loaded
    sources: list[DiscoverySource] = []
    github = config.get("github", {})
    if not isinstance(github, dict):
        github = {}
    if github.get("enabled", True):
        sources.append(GitHubPublicDiscovery(state))
    feeds = config.get("https_feeds", [])
    if isinstance(feeds, list) and feeds:
        sources.append(ConfiguredHTTPSFeeds(feeds))
    directories = config.get("signed_directories", [])
    if isinstance(directories, list) and directories:
        sources.append(SignedHTTPSDirectories(directories))
    onion_feeds = config.get("tor_onion_feeds", [])
    if isinstance(onion_feeds, list) and onion_feeds:
        sources.append(TorOnionDirectories(onion_feeds))
    sources.append(LocalP2PInventory(state))
    ipfs = config.get("ipfs", {})
    if isinstance(ipfs, dict) and ipfs.get("enabled") is True:
        api = ipfs.get("api", "http://127.0.0.1:5001")
        if isinstance(api, str):
            sources.append(IPFSSwarmDiscovery(api))
    nostr = config.get("nostr", {})
    if not isinstance(nostr, dict):
        nostr = {}
    if nostr.get("enabled") is True:
        relays = nostr.get("relays")
        sources.append(NostrAuthorizationDiscovery(relays if isinstance(relays, list) else None))
    p2p = config.get("libp2p", {})
    if not isinstance(p2p, dict):
        p2p = {}
    if p2p.get("enabled", True):
        try:
            import importlib.util
            available = importlib.util.find_spec("libp2p") is not None
        except (ImportError, ModuleNotFoundError, ValueError):
            available = False
        if available:
            bootstrap = p2p.get("bootstrap_addrs")
            sources.append(Libp2pDHTDiscovery(bootstrap if isinstance(bootstrap, list) else None))
    return ExternalNetwork(state, sources)


def network_status(state_dir: str | Path | None = None) -> dict[str, Any]:
    """Return privacy-safe inventory metrics; never expose peer identifiers or endpoints."""
    state = Path(state_dir) if state_dir is not None else _state_dir()
    registry_path = state / "registry.json"
    if registry_path.is_symlink():
        return {"status": "restricted", "reason": "REGISTRY_SYMLINK_REFUSED"}
    try:
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {
            "status": "unknown", "candidate_count": 0, "p2p_peer_count": 0,
            "protocol_peer_count": 0, "last_updated": None,
            "last_cycle": None, "external_connectivity_confirmed": False,
        }
    except (OSError, ValueError, UnicodeError):
        return {"status": "degraded", "reason": "REGISTRY_UNREADABLE"}
    if (not isinstance(registry, dict) or registry.get("schema") != 1
            or not isinstance(registry.get("candidates"), dict)
            or not isinstance(registry.get("p2p_peers", {}), dict)
            or not isinstance(registry.get("protocol_peers", {}), dict)):
        return {"status": "degraded", "reason": "REGISTRY_INVALID"}

    last_cycle = None
    audit_path = state / "events.jsonl"
    if audit_path.is_file() and not audit_path.is_symlink():
        try:
            with audit_path.open("rb") as stream:
                stream.seek(max(0, audit_path.stat().st_size - 262144))
                lines = stream.read(262144).splitlines()
            for line in reversed(lines):
                try:
                    event = json.loads(line)
                except (ValueError, UnicodeDecodeError):
                    continue
                if event.get("event") == "EXTERNAL_NETWORK_CYCLE_COMPLETED":
                    last_cycle = {
                        key: event[key] for key in (
                            "timestamp", "sources", "source_errors", "discovered",
                            "added", "refreshed", "stale", "pruned",
                        ) if key in event
                    }
                    break
        except OSError:
            pass
    candidates = registry["candidates"]
    p2p = registry.get("p2p_peers", {})
    protocol = registry.get("protocol_peers", {})
    status = "degraded" if last_cycle and last_cycle.get("source_errors", 0) else (
        "observed" if last_cycle else "unknown"
    )
    return {
        "status": status,
        "candidate_count": len(candidates),
        "p2p_peer_count": len(p2p),
        "protocol_peer_count": len(protocol),
        "last_updated": registry.get("updated_at"),
        "last_cycle": last_cycle,
        "external_connectivity_confirmed": False,
        "cryptographic_trust_confirmed": False,
    }


def start_external_network(state_dir: str | Path | None = None, fed_node=None) -> bool:
    """Start one bounded discovery worker inside the IAO server process."""
    global _THREAD
    with _LOCK:
        if _THREAD is not None and _THREAD.is_alive():
            return False
        network = build_network(state_dir)
        interval = max(300, int(os.environ.get("IAO_EXTERNAL_NETWORK_INTERVAL", DEFAULT_INTERVAL)))

        def worker() -> None:
            network.state_dir.mkdir(parents=True, exist_ok=True)
            with (network.state_dir / "worker.lock").open("a") as lock:
                try:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    return
                while True:
                    try:
                        result = network.run_cycle()
                        if fed_node is not None:
                            try:
                                from omega.federation_autonomous import run_discovered_cycle
                                result["federation"] = run_discovered_cycle(
                                    fed_node, network.state_dir,
                                    network.registry_path,
                                )
                            except Exception as federation_error:
                                network._audit(
                                    "FEDERATION_AUTOJOIN_CYCLE_FAILED",
                                    error_type=type(federation_error).__name__,
                                )
                                result["federation"] = {"status": "DEGRADED"}
                        print("IAO_EXTERNAL_NETWORK " + json.dumps(result, sort_keys=True), flush=True)
                    except Exception as exc:
                        network._audit("EXTERNAL_NETWORK_WORKER_FAILED",
                                       error_type=type(exc).__name__)
                    time.sleep(interval)

        _THREAD = threading.Thread(target=worker, name="iao-external-network", daemon=True)
        _THREAD.start()
        return True
