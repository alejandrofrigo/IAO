"""Automatic, quarantined assimilation of public libp2p observations.

Assimilation means adding a peer to IAO's local discovery inventory only.
It never enrolls the peer, grants capabilities, or permits remote execution.
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_PEERS = 1000
MAX_MULTIADDRS = 16


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def classify_multiaddr(address: str) -> dict[str, Any]:
    """Classify advertised address hints without claiming the route was tested."""
    parts = [part.lower() for part in address.split("/") if part]
    onion = "onion3" in parts or "onion" in parts
    relay = "p2p-circuit" in parts
    if "quic-v1" in parts or "quic" in parts:
        underlay = "QUIC_UDP" if "udp" in parts else "QUIC"
    elif "tcp" in parts:
        underlay = "TCP"
    elif "udp" in parts:
        underlay = "UDP_UNSPECIFIED"
    else:
        underlay = "UNKNOWN"
    if onion:
        route_class = "TOR_ONION_ADVERTISED"
    elif relay:
        route_class = "LIBP2P_RELAY_ADVERTISED"
    else:
        route_class = underlay
    return {
        "multiaddr": address,
        "route_class": route_class,
        "underlay": underlay,
        "onion_advertised": onion,
        "relay_advertised": relay,
        "connectivity_verified": False,
    }


def _clean_peer(item: Any) -> tuple[str, list[str]] | None:
    if not isinstance(item, dict):
        return None
    peer_id = item.get("peer_id")
    addrs = item.get("multiaddrs")
    if (not isinstance(peer_id, str) or not 20 <= len(peer_id) <= 120
            or not peer_id.isascii() or not peer_id.isalnum()
            or not isinstance(addrs, (list, tuple)) or not addrs
            or len(addrs) > MAX_MULTIADDRS):
        return None
    clean = []
    for addr in addrs:
        if (not isinstance(addr, str) or not addr.startswith("/")
                or len(addr) > 512
                or not all(32 < ord(ch) < 127 for ch in addr)):
            return None
        if addr not in clean:
            clean.append(addr)
    return peer_id, sorted(clean)


def _atomic_write(path: Path, payload: dict[str, Any]) -> None:
    if path.is_symlink():
        raise RuntimeError("P2P_ASSIMILATION_REGISTRY_SYMLINK_REFUSED")
    fd, name = tempfile.mkstemp(prefix=".p2p-assimilation-", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.unlink(name)
        except OSError:
            pass
        raise


def assimilate_discovered_peers(
    peers: Any, *, state_dir: str | Path, now: str | None = None
) -> dict[str, int]:
    """Automatically inventory observed public peers, without trusting them."""
    state = Path(state_dir)
    state.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(state, 0o700)
    except OSError:
        pass
    path = state / "p2p-assimilated-peers.json"
    if path.is_symlink():
        raise RuntimeError("P2P_ASSIMILATION_REGISTRY_SYMLINK_REFUSED")
    data: dict[str, Any] = {"schema": 1, "peers": {}}
    if path.exists():
        if not path.is_file():
            raise RuntimeError("P2P_ASSIMILATION_REGISTRY_PATH_REFUSED")
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if (not isinstance(loaded, dict) or loaded.get("schema") != 1
                    or not isinstance(loaded.get("peers"), dict)
                    or len(loaded["peers"]) > MAX_PEERS * 2):
                raise ValueError("INVALID_SCHEMA")
            data = loaded
        except Exception as exc:
            raise RuntimeError("P2P_ASSIMILATION_REGISTRY_INVALID_FAIL_CLOSED") from exc

    records = data["peers"]
    timestamp = now or _utc()
    added = observed = 0
    if isinstance(peers, (list, tuple)):
        for item in peers[:MAX_PEERS]:
            cleaned = _clean_peer(item)
            if cleaned is None:
                continue
            peer_id, addrs = cleaned
            previous = records.get(peer_id)
            if previous is not None and not isinstance(previous, dict):
                raise RuntimeError("P2P_ASSIMILATION_RECORD_INVALID")
            previous = previous or {}
            merged_addrs = sorted(set(previous.get("multiaddrs", [])) | set(addrs))
            records[peer_id] = {
                "peer_id": peer_id,
                "multiaddrs": merged_addrs[:MAX_MULTIADDRS],
                "address_classes": [
                    classify_multiaddr(address)
                    for address in merged_addrs[:MAX_MULTIADDRS]
                ],
                "transport_classes": sorted({
                    classify_multiaddr(address)["route_class"]
                    for address in merged_addrs[:MAX_MULTIADDRS]
                }),
                "source": "libp2p_kad_dht",
                "assimilation_state": "AUTO_ASSIMILATED_UNVERIFIED",
                "identity_state": "UNVERIFIED",
                "observation_state": "DHT_ROUTING_TABLE_OBSERVED",
                "participation_state": "CANDIDATE_ONLY",
                "first_seen": previous.get("first_seen", timestamp),
                "last_seen": timestamp,
                "observations": min(1_000_000, int(previous.get("observations", 0)) + 1),
                "capabilities": [],
                "granted_capabilities": [],
                "remote_code_execution": False,
                "control_authority": False,
            }
            observed += 1
            if not previous:
                added += 1

    ordered = sorted(
        records.values(),
        key=lambda record: record.get("last_seen", ""),
        reverse=True,
    )[:MAX_PEERS]
    data = {"schema": 1, "peers": {record["peer_id"]: record for record in ordered}}
    _atomic_write(path, data)
    return {"new": added, "observed": observed, "total": len(data["peers"])}
