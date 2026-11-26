"""Outbound-only libp2p Kademlia discovery for IAO.

Discovered peers are inventory records only. This module never executes peer
code, grants capabilities, or enrolls peers into the HTTP federation.
"""
from __future__ import annotations

import json
import os
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BOOTSTRAP = (
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
    "/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
)
MAX_BOOTSTRAP = 8
MAX_PEERS = 250
CONNECT_TIMEOUT = 8.0
DISCOVERY_TIMEOUT = 30.0


def _secure_identity_file(path: str | Path) -> None:
    """Enforce private permissions on an existing or newly-created node key."""
    target = Path(path)
    if target.is_symlink() or not target.is_file():
        raise RuntimeError("P2P_IDENTITY_PATH_REFUSED")
    try:
        os.chmod(target, 0o600)
        mode = stat.S_IMODE(target.stat().st_mode)
    except OSError as exc:
        raise RuntimeError("P2P_IDENTITY_PERMISSION_HARDENING_FAILED") from exc
    if mode & 0o077:
        raise RuntimeError("P2P_IDENTITY_PERMISSION_HARDENING_FAILED")


def _state_dir() -> Path:
    configured = os.environ.get("IAO_STATE_DIR")
    return Path(configured).expanduser() / "federation" / "libp2p" if configured else ROOT / ".state" / "federation" / "libp2p"


def _validate_bootstrap(values: Any) -> list[str]:
    if not isinstance(values, (list, tuple)):
        return list(DEFAULT_BOOTSTRAP)
    result = []
    for value in values[:MAX_BOOTSTRAP]:
        if (
            isinstance(value, str)
            and value.startswith("/")
            and len(value) <= 512
            and all(32 < ord(char) < 127 for char in value)
            and "/p2p/" in value
            and value not in result
        ):
            result.append(value)
    return result


def _peer_record(peer_id: Any, addrs: Any) -> dict[str, Any] | None:
    try:
        pretty = peer_id.pretty()
    except Exception:
        return None
    if not isinstance(pretty, str) or not 20 <= len(pretty) <= 120:
        return None
    multiaddrs = []
    if isinstance(addrs, (list, tuple)):
        for addr in addrs[:16]:
            value = str(addr)
            if value.startswith("/") and len(value) <= 512 and all(
                32 < ord(char) < 127 for char in value
            ):
                multiaddrs.append(value)
    if not multiaddrs:
        return None
    return {
        "peer_id": pretty,
        "multiaddrs": sorted(set(multiaddrs)),
        "source": "libp2p_kad_dht",
        "status": "DISCOVERED_UNVERIFIED",
        "granted_capabilities": [],
    }


async def discover_peers(
    bootstrap_addrs: Any = None,
    *,
    timeout: float = DISCOVERY_TIMEOUT,
) -> dict[str, Any]:
    """Discover Kademlia routing-table peers as an outbound-only DHT client."""
    import trio
    from multiaddr import Multiaddr
    from libp2p import new_host
    from libp2p.identity_utils import (
        create_identity_from_seed,
        load_identity,
        save_identity,
    )
    from libp2p.kad_dht.kad_dht import DHTMode, KadDHT
    from libp2p.tools.anyio_service import background_trio_service
    from libp2p.tools.utils import info_from_p2p_addr
    import secrets

    state = _state_dir()
    state.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(state, 0o700)
    except OSError:
        pass
    identity_path = state / "peer-identity.key"
    if identity_path.is_symlink():
        raise RuntimeError("P2P_IDENTITY_SYMLINK_REFUSED")
    if identity_path.exists():
        if not identity_path.is_file():
            raise RuntimeError("P2P_IDENTITY_PATH_REFUSED")
        _secure_identity_file(identity_path)
        key_pair = load_identity(identity_path)
    else:
        key_pair = create_identity_from_seed(secrets.token_bytes(32))
        previous_umask = os.umask(0o077)
        try:
            save_identity(key_pair, identity_path)
        finally:
            os.umask(previous_umask)
        _secure_identity_file(identity_path)


    addresses = _validate_bootstrap(bootstrap_addrs)
    if not addresses:
        return {"status": "NO_VALID_BOOTSTRAP_PEERS", "peers": []}

    host = new_host(key_pair=key_pair)
    discovered: dict[str, dict[str, Any]] = {}
    connected = 0
    async with host.run(listen_addrs=[]):
        for address in addresses:
            try:
                peer_info = info_from_p2p_addr(Multiaddr(address))
                host.get_peerstore().add_addrs(peer_info.peer_id, peer_info.addrs, 3600)
                with trio.fail_after(CONNECT_TIMEOUT):
                    await host.connect(peer_info)
                connected += 1
            except Exception:
                continue

        if connected:
            dht = KadDHT(host, DHTMode.CLIENT, enable_random_walk=True)
            with trio.fail_after(timeout):
                async with background_trio_service(dht):
                    try:
                        await dht.refresh_routing_table()
                    except Exception:
                        pass
                    for bucket in dht.routing_table.buckets:
                        for peer_id in bucket.peer_ids():
                            if len(discovered) >= MAX_PEERS:
                                break
                            record = _peer_record(
                                peer_id, host.get_peerstore().addrs(peer_id)
                            )
                            if record:
                                discovered[record["peer_id"]] = record
                    await trio.sleep(0.2)

    result = {
        "status": "DISCOVERY_COMPLETED" if connected else "BOOTSTRAP_UNAVAILABLE",
        "mode": "CLIENT",
        "connected_bootstrappers": connected,
        "routing_peers_discovered": len(discovered),
        "peers": list(discovered.values()),
        "enrollment_performed": False,
        "capabilities_granted": [],
        "remote_code_executed": False,
    }
    result["persisted_new_peers"] = persist_discovered_peers(
        result["peers"], state_dir=state
    )
    return result


def persist_discovered_peers(peers: Any, *, state_dir: str | Path | None = None) -> int:
    """Persist unverified DHT peers separately from HTTP federation candidates."""
    state = Path(state_dir) if state_dir is not None else _state_dir()
    state.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(state, 0o700)
    except OSError:
        pass
    path = state / "peers.json"
    if path.is_symlink():
        raise RuntimeError("P2P_REGISTRY_SYMLINK_REFUSED")
    data = {"schema": 1, "peers": {}}
    if path.exists():
        if not path.is_file():
            raise RuntimeError("P2P_REGISTRY_PATH_REFUSED")
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if (not isinstance(loaded, dict) or loaded.get("schema") != 1
                    or not isinstance(loaded.get("peers"), dict)
                    or len(loaded["peers"]) > MAX_PEERS * 4):
                raise ValueError("INVALID_SCHEMA")
            data = loaded
        except Exception as exc:
            raise RuntimeError("P2P_REGISTRY_INVALID_FAIL_CLOSED") from exc
    records = data["peers"]
    added = 0
    now = datetime.now(timezone.utc).isoformat()
    if not isinstance(peers, (list, tuple)):
        return 0
    for item in peers[:MAX_PEERS]:
        if not isinstance(item, dict):
            continue
        peer_id, addrs = item.get("peer_id"), item.get("multiaddrs")
        if (not isinstance(peer_id, str) or not 20 <= len(peer_id) <= 120
                or not isinstance(addrs, list) or not addrs or len(addrs) > 16
                or any(not isinstance(addr, str) or not addr.startswith("/")
                       or len(addr) > 512 or not all(32 < ord(c) < 127 for c in addr)
                       for addr in addrs)):
            continue
        previous = records.get(peer_id, {})
        records[peer_id] = {
            "peer_id": peer_id, "multiaddrs": sorted(set(addrs)),
            "source": "libp2p_kad_dht", "status": "DISCOVERED_UNVERIFIED",
            "granted_capabilities": [],
            "first_seen": previous.get("first_seen", now), "last_seen": now,
        }
        if not previous:
            added += 1
    ordered = sorted(records.values(), key=lambda x: x.get("last_seen", ""), reverse=True)[:MAX_PEERS]
    payload = {"schema": 1, "peers": {x["peer_id"]: x for x in ordered}}
    fd, temporary = tempfile.mkstemp(prefix=".peers-", dir=str(state))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return added

def discover_sync(bootstrap_addrs: Any = None, *, timeout: float = DISCOVERY_TIMEOUT) -> dict[str, Any]:
    """Synchronous entry point for the autonomous coordinator."""
    import trio
    return trio.run(discover_peers, bootstrap_addrs, timeout=timeout)
