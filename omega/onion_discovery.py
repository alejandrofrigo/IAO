"""Tor onion-service discovery and quarantined candidate inventory for IAO."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from omega.ipfs_content import validate_cid
from omega.federation_transport import (
    FederationTransportError,
    _parse_onion_url,
    fetch_onion_json,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STATE = ROOT / ".state"
DEFAULT_SOURCES = DEFAULT_STATE / "iao-federation-sources.json"


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def discover_onion_feed(url: str, timeout: float = 15.0) -> list[dict[str, Any]]:
    """Fetch a bounded public v3 onion feed through the local Tor SOCKS proxy."""
    try:
        _parse_onion_url(url)
        data = fetch_onion_json(url, timeout=timeout, max_bytes=500_000)
    except Exception:
        return []
    if isinstance(data, list):
        peers = data
    elif isinstance(data, dict):
        peers = data.get("peers", [])
    else:
        return []
    if not isinstance(peers, list):
        return []
    result = []
    for peer in peers[:100]:
        if not isinstance(peer, dict):
            continue
        endpoint = peer.get("url") or peer.get("onion_url")
        if not isinstance(endpoint, str):
            continue
        try:
            _parse_onion_url(endpoint)
        except FederationTransportError:
            continue
        peer_id = peer.get("peer_id")
        if peer_id is not None and (
            not isinstance(peer_id, str)
            or not 20 <= len(peer_id) <= 120
            or not peer_id.isascii()
            or not peer_id.isalnum()
        ):
            peer_id = None
        announced_cids = peer.get("cids", [])
        if not isinstance(announced_cids, list):
            announced_cids = []
        content_cids = list(dict.fromkeys(
            normalized for item in announced_cids[:32]
            if (normalized := validate_cid(item)) is not None
        ))
        result.append({
            "service_url": endpoint,
            "peer_id": peer_id,
            "content_cids": content_cids,
            "source": "tor_onion_feed",
            "identity_state": "UNVERIFIED",
            "participation_state": "CANDIDATE_ONLY",
            "capabilities": [],
            "granted_capabilities": [],
            "remote_code_execution": False,
            "control_authority": False,
        })
    return result


def merge_onion_candidates(
    candidates: list[dict[str, Any]], *, state_dir: str | Path | None = None
) -> dict[str, int]:
    """Persist advertised onion services without probing or trusting them."""
    state = Path(state_dir) if state_dir is not None else DEFAULT_STATE
    state.mkdir(parents=True, exist_ok=True)
    path = state / "iao-onion-candidates.json"
    if path.is_symlink():
        raise RuntimeError("ONION_CANDIDATE_REGISTRY_SYMLINK_REFUSED")
    data = {"schema": 1, "services": {}}
    if path.exists():
        if not path.is_file():
            raise RuntimeError("ONION_CANDIDATE_REGISTRY_PATH_REFUSED")
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise RuntimeError("ONION_CANDIDATE_REGISTRY_INVALID") from exc
        if (
            not isinstance(loaded, dict)
            or loaded.get("schema") != 1
            or not isinstance(loaded.get("services"), dict)
            or len(loaded["services"]) > 2000
        ):
            raise RuntimeError("ONION_CANDIDATE_REGISTRY_INVALID")
        data = loaded

    services = data["services"]
    added = observed = 0
    now = _utc()
    for candidate in candidates[:100]:
        if not isinstance(candidate, dict) or candidate.get("source") != "tor_onion_feed":
            continue
        endpoint = candidate.get("service_url")
        try:
            host, port, target = _parse_onion_url(endpoint)
        except Exception:
            continue
        key = hashlib.sha256(endpoint.encode("utf-8")).hexdigest()
        previous = services.get(key, {})
        if previous and not isinstance(previous, dict):
            raise RuntimeError("ONION_CANDIDATE_RECORD_INVALID")
        peer_id = candidate.get("peer_id")
        if (
            not isinstance(peer_id, str)
            or not 20 <= len(peer_id) <= 120
            or not peer_id.isascii()
            or not peer_id.isalnum()
        ):
            peer_id = None
        services[key] = {
            "service_url": endpoint,
            "onion_host": host,
            "virtual_port": port,
            "path": target,
            "peer_id": peer_id,
            "content_cids": sorted(set(previous.get("content_cids", [])) | set(
                item for item in candidate.get("content_cids", [])
                if validate_cid(item) is not None
            ))[:32],
            "source": "tor_onion_feed",
            "discovery_state": "FEED_ADVERTISED_UNPROBED",
            "identity_state": "UNVERIFIED",
            "participation_state": "CANDIDATE_ONLY",
            "first_seen": previous.get("first_seen", now),
            "last_seen": now,
            "capabilities": [],
            "granted_capabilities": [],
            "remote_code_execution": False,
            "control_authority": False,
        }
        observed += 1
        if not previous:
            added += 1

    ordered = sorted(
        services.items(),
        key=lambda item: item[1].get("last_seen", ""),
        reverse=True,
    )[:1000]
    payload = {"schema": 1, "services": dict(ordered)}
    fd, name = tempfile.mkstemp(prefix=".onion-candidates-", dir=str(state))
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
    return {"new": added, "observed": observed, "total": len(payload["services"])}


def run_configured_onion_discovery(
    *, sources_path: str | Path | None = None, state_dir: str | Path | None = None
) -> dict[str, Any]:
    """Run configured onion feeds as an independent transport leg of NODE_NETWORK."""
    source_path = Path(sources_path) if sources_path is not None else DEFAULT_SOURCES
    if source_path.is_symlink():
        raise RuntimeError("ONION_SOURCES_SYMLINK_REFUSED")
    if not source_path.exists():
        return {"status": "NO_ONION_FEEDS_CONFIGURED", "feeds_checked": 0,
                "candidates": 0, "assimilation": {"new": 0, "observed": 0, "total": 0}}
    if not source_path.is_file() or source_path.stat().st_size > 262_144:
        raise RuntimeError("ONION_SOURCES_PATH_OR_SIZE_REFUSED")
    try:
        sources = json.loads(source_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError("ONION_SOURCES_INVALID") from exc
    if not isinstance(sources, dict):
        raise RuntimeError("ONION_SOURCES_INVALID")
    feeds = sources.get("onion_feeds", [])
    if not isinstance(feeds, list):
        raise RuntimeError("ONION_FEEDS_INVALID")
    candidates = []
    checked = 0
    for feed in feeds[:20]:
        if not isinstance(feed, str):
            continue
        checked += 1
        candidates.extend(discover_onion_feed(feed))
    assimilation = merge_onion_candidates(candidates, state_dir=state_dir)
    return {
        "status": "ONION_DISCOVERY_COMPLETED",
        "feeds_checked": checked,
        "candidates": len(candidates),
        "assimilation": assimilation,
        "identity_verification": "NOT_PERFORMED",
        "enrollment_performed": False,
        "capabilities_granted": [],
        "remote_code_executed": False,
    }
