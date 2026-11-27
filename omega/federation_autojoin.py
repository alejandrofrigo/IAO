"""Controlled automatic enrollment of locally authorized federation peers."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


INTERVAL_SECONDS = 300
MAX_CONTRACT_BYTES = 65536
_LOCK = threading.Lock()
_THREAD: threading.Thread | None = None
_STOP_EVENT = threading.Event()


def _record(state_dir: Path, event: str, **details: object) -> None:
    from omega.operational_log import append_private_jsonl

    path = state_dir / "federation-autojoin.jsonl"
    entry = {
        "time": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **details,
    }
    with _LOCK:
        append_private_jsonl(path, entry)


def _origin(node: dict) -> str:
    """Accept only an HTTPS origin from the authorized node configuration."""
    candidates = ("origin", "base_url", "url", "endpoint")
    raw = next(
        (node.get(k) for k in candidates if isinstance(node.get(k), str)),
        None,
    )
    if not raw:
        raise ValueError("NODE_ORIGIN_MISSING")

    u = urlsplit(raw.strip())
    if (
        u.scheme != "https"
        or not u.hostname
        or u.username
        or u.password
        or (u.port is not None and u.port != 443)
        or u.query
        or u.fragment
    ):
        raise ValueError("NODE_ORIGIN_INVALID")

    return f"https://{u.netloc}"


def _get_contract(origin: str) -> dict:
    url = origin + "/fed/v1/contract"
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "IAO-Federation/1"},
        method="GET",
    )
    # Default TLS certificate and hostname verification remain enabled.
    with urllib.request.urlopen(req, timeout=12) as response:
        if response.status != 200:
            raise ValueError("CONTRACT_HTTP_STATUS")
        raw = response.read(MAX_CONTRACT_BYTES + 1)

    if len(raw) > MAX_CONTRACT_BYTES:
        raise ValueError("CONTRACT_TOO_LARGE")

    result = json.loads(raw.decode("utf-8"))
    if not isinstance(result, dict):
        raise ValueError("CONTRACT_NOT_OBJECT")
    return result


def _verified(node: dict, verify_node) -> tuple[bool, str]:
    result = verify_node(node)
    if not isinstance(result, dict):
        return False, "IDENTITY_RESULT_INVALID"

    status_values = {
        value for value in result.values()
        if isinstance(value, str)
    }
    if "IDENTITY_VERIFIED" not in status_values:
        return False, "IDENTITY_NOT_VERIFIED"

    actual_id = (
        result.get("actual_id")
        or result.get("actual_node_id")
        or result.get("peer_id")
    )
    expected_id = (
        node.get("node_id")
        or node.get("peer_id")
        or node.get("id")
    )
    if not isinstance(actual_id, str) or actual_id != expected_id:
        return False, "IDENTITY_ID_MISMATCH"

    return True, actual_id


def run_cycle(fed_node, state_dir: Path) -> dict:
    """Enroll authorized peers; never grant inbound capabilities automatically."""
    from tools.iao_federation_agent import load_nodes, verify_node

    cfg = load_nodes()
    if cfg.get("status") != "VALID":
        _record(state_dir, "AUTOJOIN_CONFIG_REJECTED",
                config_status=str(cfg.get("status")))
        return {"status": "CONFIG_REJECTED", "enrolled": 0}

    enrolled = 0
    skipped = 0
    failed = 0

    for node in cfg.get("nodes", []):
        try:
            if not isinstance(node, dict) or node.get("authorized") is not True:
                skipped += 1
                continue

            ok, identity = _verified(node, verify_node)
            if not ok:
                failed += 1
                _record(state_dir, "AUTOJOIN_IDENTITY_REJECTED",
                        reason=identity)
                continue

            origin = _origin(node)
            contract = _get_contract(origin)

            if contract.get("peer_id") != identity:
                raise ValueError("CONTRACT_IDENTITY_MISMATCH")

            # Endpoint is supplied locally; it is not trusted from the peer.
            contract["endpoint"] = origin + "/fed/v1/message"

            # Reuse the node's own strict contract validator.
            # This checks key/id binding, lease, rate and locally served capabilities.
            fed_node._validate_peer_contract(contract)

            existing = fed_node.peers.get(identity)
            if existing is not None:
                # Do not overwrite existing trust grants or silently rotate keys.
                existing_key = existing.get("pubkey")
                if existing_key != contract.get("pubkey"):
                    raise ValueError("ENROLLED_PEER_KEY_CHANGED")
                skipped += 1
                _record(state_dir, "AUTOJOIN_ALREADY_ENROLLED",
                        peer_id=identity)
                continue

            # No inbound permissions are granted by automatic enrollment.
            fed_node.enroll(contract, granted_capabilities=[])

            # Confirm persistence in the live node after enrollment.
            if identity not in fed_node.peers:
                raise RuntimeError("ENROLLMENT_NOT_PRESENT_IN_MEMORY")

            enrolled += 1
            _record(state_dir, "AUTOJOIN_ENROLLED",
                    peer_id=identity,
                    advertised_capabilities=contract["capabilities"],
                    granted_inbound_capabilities=[])

        except Exception as exc:
            failed += 1
            _record(
                state_dir,
                "AUTOJOIN_FAILED",
                peer_id=str(
                    node.get("node_id", node.get("peer_id", "unknown"))
                    if isinstance(node, dict) else "invalid"
                ),
                error_type=type(exc).__name__,
            )

    result = {
        "status": "CYCLE_COMPLETED",
        "enrolled": enrolled,
        "already_enrolled_or_skipped": skipped,
        "failed": failed,
    }
    _record(state_dir, "AUTOJOIN_CYCLE_COMPLETED", **result)
    return result


def start_federation_autojoin(fed_node, state_dir: Path) -> bool:
    """Start one stoppable background worker in the existing server process."""
    global _THREAD
    with _LOCK:
        if _THREAD is not None and _THREAD.is_alive():
            return True
        _STOP_EVENT.clear()

        def worker():
            _record(state_dir, "AUTOJOIN_WORKER_STARTED",
                    interval_seconds=INTERVAL_SECONDS)
            while not _STOP_EVENT.is_set():
                try:
                    result = run_cycle(fed_node, state_dir)
                    print("IAO_FEDERATION_AUTOJOIN " +
                          json.dumps(result, sort_keys=True), flush=True)
                except Exception as exc:
                    _record(state_dir, "AUTOJOIN_CYCLE_ERROR",
                            error_type=type(exc).__name__)
                    print("IAO_FEDERATION_AUTOJOIN_ERROR " +
                          type(exc).__name__, flush=True)
                if _STOP_EVENT.wait(INTERVAL_SECONDS):
                    break
            _record(state_dir, "AUTOJOIN_WORKER_STOPPED")

        _THREAD = threading.Thread(
            target=worker,
            name="iao-federation-autojoin",
            daemon=True,
        )
        _THREAD.start()
        return True


def stop_federation_autojoin(timeout: float = 5.0) -> bool:
    """Request worker shutdown and wait a bounded time for its thread."""
    global _THREAD
    _STOP_EVENT.set()
    thread = _THREAD
    if thread is None:
        return True
    if thread is threading.current_thread():
        return False
    thread.join(max(0.0, timeout))
    stopped = not thread.is_alive()
    if stopped:
        with _LOCK:
            if _THREAD is thread:
                _THREAD = None
    return stopped
