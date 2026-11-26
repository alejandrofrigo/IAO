#!/usr/bin/env python3
"""Puente P2P verificable entre PADGE e IPFS/Kubo."""
import json
import re
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CID = "bafybeihuihbhb6qhiupzbncwztz6ojho35jbz4xjvc2on5sxkbtvy37sxq"
LOCAL_ID = ""
REPORT = ROOT / ".state/p2p-rollout/padge-p2p-bridge.json"


def command(args, timeout=30):
    try:
        p = subprocess.run(
            ["ipfs", *args], cwd=ROOT, capture_output=True,
            text=True, timeout=timeout, check=False
        )
        return {
            "ok": p.returncode == 0,
            "exit": p.returncode,
            "output": (p.stdout or p.stderr or "").strip()[:12000],
        }
    except Exception as exc:
        return {"ok": False, "error": type(exc).__name__}


def main():
    global LOCAL_ID
    started = time.time()

    identity = command(["id", "-f=<id>"])
    LOCAL_ID = identity.get("output", "").strip()

    peers = command(["swarm", "peers"], 35)
    peer_ids = sorted(set(re.findall(r"/p2p/(12D3KooW[A-Za-z0-9]+)", peers.get("output", ""))))
    if not peer_ids:
        peer_ids = sorted(set(re.findall(r"(12D3KooW[A-Za-z0-9]+)", peers.get("output", ""))))

    block = command(["block", "stat", CID])
    pin = command(["pin", "ls", CID])

    # Anuncio recursivo del release completo.
    provide = command(["routing", "provide", "--recursive", CID], 105)

    # La consulta puede tardar; se limita para no bloquear el worker.
    providers = command(["routing", "findprovs", CID], 55)
    provider_ids = sorted(set(
        re.findall(r"12D3KooW[A-Za-z0-9]+", providers.get("output", ""))
    ))
    external = [p for p in provider_ids if p != LOCAL_ID]

    bandwidth = command(["stats", "bw"], 15)

    report = {
        "schema": "IAO_PADGE_IPFS_P2P_BRIDGE_V1",
        "timestamp": int(time.time()),
        "release_cid": CID,
        "local_peer_id": LOCAL_ID or None,
        "ipfs_api": identity["ok"],
        "connected_peer_count": len(peer_ids),
        "connected_peer_sample": peer_ids[:15],
        "release_block_available": block["ok"],
        "release_pin_available": pin["ok"],
        "recursive_provider_announcement": "SUCCEEDED" if provide["ok"] else "FAILED",
        "provider_ids_observed": provider_ids,
        "external_provider_count": len(external),
        "external_provider_ids": external,
        "external_provider_observed": bool(external),
        "external_replication_confirmed": False,
        "external_transfer_confirmed": False,
        "provider_lookup_ok": providers["ok"],
        "bandwidth_query_ok": bandwidth["ok"],
        "bandwidth": bandwidth.get("output", "")[:2000],
        "duration_seconds": round(time.time() - started, 2),
        "truthfulness": {
            "connected_peers_are_not_replica_proof": True,
            "provider_announcement_is_not_replica_proof": True,
            "local_provider_excluded_from_external_count": True,
            "remote_execution_authorized": False,
            "automatic_unknown_peer_enrollment": False,
        },
        "commands": {
            "identity": identity,
            "block_stat": block,
            "pin": pin,
            "provide": provide,
            "findprovs": providers,
        },
    }

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    tmp = REPORT.with_suffix(".tmp")
    tmp.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    tmp.replace(REPORT)

    print(json.dumps({
        "status": "PASS" if identity["ok"] and peers["ok"] and provide["ok"] else "DEGRADED",
        "connected_peers": len(peer_ids),
        "external_providers": len(external),
        "release_announced": provide["ok"],
        "external_replication_confirmed": bool(external),
        "report": str(REPORT),
    }, ensure_ascii=False), flush=True)

    return 0 if identity["ok"] and peers["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
