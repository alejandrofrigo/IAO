#!/usr/bin/env python3
import argparse
import datetime
import json
import os
import pathlib
import re
import subprocess
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
STATE_DIR = ROOT / ".state"
NET_DIR = STATE_DIR / "iao-node-network"
P2P_DIR = STATE_DIR / "p2p-rollout"
LOG_DIR = ROOT / "logs"

ASSIMILATED_FILE = P2P_DIR / "assimilated-open-p2p.json"
PEERS_FILE = NET_DIR / "peers.json"
LOG_FILE = LOG_DIR / "iao-open-p2p-assimilator.log"


def run_cmd(cmd, timeout=20):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except Exception as exc:
        return 1, "", str(exc)


def get_local_identity():
    node_id = "f7379bb44d1e36ff"
    ipfs_peer_id = "12D3KooWDcbkkgNqtdaLtCgP9Do33m3Zbbq1AHQwdPbvQYYUYbkA"
    try:
        with urllib.request.urlopen("http://127.0.0.1:8080/fed/v1/identity", timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            if isinstance(data, dict) and data.get("node_id"):
                node_id = data["node_id"]
    except Exception:
        pass
    rc, out, _ = run_cmd(["ipfs", "id"], timeout=12)
    if rc == 0 and out:
        try:
            pid = json.loads(out).get("ID")
            if pid:
                ipfs_peer_id = pid
        except Exception:
            pass
    return node_id, ipfs_peer_id


def parse_swarm_peers(now_utc):
    rc, out, _ = run_cmd(["ipfs", "swarm", "peers", "-v"], timeout=20)
    if rc != 0 or not out:
        rc, out, _ = run_cmd(["ipfs", "swarm", "peers"], timeout=15)

    active_map = {}
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.search(r"/p2p/([12D3KooW][A-Za-z0-9]+|Qm[1-9A-HJ-NP-Za-km-z]{44})", line)
        if not m:
            continue
        peer_id = m.group(1)
        parts = line.split()
        addr = parts[0]
        latency_ms = None
        if len(parts) > 1:
            tail = " ".join(parts[1:])
            m_ms = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*ms", tail)
            m_s = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*s\b", tail)
            if m_ms:
                latency_ms = float(m_ms.group(1))
            elif m_s:
                latency_ms = round(float(m_s.group(1)) * 1000.0, 2)

        transports = []
        if "/quic" in addr or "/quic-v1" in addr or "/webtransport" in addr:
            transports.append("udp-quic")
        if "/tcp/" in addr:
            transports.append("tcp")
        if "/ws" in addr or "/wss" in addr:
            transports.append("ws")
        if "/circuit" in addr or "/p2p-circuit" in addr:
            transports.append("circuit")
        if not transports:
            transports.append("libp2p")

        entry = active_map.setdefault(peer_id, {
            "peer_id": peer_id,
            "network": "open-p2p",
            "source": "ipfs-swarm",
            "role": "open_p2p_peer",
            "is_iao_node": False,
            "iao_required": False,
            "multiaddrs": [],
            "transports": [],
            "latency_ms": None,
            "first_assimilated_utc": now_utc,
            "last_seen_utc": now_utc,
            "assimilation_count": 0,
            "status": "CONNECTED",
        })
        if addr not in entry["multiaddrs"]:
            entry["multiaddrs"].append(addr)
        for tr in transports:
            if tr not in entry["transports"]:
                entry["transports"].append(tr)
        if latency_ms is not None and (entry["latency_ms"] is None or latency_ms < entry["latency_ms"]):
            entry["latency_ms"] = latency_ms

    return active_map


def assimilate_cycle(cycle_num):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    NET_DIR.mkdir(parents=True, exist_ok=True)
    P2P_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    node_id, ipfs_peer_id = get_local_identity()

    prev_store = {}
    if ASSIMILATED_FILE.exists():
        try:
            raw = json.loads(ASSIMILATED_FILE.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and isinstance(raw.get("peers"), dict):
                prev_store = raw["peers"]
        except Exception:
            prev_store = {}

    active_map = parse_swarm_peers(now_utc)
    newly_assimilated = 0

    for pid, cur in active_map.items():
        if pid not in prev_store:
            newly_assimilated += 1
            cur["assimilation_count"] = 1
            prev_store[pid] = cur
        else:
            old = prev_store[pid]
            old["last_seen_utc"] = now_utc
            old["status"] = "CONNECTED"
            old["is_iao_node"] = False
            old["iao_required"] = False
            old["assimilation_count"] = int(old.get("assimilation_count", 0)) + 1
            merged_addrs = list(old.get("multiaddrs", []))
            for a in cur["multiaddrs"]:
                if a not in merged_addrs:
                    merged_addrs.append(a)
            old["multiaddrs"] = merged_addrs
            merged_tr = list(old.get("transports", []))
            for t in cur["transports"]:
                if t not in merged_tr:
                    merged_tr.append(t)
            old["transports"] = merged_tr
            if cur["latency_ms"] is not None:
                if old.get("latency_ms") is None or cur["latency_ms"] < old["latency_ms"]:
                    old["latency_ms"] = cur["latency_ms"]

    for pid, old in prev_store.items():
        if pid not in active_map:
            old["status"] = "CACHED_OPEN_PEER"

    assimilated_list = sorted(
        prev_store.values(),
        key=lambda x: (0 if x.get("status") == "CONNECTED" else 1, -(x.get("assimilation_count", 0)))
    )

    store_payload = {
        "schema": "IAO_OPEN_P2P_NON_IAO_ASSIMILATION_V1",
        "updated_utc": now_utc,
        "cycle": cycle_num,
        "local_node_id": node_id,
        "local_ipfs_peer_id": ipfs_peer_id,
        "non_iao_only": True,
        "iao_required": False,
        "active_connected_count": len(active_map),
        "newly_assimilated_this_cycle": newly_assimilated,
        "total_assimilated_open_peers": len(prev_store),
        "peers": {item["peer_id"]: item for item in assimilated_list[:1000]},
    }
    ASSIMILATED_FILE.write_text(json.dumps(store_payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    active_peers_list = [prev_store[pid] for pid in active_map]
    peers_payload = {
        "version": 2,
        "node_id": node_id,
        "ipfs_peer_id": ipfs_peer_id,
        "topology": "open_p2p_non_iao_continuous",
        "requires_remote_iao": False,
        "updated_utc": now_utc,
        "active_peers_count": len(active_peers_list),
        "total_assimilated_count": len(prev_store),
        "peers": active_peers_list,
    }
    PEERS_FILE.write_text(json.dumps(peers_payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    event = {
        "ts": now_utc,
        "cycle": cycle_num,
        "mode": "AUTONOMOUS_OPEN_P2P_NON_IAO",
        "active_connected": len(active_map),
        "newly_assimilated": newly_assimilated,
        "total_assimilated": len(prev_store),
        "iao_required": False,
    }
    with LOG_FILE.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, ensure_ascii=False) + "\n")
    return event


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=int, default=int(os.environ.get("IAO_ASSIMILATE_INTERVAL", "60")))
    args = parser.parse_args()

    cycle = 0
    if args.once:
        ev = assimilate_cycle(1)
        print(json.dumps(ev, indent=2, ensure_ascii=False))
        return

    while True:
        cycle += 1
        try:
            assimilate_cycle(cycle)
        except Exception as exc:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            with LOG_FILE.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "cycle": cycle,
                    "error": str(exc),
                }, ensure_ascii=False) + "\n")
        time.sleep(max(15, args.interval))


if __name__ == "__main__":
    main()
