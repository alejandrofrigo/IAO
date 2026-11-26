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

IPNS_SELF_KEY = "k51qzi5uqu5dhl7m39omrirw7lyljr8os7rwfigwt0v154679zyffsy960hdiv"
IPNS_DISCOVERY_KEY = "iao-discovery"
ONION_IDENTITY_URL = "http://vkamya7kk2clsnrl4li5q2os6k4bpgpypweqzmvchgjziwyljnkls3ad.onion/fed/v1/identity"
LOCAL_IDENTITY_URL = "http://127.0.0.1:8080/fed/v1/identity"
SOCKS_PROXY = "127.0.0.1:9050"


def run_cmd(cmd, timeout=25):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except Exception as exc:
        return 1, "", str(exc)


def fetch_json(url, socks_host_port=None, timeout=20):
    t0 = time.monotonic()
    if socks_host_port:
        cmd = ["curl", "-sS", "-m", str(timeout), "--socks5-hostname", socks_host_port, url]
        rc, out, err = run_cmd(cmd, timeout=timeout + 5)
        ms = int((time.monotonic() - t0) * 1000)
        if rc != 0 or not out:
            return False, ms, None, err or f"curl_rc_{rc}"
        try:
            return True, ms, json.loads(out), ""
        except Exception as exc:
            return False, ms, None, f"json_err:{exc}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            raw = r.read().decode("utf-8", errors="replace")
        ms = int((time.monotonic() - t0) * 1000)
        return True, ms, json.loads(raw), ""
    except Exception as exc:
        ms = int((time.monotonic() - t0) * 1000)
        return False, ms, None, str(exc)


def sync_open_p2p_peers(node_id, ipfs_peer_id, now_utc):
    NET_DIR.mkdir(parents=True, exist_ok=True)
    P2P_DIR.mkdir(parents=True, exist_ok=True)

    rc, out, _ = run_cmd(["ipfs", "swarm", "peers", "-v"], timeout=20)
    if rc != 0 or not out:
        rc, out, _ = run_cmd(["ipfs", "swarm", "peers"], timeout=15)

    peers_map = {}
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.search(r"/p2p/([12D3KooW][A-Za-z0-9]+|Qm[1-9A-HJ-NP-Za-km-z]{44})", line)
        if not m:
            continue
        pid = m.group(1)
        parts = line.split()
        addr = parts[0]
        lat = None
        if len(parts) > 1:
            tail = " ".join(parts[1:])
            m_ms = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*ms", tail)
            m_s = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*s\b", tail)
            if m_ms:
                lat = float(m_ms.group(1))
            elif m_s:
                lat = round(float(m_s.group(1)) * 1000.0, 2)
        entry = peers_map.setdefault(pid, {
            "peer_id": pid,
            "network": "ipfs-public-p2p",
            "role": "open_p2p_peer",
            "iao_required": False,
            "multiaddrs": [],
            "latency_ms": None,
            "last_seen_utc": now_utc,
        })
        if addr not in entry["multiaddrs"]:
            entry["multiaddrs"].append(addr)
        if lat is not None and (entry["latency_ms"] is None or lat < entry["latency_ms"]):
            entry["latency_ms"] = lat

    peers_list = list(peers_map.values())
    peers_doc = {
        "version": 2,
        "node_id": node_id,
        "ipfs_peer_id": ipfs_peer_id,
        "topology": "open_p2p_network",
        "requires_remote_iao": False,
        "updated_utc": now_utc,
        "peers": peers_list,
    }
    (NET_DIR / "peers.json").write_text(json.dumps(peers_doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    p2p_doc = {
        "schema": "IAO_OPEN_P2P_PEERS_V1",
        "updated_utc": now_utc,
        "open_p2p_peers_count": len(peers_list),
        "peers": peers_list[:100],
    }
    (P2P_DIR / "open-p2p-peers.json").write_text(json.dumps(p2p_doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return len(peers_list)


def run_cycle():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

    local_ok, _, local_ident, _ = fetch_json(LOCAL_IDENTITY_URL, timeout=5)
    onion_ok, onion_ms, onion_ident, onion_err = fetch_json(ONION_IDENTITY_URL, socks_host_port=SOCKS_PROXY, timeout=25)

    ident = onion_ident if (onion_ok and isinstance(onion_ident, dict)) else (local_ident if isinstance(local_ident, dict) else {})
    node_id = ident.get("node_id") or "f7379bb44d1e36ff"
    public_key = ident.get("public_key") or ""

    rc_id, id_out, _ = run_cmd(["ipfs", "id"], timeout=15)
    ipfs_peer_id = "12D3KooWDcbkkgNqtdaLtCgP9Do33m3Zbbq1AHQwdPbvQYYUYbkA"
    if rc_id == 0 and id_out:
        try:
            ipfs_peer_id = json.loads(id_out).get("ID", ipfs_peer_id)
        except Exception:
            pass

    open_p2p_count = sync_open_p2p_peers(node_id, ipfs_peer_id, now_utc)

    manifest = {
        "status": "ACTIVE_OPEN_P2P_CYCLE",
        "timestamp_utc": now_utc,
        "node_id": node_id,
        "public_key": public_key,
        "ipfs_peer_id": ipfs_peer_id,
        "topology": "open_p2p_network",
        "requires_remote_iao": False,
        "local_identity_ok": local_ok,
        "onion_identity_url": ONION_IDENTITY_URL,
        "onion_verified_this_run": onion_ok,
        "onion_latency_ms": onion_ms,
        "onion_error": onion_err,
        "open_p2p_peers_count": open_p2p_count,
    }
    manifest_path = STATE_DIR / "iao-external-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    rc_add, cid, err_add = run_cmd(["ipfs", "add", "-Q", str(manifest_path)], timeout=15)
    cid = cid.strip() if rc_add == 0 else ""

    ipns_published = False
    ipns_err = ""
    ipns_resolved = ""
    if cid:
        rc_pub, _, err_pub = run_cmd(["ipfs", "name", "publish", "--allow-offline", "-Q", cid], timeout=35)
        if rc_pub != 0:
            rc_pub, _, err_pub = run_cmd(["ipfs", "name", "publish", "--allow-offline", "-Q", cid], timeout=35)
        ipns_published = (rc_pub == 0)
        ipns_err = err_pub
        run_cmd(["ipfs", "name", "publish", "--allow-offline", f"--key={IPNS_DISCOVERY_KEY}", "-Q", cid], timeout=35)
        rc_res, res_out, _ = run_cmd(["ipfs", "name", "resolve", "--nocache=true", IPNS_SELF_KEY], timeout=20)
        if rc_res == 0 and res_out:
            ipns_resolved = res_out.strip()

    record = {
        "ts": now_utc,
        "onion_ok": onion_ok,
        "onion_ms": onion_ms,
        "swarm_peers": open_p2p_count,
        "open_p2p_peers": open_p2p_count,
        "fed_peers": open_p2p_count,
        "cid": cid,
        "ipns_published": ipns_published,
        "ipns_resolved": ipns_resolved,
        "ipns_error": ipns_err if not ipns_published else "",
    }
    log_file = LOG_DIR / "iao-external-cycle.log"
    with log_file.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(json.dumps(record, indent=2, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=int, default=int(os.environ.get("IAO_EXTERNAL_INTERVAL", "300")))
    args = parser.parse_args()
    if args.once:
        run_cycle()
        return
    while True:
        run_cycle()
        time.sleep(max(30, args.interval))


if __name__ == "__main__":
    main()
