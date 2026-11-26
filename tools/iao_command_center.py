#!/usr/bin/env python3
import argparse
import datetime
import json
import os
import pathlib
import subprocess
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
STATE_DIR = ROOT / ".state"
NET_DIR = STATE_DIR / "iao-node-network"
P2P_DIR = STATE_DIR / "p2p-rollout"
LOG_DIR = ROOT / "logs"

CHAT_FILE = P2P_DIR / "open-p2p-deepweb-channel.json"
PEERS_FILE = NET_DIR / "peers.json"
LOG_FILE = LOG_DIR / "iao-command-center.log"

IPNS_SELF_KEY = "k51qzi5uqu5dhl7m39omrirw7lyljr8os7rwfigwt0v154679zyffsy960hdiv"
IPNS_DISCOVERY_KEY = "iao-discovery"
IPNS_DISCOVERY_ID = "k51qzi5uqu5dleb64uwtflite3np3ua2db5b0arlmwdlzdvrs2wt3ns9owb5x7"
PUBSUB_TOPIC = "iao-open-p2p-deepweb-v1"
ONION_URL = "http://vkamya7kk2clsnrl4li5q2os6k4bpgpypweqzmvchgjziwyljnkls3ad.onion/fed/v1/identity"
LOCAL_IDENTITY_URL = "http://127.0.0.1:8080/fed/v1/identity"


def run_cmd(cmd, timeout=35, input_data=None):
    try:
        p = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except Exception as exc:
        return 1, "", str(exc)


def get_identity():
    node_id = "f7379bb44d1e36ff"
    ipfs_peer_id = "12D3KooWDcbkkgNqtdaLtCgP9Do33m3Zbbq1AHQwdPbvQYYUYbkA"
    try:
        with urllib.request.urlopen(LOCAL_IDENTITY_URL, timeout=5) as r:
            d = json.loads(r.read().decode("utf-8", errors="replace"))
            if isinstance(d, dict) and d.get("node_id"):
                node_id = d["node_id"]
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


def count_open_peers():
    if PEERS_FILE.exists():
        try:
            d = json.loads(PEERS_FILE.read_text(encoding="utf-8"))
            if isinstance(d, dict) and isinstance(d.get("peers"), list):
                return len(d["peers"])
        except Exception:
            pass
    rc, out, _ = run_cmd(["ipfs", "swarm", "peers"], timeout=15)
    if rc == 0 and out:
        return len([ln for ln in out.splitlines() if ln.strip()])
    return 0


def dispatch_to_p2p_and_deepweb(message_text, sender="COMMAND_CENTER"):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    P2P_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    node_id, ipfs_peer_id = get_identity()
    open_peers = count_open_peers()

    history = []
    if CHAT_FILE.exists():
        try:
            prev = json.loads(CHAT_FILE.read_text(encoding="utf-8"))
            if isinstance(prev, dict) and isinstance(prev.get("messages"), list):
                history = prev["messages"]
        except Exception:
            history = []

    entry = {
        "ts_utc": now_utc,
        "sender": sender,
        "node_id": node_id,
        "ipfs_peer_id": ipfs_peer_id,
        "deepweb_onion_identity": ONION_URL,
        "open_p2p_peers_count": open_peers,
        "iao_required_on_remote": False,
        "message": message_text,
    }
    history.append(entry)
    history = history[-200:]

    payload = {
        "schema": "IAO_OPEN_P2P_DEEPWEB_CHANNEL_V1",
        "updated_utc": now_utc,
        "command_origin": "termux_command_center",
        "execution_plane": "open_p2p_and_deepweb_onion",
        "iao_required_on_remote": False,
        "pubsub_topic": PUBSUB_TOPIC,
        "deepweb_onion_url": ONION_URL,
        "node_id": node_id,
        "ipfs_peer_id": ipfs_peer_id,
        "open_p2p_peers_count": open_peers,
        "messages": history,
    }
    CHAT_FILE.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    rc_add, cid, _ = run_cmd(["ipfs", "add", "-Q", str(CHAT_FILE)], timeout=15)
    cid = cid.strip() if rc_add == 0 else ""

    pubsub_ok = False
    pubsub_err = ""
    if cid:
        pubsub_msg = json.dumps({
            "type": "IAO_OPEN_P2P_DEEPWEB_MSG",
            "ts_utc": now_utc,
            "node_id": node_id,
            "cid": cid,
            "onion_url": ONION_URL,
            "message": message_text,
        }, ensure_ascii=False)
        rc_ps, _, err_ps = run_cmd(["ipfs", "pubsub", "pub", PUBSUB_TOPIC], timeout=15, input_data=pubsub_msg)
        pubsub_ok = (rc_ps == 0)
        pubsub_err = err_ps

    ipns_ok = False
    ipns_resolved = ""
    ipns_err = ""
    if cid:
        rc_pub, _, err_pub = run_cmd(
            ["ipfs", "name", "publish", "--allow-offline", f"--key={IPNS_DISCOVERY_KEY}", "-Q", cid],
            timeout=60,
        )
        ipns_ok = (rc_pub == 0)
        ipns_err = err_pub
        run_cmd(["ipfs", "name", "publish", "--allow-offline", "-Q", cid], timeout=45)
        rc_res, res_out, _ = run_cmd(["ipfs", "name", "resolve", "--nocache=true", IPNS_DISCOVERY_ID], timeout=25)
        if rc_res == 0 and res_out:
            ipns_resolved = res_out.strip()
        else:
            rc_res2, res_out2, _ = run_cmd(["ipfs", "name", "resolve", "--nocache=true", IPNS_SELF_KEY], timeout=25)
            if rc_res2 == 0 and res_out2:
                ipns_resolved = res_out2.strip()

    out_rec = {
        "ts_utc": now_utc,
        "cid": cid,
        "pubsub_topic": PUBSUB_TOPIC,
        "pubsub_published": pubsub_ok,
        "pubsub_error": "" if pubsub_ok else pubsub_err,
        "ipns_discovery_published": ipns_ok,
        "ipns_resolved": ipns_resolved,
        "ipns_error": "" if ipns_ok else ipns_err,
        "deepweb_onion_url": ONION_URL,
        "open_p2p_peers_count": open_peers,
        "message": message_text,
    }
    with LOG_FILE.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(out_rec, ensure_ascii=False) + "\n")
    return out_rec


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--say", type=str, default="")
    parser.add_argument("--status", action="store_true")
    args = parser.parse_args()

    if args.say:
        res = dispatch_to_p2p_and_deepweb(args.say.strip())
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return

    if args.status:
        if CHAT_FILE.exists():
            print(CHAT_FILE.read_text(encoding="utf-8"))
        else:
            print("{}")
        return

    res = dispatch_to_p2p_and_deepweb("IAO command center online over open P2P swarm and Deep Web (.onion).")
    print(json.dumps(res, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
