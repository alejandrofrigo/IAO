#!/usr/bin/env python3
"""Control P2P ejecutado dentro del proceso PADGE."""
import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / ".state/p2p-rollout/padge-direct-p2p.json"
BRIDGE = ROOT / "tools/iao_p2p_autonomy_bridge.py"
TORRENT = ROOT / ".state/p2p-rollout/bittorrent/iao-source-release.torrent"
MAGNET = ROOT / ".state/p2p-rollout/bittorrent/iao-source-release.magnet"
INTERVAL = 300
_lock = threading.Lock()
_started = False


def utc():
    return datetime.now(timezone.utc).isoformat()


def run(args, timeout=25):
    try:
        p = subprocess.run(
            args, cwd=str(ROOT), capture_output=True, text=True,
            timeout=timeout, check=False
        )
        return {
            "exit_code": p.returncode,
            "output": (p.stdout or "").strip()[-5000:],
            "error": (p.stderr or "").strip()[-2000:],
        }
    except Exception as exc:
        return {"exit_code": None, "error": str(exc)[:1000]}


def process_matches(fragment):
    found = []
    proc = Path("/proc")
    try:
        for entry in proc.iterdir():
            if not entry.name.isdigit():
                continue
            try:
                cmd = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode(
                    errors="replace"
                )
                if fragment in cmd:
                    found.append(int(entry.name))
            except (OSError, ValueError):
                pass
    except OSError:
        pass
    return sorted(set(found))


def cycle():
    result = {
        "timestamp": utc(),
        "controller": "PADGE_PROCESS",
        "ipfs_libp2p": {},
        "bittorrent": {},
        "tor": {},
        "safety": {
            "remote_execution": False,
            "unknown_peer_auto_enrollment": False,
            "external_replica_claimed": False,
        },
    }

    # IPFS/libp2p: conectividad, peers y anuncio del release.
    ipfs_bin = __import__("shutil").which("ipfs")
    if ipfs_bin:
        ident = run([ipfs_bin, "id", "-f=<id>"], 15)
        peers = run([ipfs_bin, "swarm", "peers"], 30)
        peer_lines = [
            x for x in peers.get("output", "").splitlines() if x.strip()
        ]
        result["ipfs_libp2p"] = {
            "identity_check": ident,
            "peer_check": peers,
            "connected_peer_count": len(peer_lines)
                if peers.get("exit_code") == 0 else None,
            "bridge": None,
        }

        if BRIDGE.exists():
            result["ipfs_libp2p"]["bridge"] = run(
                [sys.executable, str(BRIDGE), "--once"], 190
            )
    else:
        result["ipfs_libp2p"] = {"status": "IPFS_BINARY_NOT_FOUND"}

    # BitTorrent: comprobar el proceso y los artefactos del seeder.
    aria_pids = process_matches("aria2c")
    result["bittorrent"] = {
        "aria2_process_pids": aria_pids,
        "torrent_file_present": TORRENT.is_file(),
        "magnet_file_present": MAGNET.is_file(),
        "external_peer_or_transfer_confirmed": False,
    }

    # Tor: distinguir binario instalado de daemon activo.
    result["tor"] = {
        "binary": __import__("shutil").which("tor"),
        "daemon_pids": process_matches("tor") if __import__("shutil").which("tor") else [],
        "network_connection_confirmed": False,
    }

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    tmp = REPORT.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    os.replace(tmp, REPORT)
    print(
        "[PADGE-P2P] peers={} aria2={} tor_daemons={} report={}".format(
            result["ipfs_libp2p"].get("connected_peer_count"),
            len(aria_pids),
            len(result["tor"]["daemon_pids"]),
            REPORT,
        ),
        flush=True,
    )


def loop():
    while True:
        try:
            cycle()
        except Exception as exc:
            print("[PADGE-P2P] cycle error: " + repr(exc), flush=True)
        time.sleep(INTERVAL)


def start():
    global _started
    with _lock:
        if _started:
            return
        _started = True
    thread = threading.Thread(
        target=loop, name="PADGE-P2P-CONTROLLER", daemon=True
    )
    thread.start()
    print("[PADGE-P2P] controlador iniciado dentro del proceso PADGE", flush=True)


if __name__ == "__main__":
    start()
    cycle()
