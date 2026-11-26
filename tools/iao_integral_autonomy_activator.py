#!/usr/bin/env python3
import argparse
import datetime
import json
import os
import pathlib
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
STATE_DIR = ROOT / ".state"
NET_DIR = STATE_DIR / "iao-node-network"
P2P_DIR = STATE_DIR / "p2p-rollout"
LOG_DIR = ROOT / "logs"

REPORT_FILE = P2P_DIR / "integral-activation-status.json"
LOG_FILE = LOG_DIR / "iao-integral-activation.log"
AUTHORIZED_HOSTS_FILE = NET_DIR / "authorized-remote-iao-hosts.json"

SOCKS_PROXY = "127.0.0.1:9050"
ONION_IDENTITY_URL = "http://vkamya7kk2clsnrl4li5q2os6k4bpgpypweqzmvchgjziwyljnkls3ad.onion/fed/v1/identity"
IPNS_DISCOVERY_KEY = "iao-discovery"
HTTP_PORTS = [8080, 8000, 8001, 9000]

LOCAL_PROCESSES = [
    {
        "name": "control_plane_local",
        "match": "tools/iao_control_plane_local.py",
        "cmd": ["python", "tools/iao_control_plane_local.py"],
        "log": LOG_DIR / "iao-control-plane-local.log",
    },
    {
        "name": "five_motor_supervisor",
        "match": "tools/iao_five_motor_supervisor.py",
        "cmd": ["python", "tools/iao_five_motor_supervisor.py"],
        "log": LOG_DIR / "iao-five-motor-supervisor.log",
    },
    {
        "name": "autonomy_daemon",
        "match": "tools/iao_autonomy_daemon.py",
        "cmd": ["python", "tools/iao_autonomy_daemon.py"],
        "log": LOG_DIR / "iao-autonomy-daemon.log",
    },
    {
        "name": "padge_loop_entry",
        "match": "tools/iao_padge_loop_entry.py",
        "cmd": ["python", "tools/iao_padge_loop_entry.py"],
        "log": LOG_DIR / "iao-padge-loop-entry.log",
    },
    {
        "name": "internet_guardian",
        "match": "tools/iao_internet_guardian.py",
        "cmd": ["python", "tools/iao_internet_guardian.py"],
        "log": LOG_DIR / "iao-internet-guardian.log",
    },
    {
        "name": "node_network_engine",
        "match": "tools/iao_node_network_engine.py",
        "cmd": ["python", "tools/iao_node_network_engine.py", "serve"],
        "log": LOG_DIR / "iao-node-network-engine.log",
    },
    {
        "name": "federation_worker",
        "match": "tools/iao_federation_worker.py",
        "cmd": ["python", "tools/iao_federation_worker.py"],
        "log": LOG_DIR / "iao-federation-worker.log",
    },
    {
        "name": "deepweb_p2p_orchestrator",
        "match": "tools/iao_deepweb_p2p_orchestrator.py",
        "cmd": ["python", "tools/iao_deepweb_p2p_orchestrator.py", "--interval", "120"],
        "log": LOG_DIR / "iao-deepweb-p2p-orchestrator-daemon.log",
    },
    {
        "name": "deepweb_open_scanner",
        "match": "tools/iao_deepweb_open_scanner.py",
        "cmd": ["python", "tools/iao_deepweb_open_scanner.py", "--interval", "120"],
        "log": LOG_DIR / "iao-deepweb-open-scanner-daemon.log",
    },
    {
        "name": "tor_stream_heartbeat",
        "match": "tools/iao_tor_stream_heartbeat.py",
        "cmd": ["python", "tools/iao_tor_stream_heartbeat.py", "--interval", "90"],
        "log": LOG_DIR / "iao-tor-stream-heartbeat-daemon.log",
    },
]

EXTERNAL_PROCESSES = [
    {
        "name": "tor_daemon",
        "match": "(^|/)tor(\s|$)",
        "cmd": ["tor"],
        "log": LOG_DIR / "iao-tor-daemon.log",
    },
    {
        "name": "ipfs_kubo_daemon",
        "match": "ipfs daemon",
        "cmd": ["ipfs", "daemon", "--enable-pubsub-experiment"],
        "log": LOG_DIR / "iao-ipfs-daemon.log",
    },
    {
        "name": "external_cycle",
        "match": "tools/iao_external_cycle.py",
        "cmd": ["python", "tools/iao_external_cycle.py"],
        "log": LOG_DIR / "iao-external-cycle-daemon.log",
    },
    {
        "name": "open_p2p_assimilator",
        "match": "tools/iao_open_p2p_assimilator.py",
        "cmd": ["python", "tools/iao_open_p2p_assimilator.py"],
        "log": LOG_DIR / "iao-open-p2p-assimilator-daemon.log",
    },
    {
        "name": "federation_autonomous",
        "match": "tools/iao_federation_autonomous.py",
        "cmd": ["python", "tools/iao_federation_autonomous.py"],
        "log": LOG_DIR / "iao-federation-autonomous-daemon.log",
    },
    {
        "name": "public_node_launcher",
        "match": "tools/iao_public_node_launcher.py",
        "cmd": ["python", "tools/iao_public_node_launcher.py"],
        "log": LOG_DIR / "iao-public-node-launcher-daemon.log",
    },
]


def run_cmd(cmd, timeout=20):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except Exception as exc:
        return 1, "", str(exc)


def matching_pids(match_str):
    rc, out, _ = run_cmd(["pgrep", "-f", match_str], timeout=5)
    if rc != 0 or not out.strip():
        return []
    my_pid = os.getpid()
    parent_pid = os.getppid()
    pids = []
    for tok in out.splitlines():
        tok = tok.strip()
        if tok.isdigit():
            val = int(tok)
            if val not in (my_pid, parent_pid):
                pids.append(val)
    return pids


def binary_or_script_exists(cmd_list):
    first = cmd_list[0]
    candidate = ROOT / first
    if candidate.exists():
        return True, str(candidate)
    rc, out, _ = run_cmd(["command", "-v", first] if first != "python" else ["which", "python3"], timeout=4)
    if first == "python":
        rc2, out2, _ = run_cmd(["which", "python"], timeout=4)
        if rc2 == 0 and out2:
            return True, out2
        if rc == 0 and out:
            return True, out
        return False, "python_not_found"
    if rc == 0 and out:
        return True, out
    return False, f"executable_not_found:{first}"


def ensure_process(entry):
    pids = matching_pids(entry["match"])
    if pids:
        return {
            "name": entry["name"],
            "status": "ALREADY_ACTIVE",
            "pids": pids,
            "started_now": False,
            "detail": "running",
        }

    cmd = list(entry["cmd"])
    if cmd[0] == "python":
        rc_py, py_bin, _ = run_cmd(["sh", "-c", "command -v python || command -v python3"], timeout=4)
        if rc_py == 0 and py_bin:
            cmd[0] = py_bin

    script_rel = cmd[1] if len(cmd) > 1 and cmd[1].endswith(".py") else None
    if script_rel and not (ROOT / script_rel).exists():
        return {
            "name": entry["name"],
            "status": "SCRIPT_NOT_FOUND",
            "pids": [],
            "started_now": False,
            "detail": f"missing_file:{script_rel}",
        }

    if not script_rel:
        rc_bin, bin_path, _ = run_cmd(["sh", "-c", f"command -v {cmd[0]}"], timeout=4)
        if rc_bin != 0 or not bin_path:
            return {
                "name": entry["name"],
                "status": "EXECUTABLE_NOT_FOUND",
                "pids": [],
                "started_now": False,
                "detail": f"missing_binary:{cmd[0]}",
            }

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_fh = entry["log"].open("a", encoding="utf-8")
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(ROOT),
            stdout=log_fh,
            stderr=log_fh,
            start_new_session=True,
        )
    except Exception as exc:
        log_fh.close()
        return {
            "name": entry["name"],
            "status": "START_ERROR",
            "pids": [],
            "started_now": False,
            "detail": str(exc),
        }

    time.sleep(1.5)
    pids_after = matching_pids(entry["match"])
    poll_rc = proc.poll()
    active = bool(pids_after) or (poll_rc is None)
    return {
        "name": entry["name"],
        "status": "ACTIVATED_NOW" if active else f"EXITED_RC_{poll_rc}",
        "pids": pids_after if pids_after else ([proc.pid] if poll_rc is None else []),
        "started_now": active,
        "detail": f"log={entry['log'].name}",
    }


def check_http_ports():
    ports_report = {}
    for port in HTTP_PORTS:
        rc_live, out_live, err_live = run_cmd(
            ["curl", "-sS", "--max-time", "3", f"http://127.0.0.1:{port}/health/live"], timeout=6
        )
        rc_ready, out_ready, err_ready = run_cmd(
            ["curl", "-sS", "--max-time", "3", f"http://127.0.0.1:{port}/health/ready"], timeout=6
        )
        live_ok = rc_live == 0 and bool(out_live)
        ready_status = "unreachable"
        if rc_ready == 0 and out_ready:
            try:
                ready_status = json.loads(out_ready).get("status", "raw_200")
            except Exception:
                ready_status = "raw_200"
        ports_report[str(port)] = {
            "reachable": live_ok or (rc_ready == 0),
            "live_ok": live_ok,
            "ready_status": ready_status,
            "error": "" if (live_ok or rc_ready == 0) else (err_live or err_ready or f"rc_{rc_live}"),
        }
    return ports_report


def check_local_state():
    omega_db = STATE_DIR / "omega.db"
    knowledge_db = STATE_DIR / "iao-knowledge.db"
    return {
        "http_ports": check_http_ports(),
        "files_present": {
            "omega_db": omega_db.exists(),
            "omega_db_bytes": omega_db.stat().st_size if omega_db.exists() else 0,
            "knowledge_db": knowledge_db.exists(),
            "knowledge_db_bytes": knowledge_db.stat().st_size if knowledge_db.exists() else 0,
            "autonomy_log": (STATE_DIR / "autonomy.log").exists(),
            "autonomy_audit_v2": (STATE_DIR / "autonomy-audit-v2.jsonl").exists(),
            "padge_events": (STATE_DIR / "padge" / "events.jsonl").exists(),
            "padge_backup": any((STATE_DIR / "backups").glob("padge-fix-*/padge.py.bak")),
        },
    }


def check_external_state():
    rc_ipfs_id, out_ipfs_id, err_ipfs_id = run_cmd(["ipfs", "id", "-f", "<id>"], timeout=8)
    rc_peers, out_peers, err_peers = run_cmd(["ipfs", "swarm", "peers"], timeout=10)
    peers = [line.strip() for line in out_peers.splitlines() if line.strip()] if rc_peers == 0 else []

    rc_ipns, out_ipns, err_ipns = run_cmd(
        ["ipfs", "name", "resolve", "--nocache", f"/ipns/{IPNS_DISCOVERY_KEY}"], timeout=25
    )

    t0 = time.monotonic()
    rc_tor, out_tor, err_tor = run_cmd(
        ["curl", "-sS", "-m", "18", "--socks5-hostname", SOCKS_PROXY, ONION_IDENTITY_URL],
        timeout=24,
    )
    tor_ms = int((time.monotonic() - t0) * 1000)
    tor_ok = rc_tor == 0 and bool(out_tor)

    authorized_hosts = []
    if AUTHORIZED_HOSTS_FILE.exists():
        try:
            raw = json.loads(AUTHORIZED_HOSTS_FILE.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and isinstance(raw.get("hosts"), list):
                for h in raw["hosts"]:
                    if isinstance(h, dict) and h.get("enabled"):
                        authorized_hosts.append(h.get("name") or h.get("ssh_target") or "unnamed")
        except Exception:
            pass

    return {
        "ipfs": {
            "daemon_reachable": rc_ipfs_id == 0 and bool(out_ipfs_id),
            "peer_id": out_ipfs_id if rc_ipfs_id == 0 else "",
            "error": "" if rc_ipfs_id == 0 else (err_ipfs_id or f"rc_{rc_ipfs_id}"),
            "swarm_reachable": rc_peers == 0,
            "connected_peers": len(peers),
            "swarm_error": "" if rc_peers == 0 else (err_peers or f"rc_{rc_peers}"),
            "ipns_discovery_resolved": rc_ipns == 0 and bool(out_ipns),
            "ipns_discovery_target": out_ipns if rc_ipns == 0 else "",
            "ipns_discovery_error": "" if rc_ipns == 0 else (err_ipns or f"rc_{rc_ipns}"),
        },
        "tor": {
            "socks5_proxy": SOCKS_PROXY,
            "onion_url": ONION_IDENTITY_URL,
            "onion_reachable": tor_ok,
            "latency_ms": tor_ms,
            "http_sample_bytes": len(out_tor) if tor_ok else 0,
            "error": "" if tor_ok else (err_tor or f"rc_{rc_tor}"),
        },
        "authorized_remote_hosts_enabled": authorized_hosts,
    }


def integral_cycle(cycle_num):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    NET_DIR.mkdir(parents=True, exist_ok=True)
    P2P_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    local_state = check_local_state()
    local_procs = [ensure_process(proc) for proc in LOCAL_PROCESSES]
    external_procs = [ensure_process(proc) for proc in EXTERNAL_PROCESSES]
    external_state = check_external_state()

    local_active_count = sum(1 for item in local_procs if item["started_now"])
    external_active_count = sum(1 for item in external_procs if item["started_now"])

    summary = {
        "schema": "IAO_INTEGRAL_100PCT_REAL_ACTIVATION_V4",
        "updated_utc": now_utc,
        "cycle": cycle_num,
        "local": {
            **local_state,
            "processes": local_procs,
            "active_or_activated_processes": local_active_count,
            "total_checked_processes": len(local_procs),
        },
        "external": {
            "processes": external_procs,
            "active_or_activated_processes": external_active_count,
            "total_checked_processes": len(external_procs),
            **external_state,
        },
        "ipfs_report_publication": {
            "published": False,
            "cid": "",
            "error": "",
        },
    }

    REPORT_FILE.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    rc_add, cid, err_add = run_cmd(["ipfs", "add", "-Q", str(REPORT_FILE)], timeout=12)
    if rc_add == 0 and cid.strip():
        summary["ipfs_report_publication"] = {
            "published": True,
            "cid": cid.strip(),
            "error": "",
        }
        REPORT_FILE.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    else:
        summary["ipfs_report_publication"] = {
            "published": False,
            "cid": "",
            "error": err_add or f"rc_{rc_add}",
        }

    with LOG_FILE.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(summary, ensure_ascii=False) + "\n")
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=int, default=int(os.environ.get("IAO_INTEGRAL_INTERVAL", "180")))
    args = parser.parse_args()

    if args.once:
        print(json.dumps(integral_cycle(1), indent=2, ensure_ascii=False))
        return

    cycle = 0
    while True:
        cycle += 1
        try:
            integral_cycle(cycle)
        except Exception as exc:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            with LOG_FILE.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "ts_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "cycle": cycle,
                    "error": str(exc),
                }, ensure_ascii=False) + "\n")
        time.sleep(max(30, args.interval))


if __name__ == "__main__":
    main()
