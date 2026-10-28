#!/usr/bin/env python3
"""IAO safe autonomy cycle: local health, compile, federation evidence."""
import argparse, hashlib, json, os, socket, subprocess, sys, time, urllib.request
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".state"
REPORTS = STATE / "iao-reports"
def now():
    return datetime.now(timezone.utc).isoformat()
def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
def port_open(host="127.0.0.1", port=8080):
    s = socket.socket()
    s.settimeout(1)
    try: return s.connect_ex((host, port)) == 0
    finally: s.close()
def http_check():
    try:
        req = urllib.request.Request("http://127.0.0.1:8080/", headers={"User-Agent":"IAO-Autonomy/1"})
        with urllib.request.urlopen(req, timeout=3) as r:
            return {"status":"PASS" if 200 <= r.status < 500 else "FAIL",
                    "http_status":r.status, "bytes_read":len(r.read(1024))}
    except Exception as e:
        return {"status":"FAIL", "error":type(e).__name__}
def run_cycle():
    STATE.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    r = {"system":"IAO", "utc":now(), "actions":[], "checks":{},
         "secrets_printed":False, "external_network_requests":0}
    p = subprocess.run([sys.executable, "-m", "compileall", "-q", "omega", "tools"],
                       cwd=ROOT, capture_output=True, text=True, timeout=45)
    r["checks"]["compileall"] = {"status":"PASS" if p.returncode == 0 else "FAIL",
                                  "returncode":p.returncode}
    r["checks"]["local_http_before"] = http_check()
    # Recover only when the port is free. Never kill an unknown process.
    if r["checks"]["local_http_before"]["status"] != "PASS" and not port_open():
        supervisor = ROOT / "omega" / "supervisor.py"
        if supervisor.is_file():
            log = STATE / "iao-autonomy-supervisor.log"
            try:
                with log.open("ab") as fh:
                    proc = subprocess.Popen([sys.executable, "-m", "omega.supervisor"],
                        cwd=ROOT, stdin=subprocess.DEVNULL, stdout=fh,
                        stderr=subprocess.STDOUT, start_new_session=True,
                        close_fds=True)
                r["actions"].append({"action":"start_supervisor",
                                     "result":"START_REQUESTED","pid":proc.pid})
                time.sleep(2)
            except Exception as e:
                r["actions"].append({"action":"start_supervisor",
                                     "result":"FAILED","error":type(e).__name__})
        else:
            r["actions"].append({"action":"start_supervisor","result":"BLOCKED",
                                 "reason":"omega/supervisor.py missing"})
    elif r["checks"]["local_http_before"]["status"] != "PASS":
        r["actions"].append({"action":"service_recovery","result":"NOT_ATTEMPTED",
                             "reason":"port occupied; refusing to terminate unknown process"})
    r["checks"]["local_http_after"] = http_check()
    contract = ROOT / "tools" / "iao_federation_contract.py"
    if contract.is_file():
        try:
            cp = subprocess.run([sys.executable, str(contract)], cwd=ROOT,
                                capture_output=True, text=True, timeout=30)
            # Preserve only concise status; contract writes its own full report.
            r["checks"]["federation_contract"] = {
                "status":"PASS" if cp.returncode == 0 else "BLOCKED_OR_FAILED",
                "exit_code":cp.returncode,
                "report_exists":(STATE / "iao-federation-contract.json").is_file()
            }
        except Exception as e:
            r["checks"]["federation_contract"] = {"status":"ERROR","error":type(e).__name__}
    else:
        r["checks"]["federation_contract"] = {"status":"NOT_INSTALLED"}
    nodes_file = STATE / "iao-external-nodes.json"
    try:
        data = json.loads(nodes_file.read_text(encoding="utf-8")) if nodes_file.exists() else {}
        nodes = data.get("nodes", []) if isinstance(data, dict) else []
        r["checks"]["external_nodes"] = {
            "config_exists":nodes_file.exists(),
            "json_valid":True,
            "configured_count":len(nodes) if isinstance(nodes,list) else None,
            "authorized_count":sum(1 for n in nodes if isinstance(n,dict) and n.get("authorized") is True)
                if isinstance(nodes,list) else None,
            "exchange_verified":False
        }
    except Exception:
        r["checks"]["external_nodes"] = {"config_exists":True,"json_valid":False,
                                         "exchange_verified":False}
    r["status"] = ("HEALTHY_LOCAL" if r["checks"]["compileall"]["status"] == "PASS"
                   and r["checks"]["local_http_after"]["status"] == "PASS"
                   else "DEGRADED")
    name = datetime.now(timezone.utc).strftime("cycle-%Y%m%dT%H%M%S-%fZ.json")
    out = REPORTS / name
    out.write_text(json.dumps(r, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    latest = STATE / "iao-autonomy-latest.json"
    tmp = latest.with_suffix(".tmp")
    tmp.write_text(json.dumps(r, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, latest)
    print(json.dumps(r, indent=2, ensure_ascii=False))
    print("CYCLE_REPORT=" + str(out))
    print("CYCLE_REPORT_SHA256=" + sha(out))
    print("LATEST_REPORT=" + str(latest))
    print("LATEST_REPORT_SHA256=" + sha(latest))
    return r

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--loop", action="store_true", help="repeat every 60 seconds")
    ap.add_argument("--interval", type=int, default=60)
    args = ap.parse_args()
    while True:
        run_cycle()
        if not args.loop: break
        time.sleep(max(30, args.interval))
if __name__ == "__main__":
    main()
