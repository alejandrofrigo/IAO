#!/usr/bin/env python3
"""IAO single-command startup, local health check and evidence report."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib, json, os, socket, subprocess, sys, time, urllib.request

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".state"
def utc():
    return datetime.now(timezone.utc).isoformat()
def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
def port_open():
    s = socket.socket()
    s.settimeout(1)
    try: return s.connect_ex(("127.0.0.1", 8080)) == 0
    finally: s.close()
def http():
    try:
        req = urllib.request.Request(
            "http://127.0.0.1:8080/",
            headers={"User-Agent":"IAO-Boot/1.0"})
        with urllib.request.urlopen(req, timeout=4) as r:
            r.read(2048)
            return {"status":"PASS" if 200 <= r.status < 400 else "FAIL",
                    "http_status":r.status}
    except Exception as e:
        return {"status":"FAIL","error":type(e).__name__}
def main():
    STATE.mkdir(parents=True, exist_ok=True)
    r = {"system":"IAO","patch":"IAO-020","utc":utc(),
         "secrets_printed":False,"external_network_requests":0,
         "actions":[],"checks":{}}
    cp = subprocess.run([sys.executable,"-m","compileall","-q","omega","tools"],
                        cwd=ROOT,capture_output=True,text=True,timeout=60)
    r["checks"]["compileall"] = "PASS" if cp.returncode == 0 else "FAIL"
    if cp.returncode:
        r["status"] = "BLOCKED_COMPILE_FAILURE"
        r["compile_error"] = (cp.stderr or cp.stdout)[-1200:]
    else:
        r["checks"]["http_before"] = http()
        if r["checks"]["http_before"]["status"] != "PASS":
            if port_open():
                r["actions"].append({
                    "action":"start_supervisor",
                    "status":"SKIPPED",
                    "reason":"Port 8080 is occupied but HTTP health check failed; refusing to kill unknown process"})
            else:
                supervisor = ROOT / "omega" / "supervisor.py"
                if supervisor.is_file():
                    log_path = STATE / "iao-boot-supervisor.log"
                    try:
                        log = log_path.open("ab")
                        proc = subprocess.Popen(
                            [sys.executable,"-m","omega.supervisor"],
                            cwd=ROOT,stdin=subprocess.DEVNULL,
                            stdout=log,stderr=subprocess.STDOUT,
                            start_new_session=True,close_fds=True)
                        log.close()
                        r["actions"].append({
                            "action":"start_supervisor","status":"START_REQUESTED",
                            "pid":proc.pid})
                        time.sleep(3)
                    except Exception as e:
                        r["actions"].append({
                            "action":"start_supervisor","status":"FAILED",
                            "error":type(e).__name__})
                else:
                    r["actions"].append({
                        "action":"start_supervisor","status":"BLOCKED",
                        "reason":"omega/supervisor.py missing"})
        r["checks"]["http_after"] = http()
        cycle = ROOT / "tools" / "iao_autonomy_cycle.py"
        if cycle.is_file():
            r["checks"]["autonomy_cycle_installed"] = True
        else:
            r["checks"]["autonomy_cycle_installed"] = False
        federation = ROOT / "tools" / "iao_federation_contract.py"
        r["checks"]["federation_contract_installed"] = federation.is_file()
        cfg = STATE / "iao-external-nodes.json"
        try:
            d = json.loads(cfg.read_text(encoding="utf-8")) if cfg.exists() else {}
            nodes = d.get("nodes",[]) if isinstance(d,dict) else []
            r["checks"]["external_nodes"] = {
                "config_exists":cfg.exists(),
                "configured_count":len(nodes) if isinstance(nodes,list) else None,
                "authorized_count":sum(1 for n in nodes if isinstance(n,dict)
                                       and n.get("authorized") is True)
                    if isinstance(nodes,list) else None,
                "real_exchange_verified":False}
        except Exception:
            r["checks"]["external_nodes"] = {"config_valid":False,
                                             "real_exchange_verified":False}
        r["status"] = (
            "LOCAL_ONLINE" if r["checks"]["compileall"] == "PASS"
            and r["checks"]["http_after"]["status"] == "PASS"
            else "DEGRADED")
    r["utc_finished"] = utc()
    r["source_sha256"] = {
        str(p.relative_to(ROOT)):sha(p)
        for p in (ROOT/"omega"/"supervisor.py",
                  ROOT/"omega"/"server.py",
                  ROOT/"omega"/"service.py")
    }
    out = STATE / "iao-020-report.json"
    tmp = out.with_suffix(".tmp")
    tmp.write_text(json.dumps(r,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    os.replace(tmp,out)
    print(json.dumps(r,indent=2,ensure_ascii=False))
    print("REPORT_PATH="+str(out))
    print("REPORT_SHA256="+sha(out))
    return 0 if r["status"] == "LOCAL_ONLINE" else 2
if __name__ == "__main__":
    raise SystemExit(main())
