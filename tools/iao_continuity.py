#!/usr/bin/env python3
"""IAO-021: continuous local supervision with bounded recovery."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib, json, os, socket, subprocess, sys, time, urllib.request, ssl

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".state"
PIDFILE = STATE / "iao-continuity.pid"
STATUS = STATE / "iao-continuity-status.json"
LOG = STATE / "iao-continuity-events.jsonl"
INTERVAL = 60

def utc():
    return datetime.now(timezone.utc).isoformat()
def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
def port_open():
    s = socket.socket()
    s.settimeout(1)
    try:
        return s.connect_ex(("127.0.0.1", 8080)) == 0
    finally:
        s.close()
def http_check():
    try:
        req = urllib.request.Request("http://127.0.0.1:8080/",
                                     headers={"User-Agent":"IAO-Continuity/1.0"})
        with urllib.request.urlopen(req, timeout=4) as r:
            r.read(512)
            return {"ok": 200 <= r.status < 400, "code": r.status}
    except Exception as e:
        return {"ok": False, "error": type(e).__name__}
def internet_check():
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection(("example.com",443),timeout=4) as raw:
            with ctx.wrap_socket(raw,server_hostname="example.com") as s:
                return {"ok": True, "tls": s.version()}
    except Exception as e:
        return {"ok": False, "error": type(e).__name__}
def event(obj):
    obj["utc"] = utc()
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")
def alive_pid():
    try:
        pid = int(PIDFILE.read_text().strip())
        if pid == os.getpid():
            return False
        cmd = Path("/proc") / str(pid) / "cmdline"
        return cmd.exists() and b"iao_continuity.py" in cmd.read_bytes()
    except Exception:
        return False
def cycle(n):
    r = {"system":"IAO","patch":"IAO-021","cycle":n,"utc":utc()}
    if n == 1 or n % 10 == 0:
        try:
            cp = subprocess.run([sys.executable,"-m","compileall","-q","omega","tools"],
                                cwd=ROOT,capture_output=True,text=True,timeout=60)
            r["compileall"] = "PASS" if cp.returncode == 0 else "FAIL"
        except Exception as e:
            r["compileall"] = "ERROR:" + type(e).__name__
    h = http_check()
    r["local_http"] = h
    if not h["ok"] and not port_open():
        sup = ROOT / "omega" / "supervisor.py"
        if sup.is_file():
            try:
                with (STATE / "iao-continuity-supervisor.log").open("ab") as log:
                    p = subprocess.Popen(
                        [sys.executable,"-m","omega.supervisor"],cwd=ROOT,
                        stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,
                        start_new_session=True,close_fds=True)
                r["recovery"] = {"result":"START_REQUESTED","pid":p.pid}
                time.sleep(3)
                r["local_http_after_recovery"] = http_check()
            except Exception as e:
                r["recovery"] = {"result":"FAILED","error":type(e).__name__}
        else:
            r["recovery"] = {"result":"BLOCKED","reason":"supervisor missing"}
    elif not h["ok"]:
        r["recovery"] = {"result":"NOT_ATTEMPTED",
                         "reason":"port occupied; refusing to kill unknown process"}
    if n == 1 or n % 5 == 0:
        r["outbound_tls"] = internet_check()
    cfg = STATE / "iao-external-nodes.json"
    try:
        d = json.loads(cfg.read_text(encoding="utf-8")) if cfg.exists() else {}
        nodes = d.get("nodes",[]) if isinstance(d,dict) else []
        r["configured_nodes"] = len(nodes) if isinstance(nodes,list) else None
    except Exception:
        r["configured_nodes"] = "CONFIG_INVALID"
    r["verified_peer_exchanges"] = 0
    r["note"] = "TLS reachability does not prove federation or public deployment"
    r["status"] = "LOCAL_ONLINE" if http_check()["ok"] else "DEGRADED"
    tmp = STATUS.with_suffix(".tmp")
    tmp.write_text(json.dumps(r,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    os.replace(tmp,STATUS)
    event(r)
    return r
def main():
    STATE.mkdir(parents=True,exist_ok=True)
    if alive_pid():
        print("IAO_CONTINUITY=ALREADY_RUNNING")
        print("STATUS_PATH="+str(STATUS))
        return 0
    PIDFILE.write_text(str(os.getpid())+"\n",encoding="utf-8")
    n = 0
    event({"event":"CONTINUITY_STARTED","pid":os.getpid()})
    try:
        while True:
            n += 1
            try:
                cycle(n)
            except Exception as e:
                event({"event":"CYCLE_ERROR","cycle":n,"error":type(e).__name__})
            time.sleep(INTERVAL)
    finally:
        try:
            PIDFILE.unlink()
        except OSError:
            pass
if __name__ == "__main__":
    main()
