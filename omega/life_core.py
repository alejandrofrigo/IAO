from __future__ import annotations

import argparse
import asyncio
import fcntl
import json
import os
import signal
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / ".state" / "iao-life"
MEMORY = STATE / "memory.json"
EVENTS = STATE / "life-events.jsonl"
LOG = ROOT / "logs" / "iao-life-core.log"
LOCK = STATE / "life-core.lock"

INTERVAL = max(300, int(os.environ.get("IAO_LIFE_INTERVAL", "900")))
DAILY_LIMIT = max(1, int(os.environ.get("IAO_LIFE_DAILY_LIMIT", "24")))

GOALS = [
    "SELF_PROGRAMMING",
    "FEDERATION",
    "PERSISTENT_MEMORY",
    "RESILIENCE",
    "SYSTEM_INTEGRATION",
    "CAPABILITY_RESEARCH",
]

running = True


def utc():
    return datetime.now(timezone.utc).isoformat()


def log(message):
    LOG.parent.mkdir(parents=True, exist_ok=True)
    line = f"{utc()} {message}"
    with LOG.open("a", encoding="utf-8") as f:
        f.write(line + "\n")
    print(line, flush=True)


def event(name, **data):
    STATE.mkdir(parents=True, exist_ok=True)
    record = {"time": utc(), "event": name, **data}
    with EVENTS.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
    log(json.dumps(record, ensure_ascii=False, default=str))


def load_memory():
    if not MEMORY.exists():
        return {
            "version": 1,
            "created_at": utc(),
            "updated_at": utc(),
            "cycle_count": 0,
            "goal_cursor": 0,
            "last_goal": None,
            "last_result": None,
            "history": [],
        }
    try:
        data = json.loads(MEMORY.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("memory root is not an object")
        data.setdefault("cycle_count", 0)
        data.setdefault("goal_cursor", 0)
        data.setdefault("history", [])
        return data
    except Exception as exc:
        event("MEMORY_RECOVERY_REQUIRED", error=str(exc))
        return {
            "version": 1,
            "created_at": utc(),
            "updated_at": utc(),
            "cycle_count": 0,
            "goal_cursor": 0,
            "last_goal": None,
            "last_result": None,
            "history": [],
        }


def save_memory(memory):
    memory["updated_at"] = utc()
    MEMORY.parent.mkdir(parents=True, exist_ok=True)
    temp = MEMORY.with_suffix(".json.tmp")
    temp.write_text(
        json.dumps(memory, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    os.replace(temp, MEMORY)


def daily_cycles():
    today = datetime.now(timezone.utc).date().isoformat()
    count = 0
    if not EVENTS.exists():
        return count

    with EVENTS.open(encoding="utf-8") as f:
        for line in f:
            try:
                row = json.loads(line)
                if (
                    row.get("event") == "LIFE_CYCLE_COMPLETED"
                    and str(row.get("time", "")).startswith(today)
                ):
                    count += 1
            except Exception:
                continue
    return count


def safe_result(value):
    try:
        rendered = json.dumps(value, ensure_ascii=False, default=str)
    except Exception:
        rendered = repr(value)
    return rendered[:12000]


def build_snapshot(memory, goal):
    return {
        "system": "IAO",
        "component": "LIFE_CORE",
        "mode": "CONTINUOUS_OPERATION",
        "timestamp": utc(),
        "current_goal": goal,
        "cycle_count": memory["cycle_count"],
        "previous_goal": memory.get("last_goal"),
        "previous_result": memory.get("last_result"),
        "persistent_memory": {
            "history": memory.get("history", [])[-12:],
        },
        "instructions": [
            "Analiza el objetivo actual usando el estado y las evidencias disponibles.",
            "Propón acciones técnicas concretas y verificables.",
            "Distingue propuestas, ejecuciones, promociones e integraciones.",
            "No inventes procesos, nodos, endpoints ni resultados.",
            "Prioriza cambios reversibles con respaldo y pruebas.",
            "No solicites secretos ni reveles credenciales.",
            "No declares un cambio integrado si no se ha ejecutado y verificado.",
            "Respeta la autoridad administrativa y las políticas de IAO.",
        ],
    }


async def invoke_padge(snapshot):
    from omega.padge import ask_iao

    result = ask_iao(snapshot)
    if hasattr(result, "__await__"):
        result = await result
    return result


def run_cycle(memory):
    cursor = int(memory.get("goal_cursor", 0)) % len(GOALS)
    goal = GOALS[cursor]
    cycle_id = f"{int(time.time())}-{cursor}"

    event(
        "LIFE_CYCLE_STARTED",
        cycle_id=cycle_id,
        goal=goal,
        cycle_number=memory.get("cycle_count", 0) + 1,
    )

    try:
        snapshot = build_snapshot(memory, goal)
        result = asyncio.run(invoke_padge(snapshot))
        result_text = safe_result(result)

        # Persistir el resultado de PADGE en la cola de desarrollo.
        from omega.padge_execution_bridge import register_result
        bridge_result = register_result(cycle_id, goal, result)
        event("PADGE_RESULT_REGISTERED", **bridge_result)

        memory["cycle_count"] = int(memory.get("cycle_count", 0)) + 1
        memory["last_goal"] = goal
        memory["last_result"] = result_text
        memory["goal_cursor"] = (cursor + 1) % len(GOALS)
        memory.setdefault("history", []).append({
            "time": utc(),
            "cycle_id": cycle_id,
            "goal": goal,
            "status": "PADGE_RESPONSE_RECEIVED",
            "result": result_text[:3000],
        })
        memory["history"] = memory["history"][-100:]
        save_memory(memory)

        event(
            "LIFE_CYCLE_COMPLETED",
            cycle_id=cycle_id,
            goal=goal,
            execution="PADGE_RESPONSE_RECEIVED",
            code_integration="NOT_ASSERTED",
            result=result_text[:3000],
        )
        return True

    except Exception as exc:
        memory["last_goal"] = goal
        memory["last_result"] = f"{type(exc).__name__}: {exc}"
        memory["goal_cursor"] = (cursor + 1) % len(GOALS)
        memory.setdefault("history", []).append({
            "time": utc(),
            "cycle_id": cycle_id,
            "goal": goal,
            "status": "ERROR",
            "error": str(exc),
        })
        memory["history"] = memory["history"][-100:]
        save_memory(memory)

        event(
            "LIFE_CYCLE_ERROR",
            cycle_id=cycle_id,
            goal=goal,
            error=f"{type(exc).__name__}: {exc}",
            traceback=traceback.format_exc()[-5000:],
        )
        return False


def stop_handler(signum, frame):
    global running
    running = False
    log(f"STOP_SIGNAL_RECEIVED signal={signum}")


def main():
    global running

    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--daemon", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    STATE.mkdir(parents=True, exist_ok=True)
    LOG.parent.mkdir(parents=True, exist_ok=True)

    if args.self_test:
        from omega.padge import ask_iao
        if not callable(ask_iao):
            raise RuntimeError("PADGE ask_iao is not callable")
        print("SELF_TEST_OK: PADGE.ask_iao disponible")
        print(f"MEMORY_PATH={MEMORY}")
        print(f"EVENTS_PATH={EVENTS}")
        return 0

    with LOCK.open("a+", encoding="utf-8") as lockfile:
        try:
            fcntl.flock(lockfile.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("LIFE_ALREADY_RUNNING")
            return 0

        signal.signal(signal.SIGTERM, stop_handler)
        signal.signal(signal.SIGINT, stop_handler)

        memory = load_memory()
        event(
            "LIFE_CORE_STARTED",
            pid=os.getpid(),
            interval_seconds=INTERVAL,
            daily_limit=DAILY_LIMIT,
        )

        if args.once:
            run_cycle(memory)
            return 0

        while running:
            if daily_cycles() >= DAILY_LIMIT:
                event("DAILY_CYCLE_LIMIT_REACHED", limit=DAILY_LIMIT)
                time.sleep(60)
                continue

            run_cycle(memory)

            for _ in range(INTERVAL):
                if not running:
                    break
                time.sleep(1)

        event("LIFE_CORE_STOPPED", pid=os.getpid())

    return 0


if __name__ == "__main__":
    sys.exit(main())
