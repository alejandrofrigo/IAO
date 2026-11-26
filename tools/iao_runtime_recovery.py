#!/usr/bin/env python3
"""Supervisión conservadora de procesos locales de IAO.

No inicia procesos, no mata procesos externos y no interpreta un PID
aislado como prueba suficiente de salud.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Callable


DEFAULT_STATE = Path(".state/iao-runtime-recovery")
MAX_RESTARTS = 3
WINDOW_SECONDS = 300


def process_matches(pid: int, expected: str) -> bool:
    if pid <= 1 or not expected:
        return False
    proc = Path("/proc") / str(pid)
    try:
        if not proc.exists():
            return False
        cmdline = (proc / "cmdline").read_bytes().replace(b"\0", b" ").decode(
            "utf-8", "replace"
        )
        return expected in cmdline
    except (OSError, ProcessLookupError):
        return False


class RuntimeRecovery:
    def __init__(
        self,
        state_dir: Path = DEFAULT_STATE,
        clock: Callable[[], float] = time.time,
    ):
        self.state_dir = Path(state_dir)
        self.clock = clock
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.events = self.state_dir / "events.jsonl"
        self.state = self.state_dir / "state.json"

    def _read(self) -> dict:
        try:
            value = json.loads(self.state.read_text())
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError):
            return {}

    def _write(self, value: dict) -> None:
        tmp = self.state.with_suffix(".tmp")
        tmp.write_text(json.dumps(value, sort_keys=True) + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.state)

    def _event(self, event: dict) -> None:
        event["timestamp"] = self.clock()
        fd = os.open(
            self.events,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o600,
        )
        with os.fdopen(fd, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    def observe(self, name: str, pid: int, expected_command: str) -> dict:
        if not name or "/" in name or not expected_command:
            raise ValueError("Identidad de proceso no válida")

        alive = process_matches(pid, expected_command)
        now = self.clock()
        state = self._read()
        entry = state.get(name, {})
        if not isinstance(entry, dict):
            entry = {}

        if alive:
            entry["last_seen"] = now
            entry["pid"] = pid
            entry["status"] = "RUNNING_VERIFIED"
            result = "RUNNING_VERIFIED"
        else:
            history = [
                t for t in entry.get("restart_attempts", [])
                if isinstance(t, (int, float)) and now - t < WINDOW_SECONDS
            ]
            entry["restart_attempts"] = history
            entry["pid"] = None
            entry["status"] = (
                "RESTART_BUDGET_EXHAUSTED"
                if len(history) >= MAX_RESTARTS
                else "NOT_RUNNING"
            )
            result = entry["status"]

        state[name] = entry
        self._write(state)
        self._event({
            "component": name,
            "observed_pid": pid,
            "status": result,
        })
        return {
            "component": name,
            "status": result,
            "restart_attempts_in_window": len(
                entry.get("restart_attempts", [])
            ),
            "restart_performed": False,
        }

    def record_restart_attempt(self, name: str) -> dict:
        if not name or "/" in name:
            raise ValueError("Identidad de componente no válida")

        now = self.clock()
        state = self._read()
        entry = state.setdefault(name, {})
        if not isinstance(entry, dict):
            raise ValueError("Estado de componente corrupto")

        history = [
            t for t in entry.get("restart_attempts", [])
            if isinstance(t, (int, float)) and now - t < WINDOW_SECONDS
        ]
        if len(history) >= MAX_RESTARTS:
            entry["status"] = "RESTART_BUDGET_EXHAUSTED"
            self._write(state)
            self._event({"component": name, "status": entry["status"]})
            return {"allowed": False, "status": entry["status"]}

        history.append(now)
        entry["restart_attempts"] = history
        entry["status"] = "RESTART_ATTEMPT_RECORDED"
        self._write(state)
        self._event({"component": name, "status": entry["status"]})
        return {"allowed": True, "status": entry["status"]}


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--state-dir", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--component", required=True)
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--expected-command", required=True)
    args = parser.parse_args()

    monitor = RuntimeRecovery(args.state_dir)
    print(json.dumps(
        monitor.observe(args.component, args.pid, args.expected_command),
        indent=2,
    ))
