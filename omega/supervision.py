"""Small, privacy-safe heartbeat primitives for local IAO supervisors."""
from __future__ import annotations

import fcntl
import json
import math
import os
import stat
import tempfile
import time
from pathlib import Path
from typing import Any

_HEARTBEAT_PHASES = {"starting", "cycle_running", "cycle_completed"}


def write_heartbeat(
    path: Path,
    *,
    component: str,
    pid: int,
    phase: str,
    interval_seconds: int,
    stale_after_seconds: int,
    last_cycle_completed_at: float | None = None,
    last_cycle_result: bool | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    """Atomically persist a minimal heartbeat without task or operator data."""
    timestamp = time.time() if now is None else float(now)
    if (
        not isinstance(component, str) or not component or len(component) > 64
        or isinstance(pid, bool) or not isinstance(pid, int) or pid < 1
        or phase not in _HEARTBEAT_PHASES
        or isinstance(interval_seconds, bool) or not isinstance(interval_seconds, int)
        or interval_seconds < 1
        or isinstance(stale_after_seconds, bool) or not isinstance(stale_after_seconds, int)
        or stale_after_seconds < interval_seconds
        or not math.isfinite(timestamp)
        or (last_cycle_completed_at is not None
            and (isinstance(last_cycle_completed_at, bool)
                 or not isinstance(last_cycle_completed_at, (int, float))
                 or not math.isfinite(float(last_cycle_completed_at))))
        or (last_cycle_result is not None and not isinstance(last_cycle_result, bool))
    ):
        raise ValueError("INVALID_HEARTBEAT")
    completed_at = timestamp if phase == "cycle_completed" else last_cycle_completed_at
    result = last_cycle_result if phase != "cycle_completed" else last_cycle_result
    payload = {
        "schema_version": 1,
        "component": component,
        "pid": pid,
        "phase": phase,
        "updated_at": timestamp,
        "interval_seconds": interval_seconds,
        "stale_after_seconds": stale_after_seconds,
        "last_cycle_completed_at": completed_at,
        "last_cycle_result": result,
    }
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    fd, temporary = tempfile.mkstemp(prefix=".heartbeat-", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return payload


def read_heartbeat(
    path: Path,
    *,
    expected_component: str,
    now: float | None = None,
) -> dict[str, Any]:
    """Return a bounded health classification; malformed or stale is unverified."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("INVALID_HEARTBEAT_FILE")
            payload = json.load(stream)
        if (
            not isinstance(payload, dict)
            or isinstance(payload.get("schema_version"), bool)
            or payload.get("schema_version") != 1
        ):
            raise ValueError
        if payload.get("component") != expected_component:
            raise ValueError
        pid = payload.get("pid")
        updated_at = payload.get("updated_at")
        stale_after = payload.get("stale_after_seconds")
        phase = payload.get("phase")
        if (
            isinstance(pid, bool) or not isinstance(pid, int) or pid < 1
            or isinstance(updated_at, bool) or not isinstance(updated_at, (int, float))
            or not math.isfinite(float(updated_at))
            or isinstance(stale_after, bool) or not isinstance(stale_after, int)
            or stale_after < 1
            or phase not in _HEARTBEAT_PHASES
        ):
            raise ValueError
        last_completed = payload.get("last_cycle_completed_at")
        last_result = payload.get("last_cycle_result")
        if (
            last_completed is not None
            and (
                isinstance(last_completed, bool)
                or not isinstance(last_completed, (int, float))
                or not math.isfinite(float(last_completed))
            )
        ):
            raise ValueError
        if last_result is not None and not isinstance(last_result, bool):
            raise ValueError
        current = time.time() if now is None else float(now)
        age = current - float(updated_at)
        if not math.isfinite(age) or age < -5:
            raise ValueError
        if age > stale_after:
            state = "STALE"
        elif phase == "cycle_running":
            state = "CYCLE_IN_PROGRESS"
        elif phase == "cycle_completed" and last_result is False:
            state = "DEGRADED"
        elif phase == "cycle_completed":
            state = "HEALTHY"
        else:
            state = "STARTING"
        return {
            "status": state,
            "pid": pid,
            "phase": phase,
            "age_seconds": max(0, int(age)),
            "last_cycle_completed_at": payload.get("last_cycle_completed_at"),
            "last_cycle_result": payload.get("last_cycle_result"),
        }
    except (OSError, ValueError, TypeError, OverflowError):
        return {"status": "UNVERIFIED"}


def read_lock_owner(path: Path) -> int | None:
    """Return the PID holding an advisory lock, or None when no lock is held."""
    path = Path(path)
    fd = None
    try:
        fd = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        with os.fdopen(fd, "r+", encoding="utf-8") as stream:
            fd = None
            raw_owner = stream.read(32).strip()
            owner = int(raw_owner) if raw_owner.isdigit() else None
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return owner if owner is not None and owner > 0 else 0
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            return None
    except (OSError, ValueError):
        return None
    finally:
        if fd is not None:
            os.close(fd)

