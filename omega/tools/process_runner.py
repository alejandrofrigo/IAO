"""Killable process boundary plus a production-required bubblewrap OS sandbox.

Development defaults to a restricted process. APP_ENV=production defaults to
bubblewrap: read-only root, masked state/home/runtime directories, no network,
dropped capabilities and POSIX resource limits. Missing sandbox support fails closed.
"""
from __future__ import annotations

import json
import multiprocessing
import os
import math
import pickle
import shutil
import subprocess
import sys
from typing import Any, Callable

MAX_RESULT_BYTES = 1_048_576
MAX_INPUT_BYTES = 65_536
MAX_ADDRESS_SPACE = 2_147_483_648


class ToolProcessTimeout(TimeoutError):
    pass


class ToolProcessError(RuntimeError):
    pass


def _apply_child_limits(timeout_seconds: float) -> None:
    """Apply mandatory POSIX limits; never silently continue without them.

    This is defense-in-depth, not filesystem or network isolation. Deployments
    that execute untrusted tools still require an OS/container sandbox.
    """
    if os.name != "posix":
        raise RuntimeError("OS_RESOURCE_LIMITS_UNAVAILABLE")
    try:
        import resource

        requested = {
            resource.RLIMIT_CPU: (max(1, int(timeout_seconds) + 1), max(2, int(timeout_seconds) + 2)),
            resource.RLIMIT_AS: (MAX_ADDRESS_SPACE, MAX_ADDRESS_SPACE),
            resource.RLIMIT_FSIZE: (MAX_RESULT_BYTES, MAX_RESULT_BYTES),
            resource.RLIMIT_NOFILE: (64, 64),
        }
        if hasattr(resource, "RLIMIT_CORE"):
            requested[resource.RLIMIT_CORE] = (0, 0)
        for limit, (soft, hard) in requested.items():
            _current_soft, current_hard = resource.getrlimit(limit)
            if current_hard != resource.RLIM_INFINITY:
                hard = min(hard, current_hard)
                soft = min(soft, hard)
            if soft <= 0 and limit != getattr(resource, "RLIMIT_CORE", None):
                raise RuntimeError("OS_RESOURCE_LIMIT_INVALID")
            resource.setrlimit(limit, (soft, hard))
            applied_soft, applied_hard = resource.getrlimit(limit)
            if applied_soft > soft or applied_hard > hard:
                raise RuntimeError("OS_RESOURCE_LIMIT_NOT_ENFORCED")
    except (ImportError, OSError, ValueError) as exc:
        raise RuntimeError("OS_RESOURCE_LIMITS_UNAVAILABLE") from exc


def _child_entry(send_conn: Any, run: Callable[..., Any], verify: Callable[..., Any],
                 payload: dict[str, Any], timeout_seconds: float) -> None:
    try:
        _apply_child_limits(timeout_seconds)
        # Queued tools must not inherit application credentials through env vars.
        os.environ.clear()
        output = run(payload)
        encoded = json.dumps(
            output, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        if len(encoded) > MAX_RESULT_BYTES:
            raise ValueError("TOOL_RESULT_TOO_LARGE")
        verdict = verify(output)
        if not isinstance(verdict, str) or len(verdict) > 32:
            raise ValueError("INVALID_VERIFICATION_RESULT")
        send_conn.send_bytes(json.dumps({
            "ok": True, "output": encoded.decode("utf-8"), "verdict": verdict,
        }, separators=(",", ":")).encode("utf-8"))
    except BaseException as exc:
        try:
            send_conn.send_bytes(json.dumps({
                "ok": False,
                "error": "TOOL_PROCESS_ERROR",
                "error_type": type(exc).__name__[:80],
            }).encode("utf-8"))
        except (BrokenPipeError, OSError):
            pass
    finally:
        send_conn.close()





def _run_tool_bubblewrap(
    run: Callable[..., Any],
    verify: Callable[..., Any],
    payload: dict[str, Any],
    timeout_seconds: float,
) -> tuple[dict[str, Any], str]:
    """Execute a trusted registered tool inside a read-only, networkless namespace."""
    binary = shutil.which("bwrap")
    if not binary:
        raise ToolProcessError("OS_SANDBOX_UNAVAILABLE")
    command = [
        binary,
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--ro-bind", "/", "/",
        "--dev", "/dev",
        "--proc", "/proc",
        "--tmpfs", "/tmp",
        "--tmpfs", "/home",
        "--tmpfs", "/root",
        "--tmpfs", "/var/lib",
        "--tmpfs", "/run",
        "--cap-drop", "ALL",
        "--clearenv",
        "--setenv", "HOME", "/tmp",
        "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
        "--setenv", "PYTHONDONTWRITEBYTECODE", "1",
        "--chdir", os.getcwd(),
        sys.executable, "-m", "omega.tools.sandbox_child",
    ]
    try:
        serialized = pickle.dumps(
            (run, verify, payload, timeout_seconds),
            protocol=pickle.HIGHEST_PROTOCOL,
        )
        if len(serialized) > MAX_INPUT_BYTES + 262_144:
            raise ValueError("TOOL_SANDBOX_INPUT_TOO_LARGE")
        completed = subprocess.run(
            command,
            input=serialized,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds + 2,
            check=False,
            close_fds=True,
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolProcessTimeout("TOOL_PROCESS_TIMED_OUT") from exc
    except (OSError, pickle.PickleError) as exc:
        raise ToolProcessError("OS_SANDBOX_LAUNCH_FAILED") from exc
    if completed.returncode != 0:
        raise ToolProcessError("OS_SANDBOX_EXECUTION_FAILED")
    try:
        message = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ToolProcessError("OS_SANDBOX_INVALID_RESULT") from exc
    if not isinstance(message, dict) or not message.get("ok"):
        raise ToolProcessError("TOOL_PROCESS_ERROR")
    try:
        output = json.loads(message["output"])
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ToolProcessError("OS_SANDBOX_INVALID_RESULT") from exc
    verdict = message.get("verdict")
    if not isinstance(output, dict) or not isinstance(verdict, str) or len(verdict) > 32:
        raise ToolProcessError("OS_SANDBOX_INVALID_RESULT")
    return output, verdict

def run_tool_isolated(run: Callable[..., Any], verify: Callable[..., Any],
                      payload: dict[str, Any], timeout_seconds: float
                      ) -> tuple[dict[str, Any], str]:
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(float(timeout_seconds))
        or not 0 < timeout_seconds <= 300
    ):
        raise ValueError("INVALID_TOOL_TIMEOUT")
    try:
        input_bytes = json.dumps(
            payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ValueError("INVALID_TOOL_INPUT") from exc
    if len(input_bytes) > MAX_INPUT_BYTES:
        raise ValueError("TOOL_INPUT_TOO_LARGE")
    production = os.environ.get("APP_ENV", "").strip().lower() == "production"
    mode = os.environ.get("IAO_TOOL_SANDBOX_MODE")
    if production:
        if mode not in (None, "bubblewrap", "required"):
            raise ToolProcessError("OS_SANDBOX_REQUIRED")
        mode = "bubblewrap"
    elif mode is None:
        mode = "process"
    if mode in {"bubblewrap", "required"}:
        return _run_tool_bubblewrap(run, verify, payload, timeout_seconds)
    if mode != "process":
        raise ValueError("INVALID_TOOL_SANDBOX_MODE")

    context = multiprocessing.get_context("spawn")
    receive_conn, send_conn = context.Pipe(duplex=False)
    process = context.Process(
        target=_child_entry,
        args=(send_conn, run, verify, payload, timeout_seconds),
        daemon=True,
    )
    try:
        process.start()
    except BaseException:
        receive_conn.close()
        send_conn.close()
        raise
    send_conn.close()
    try:
        if not receive_conn.poll(timeout_seconds):
            if process.is_alive():
                process.terminate()
                process.join(timeout=1)
            if process.is_alive() and hasattr(process, "kill"):
                process.kill()
                process.join(timeout=1)
            raise ToolProcessTimeout("TOOL_PROCESS_TIMED_OUT")
        raw = receive_conn.recv_bytes(MAX_RESULT_BYTES + 4096)
        message = json.loads(raw.decode("utf-8"))
        process.join(timeout=1)
        if process.is_alive():
            process.terminate()
            process.join(timeout=1)
        if not message.get("ok"):
            raise ToolProcessError(message.get("error", "TOOL_PROCESS_ERROR"))
        output = json.loads(message["output"])
        if not isinstance(output, dict):
            raise ToolProcessError("INVALID_TOOL_OUTPUT")
        return output, message["verdict"]
    except ToolProcessTimeout:
        raise
    except (EOFError, OSError, json.JSONDecodeError) as exc:
        raise ToolProcessError("TOOL_PROCESS_CRASHED") from exc
    finally:
        receive_conn.close()
        if process.is_alive():
            process.terminate()
            process.join(timeout=1)
        if process.is_alive() and hasattr(process, "kill"):
            process.kill()
            process.join(timeout=1)
        process.close()


def _sandbox_probe_run(payload: dict[str, Any]) -> dict[str, Any]:
    return {"probe": payload.get("probe")}


def _sandbox_probe_verify(output: dict[str, Any]) -> str:
    return "PASS" if output == {"probe": "IAO_OS_SANDBOX_V1"} else "FAIL"


def verify_os_sandbox() -> bool:
    """Prove that the configured production sandbox can actually launch and isolate."""
    output, verdict = run_tool_isolated(
        _sandbox_probe_run,
        _sandbox_probe_verify,
        {"probe": "IAO_OS_SANDBOX_V1"},
        5,
    )
    if verdict != "PASS" or output != {"probe": "IAO_OS_SANDBOX_V1"}:
        raise ToolProcessError("OS_SANDBOX_PREFLIGHT_FAILED")
    return True
