"""Killable process boundary for queued, explicitly approved read-only tools.

This limits execution time and selected POSIX resources. It is not an OS
sandbox: filesystem isolation and controlled global outbound networking must
be supplied by deployment. The child inherits the host network namespace;
this module neither provides persistent connectivity nor qualifies egress
policy, route failover, or isolation from private/control-plane networks.
See docs/SANDBOX_GLOBAL_NETWORK.md before production use.
"""
from __future__ import annotations

import json
import multiprocessing
import os
from typing import Any, Callable

MAX_RESULT_BYTES = 1_048_576
MAX_INPUT_BYTES = 65_536
MAX_ADDRESS_SPACE = 2_147_483_648


class ToolProcessTimeout(TimeoutError):
    pass


class ToolProcessError(RuntimeError):
    pass


def _apply_child_limits(timeout_seconds: float) -> None:
    if os.name != "posix":
        return
    try:
        import resource

        cpu = max(1, int(timeout_seconds) + 1)
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
        resource.setrlimit(
            resource.RLIMIT_AS, (MAX_ADDRESS_SPACE, MAX_ADDRESS_SPACE)
        )
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_RESULT_BYTES, MAX_RESULT_BYTES))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        if hasattr(resource, "RLIMIT_CORE"):
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, OSError, ValueError):
        # Parent still enforces a wall-clock deadline and kills the process.
        pass


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


def run_tool_isolated(run: Callable[..., Any], verify: Callable[..., Any],
                      payload: dict[str, Any], timeout_seconds: float
                      ) -> tuple[dict[str, Any], str]:
    if not 0 < timeout_seconds <= 300:
        raise ValueError("INVALID_TOOL_TIMEOUT")
    input_bytes = json.dumps(
        payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    if len(input_bytes) > MAX_INPUT_BYTES:
        raise ValueError("TOOL_INPUT_TOO_LARGE")

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
