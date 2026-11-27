"""Trusted child entrypoint used only inside the bubblewrap namespace."""
from __future__ import annotations

import contextlib
import json
import os
import pickle
import sys
from contextlib import redirect_stderr, redirect_stdout
from typing import Any

MAX_INPUT_BYTES = 65_536 + 262_144
MAX_RESULT_BYTES = 1_048_576
MAX_ADDRESS_SPACE = 2_147_483_648


def _limits(timeout: float) -> None:
    if os.name != "posix":
        raise RuntimeError("POSIX_SANDBOX_REQUIRED")
    import resource

    def bounded(kind: int, soft_cap: int, hard_cap: int | None = None) -> None:
        _old_soft, old_hard = resource.getrlimit(kind)
        target_hard = soft_cap if hard_cap is None else hard_cap
        if old_hard != resource.RLIM_INFINITY:
            target_hard = min(target_hard, old_hard)
        target_soft = min(soft_cap, target_hard)
        resource.setrlimit(kind, (target_soft, target_hard))

    cpu = max(1, int(timeout) + 1)
    bounded(resource.RLIMIT_CPU, cpu, cpu + 1)
    bounded(resource.RLIMIT_AS, MAX_ADDRESS_SPACE)
    bounded(resource.RLIMIT_FSIZE, MAX_RESULT_BYTES)
    bounded(resource.RLIMIT_NOFILE, 64)
    if hasattr(resource, "RLIMIT_NPROC"):
        bounded(resource.RLIMIT_NPROC, 32)
    if hasattr(resource, "RLIMIT_STACK"):
        bounded(resource.RLIMIT_STACK, 16 * 1024 * 1024)
    if hasattr(resource, "RLIMIT_CORE"):
        bounded(resource.RLIMIT_CORE, 0)


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        return 2
    try:
        run, verify, payload, timeout = pickle.loads(raw)
        if not isinstance(payload, dict) or not isinstance(timeout, (int, float)):
            raise ValueError("INVALID_SANDBOX_PAYLOAD")
        os.environ.clear()
        _limits(float(timeout))
        # Tool diagnostics must not corrupt the bounded stdout result protocol.
        with open(os.devnull, "w", encoding="utf-8") as sink:
            with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
                output = run(payload)
                verdict = verify(output)
        encoded = json.dumps(
            output, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        if len(encoded) > MAX_RESULT_BYTES:
            raise ValueError("TOOL_RESULT_TOO_LARGE")
        if not isinstance(verdict, str) or len(verdict) > 32:
            raise ValueError("INVALID_VERIFICATION_RESULT")
        message: dict[str, Any] = {
            "ok": True, "output": encoded.decode("utf-8"), "verdict": verdict,
        }
    except BaseException as exc:
        message = {
            "ok": False, "error": "TOOL_PROCESS_ERROR",
            "error_type": type(exc).__name__[:80],
        }
    sys.stdout.write(json.dumps(message, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
