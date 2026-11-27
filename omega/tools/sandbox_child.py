"""Trusted child entrypoint used only inside the bubblewrap namespace."""
from __future__ import annotations

import contextlib
import json
import os
import pickle
import sys
from typing import Any

MAX_INPUT_BYTES = 65_536 + 262_144
MAX_RESULT_BYTES = 1_048_576
MAX_ADDRESS_SPACE = 2_147_483_648


def _limits(timeout: float) -> None:
    if os.name != "posix":
        raise RuntimeError("POSIX_SANDBOX_REQUIRED")
    import resource

    cpu = max(1, int(timeout) + 1)
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
    resource.setrlimit(resource.RLIMIT_AS, (MAX_ADDRESS_SPACE, MAX_ADDRESS_SPACE))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_RESULT_BYTES, MAX_RESULT_BYTES))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    if hasattr(resource, "RLIMIT_CORE"):
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


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
