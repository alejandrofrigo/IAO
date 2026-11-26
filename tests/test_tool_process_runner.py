from __future__ import annotations

import os
import time

import pytest

from omega.tools.process_runner import (
    ToolProcessTimeout,
    run_tool_isolated,
)


def _echo_tool(payload):
    return {"value": payload["value"]}


def _verify_echo(output):
    return "PASS" if output == {"value": "isolated"} else "FAIL"


def _sleep_tool(_payload):
    time.sleep(10)
    return {"finished": True}


def _verify_sleep(_output):
    return "PASS"


def test_tool_runs_in_separate_process_and_returns_verified_json():
    output, verdict = run_tool_isolated(
        _echo_tool, _verify_echo, {"value": "isolated"}, 5
    )
    assert output == {"value": "isolated"}
    assert verdict == "PASS"


def test_timed_out_tool_process_is_terminated():
    started = time.monotonic()
    with pytest.raises(ToolProcessTimeout):
        run_tool_isolated(_sleep_tool, _verify_sleep, {}, 0.5)
    assert time.monotonic() - started < 5
