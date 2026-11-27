from __future__ import annotations

import os
import shutil
import subprocess
import time

import pytest
from omega.tools import process_runner

from omega.tools.knowledge_search import KnowledgeCorpus
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


def test_bound_local_corpus_tool_is_pickleable_in_spawned_process(tmp_path):
    (tmp_path / "security.txt").write_text(
        "IAO local knowledge corpus verifies source provenance.",
        encoding="utf-8",
    )
    corpus = KnowledgeCorpus(tmp_path)
    payload = corpus.validate_input({"query": "source provenance", "limit": 2})

    output, verdict = run_tool_isolated(
        corpus.run, corpus.verify, payload, 5
    )

    assert output["tool"] == "knowledge.search"
    assert output["items"][0]["document_id"] == "security"
    assert verdict == "PASS"


def test_production_mode_fails_closed_without_os_sandbox(monkeypatch):
    monkeypatch.delenv("IAO_TOOL_SANDBOX_MODE", raising=False)
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setattr(process_runner.shutil, "which", lambda _name: None)
    with pytest.raises(process_runner.ToolProcessError, match="OS_SANDBOX_UNAVAILABLE"):
        run_tool_isolated(_echo_tool, _verify_echo, {"value": "isolated"}, 5)


def test_bubblewrap_mode_uses_read_only_root_and_unshared_network(monkeypatch):
    monkeypatch.setenv("IAO_TOOL_SANDBOX_MODE", "bubblewrap")
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.setattr(process_runner.shutil, "which", lambda _name: "/usr/bin/bwrap")
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(
            command, 0,
            stdout=b'{"ok":true,"output":"{\\"value\\":\\"isolated\\"}","verdict":"PASS"}',
            stderr=b"",
        )

    monkeypatch.setattr(process_runner.subprocess, "run", fake_run)
    output, verdict = run_tool_isolated(
        _echo_tool, _verify_echo, {"value": "isolated"}, 5
    )
    assert output == {"value": "isolated"}
    assert verdict == "PASS"
    command = captured["command"]
    assert "--unshare-all" in command
    assert command[command.index("--ro-bind") + 1:command.index("--ro-bind") + 3] == ["/", "/"]
    assert command[command.index("--tmpfs") + 1] == "/tmp"
    pairs = set(zip(command, command[1:]))
    assert ("--tmpfs", "/var/lib") in pairs
    assert ("--tmpfs", "/run") in pairs
    assert ("--cap-drop", "ALL") in pairs


@pytest.mark.skipif(shutil.which("bwrap") is None, reason="bubblewrap not installed")
def test_bubblewrap_executes_registered_read_only_tool_in_os_sandbox(monkeypatch):
    monkeypatch.setenv("IAO_TOOL_SANDBOX_MODE", "bubblewrap")
    monkeypatch.delenv("APP_ENV", raising=False)
    output, verdict = run_tool_isolated(
        _echo_tool, _verify_echo, {"value": "isolated"}, 5
    )
    assert output == {"value": "isolated"}
    assert verdict == "PASS"



def test_runner_rejects_invalid_timeout_and_non_json_input_before_spawn():
    with pytest.raises(ValueError, match="INVALID_TOOL_TIMEOUT"):
        run_tool_isolated(_echo_tool, _verify_echo, {"value": "ok"}, float("nan"))
    with pytest.raises(ValueError, match="INVALID_TOOL_INPUT"):
        run_tool_isolated(_echo_tool, _verify_echo, {"value": object()}, 2)


def test_child_resource_limits_are_mandatory_on_posix(monkeypatch):
    import omega.tools.process_runner as runner

    monkeypatch.setattr(runner.os, "name", "nt")
    with pytest.raises(RuntimeError, match="OS_RESOURCE_LIMITS_UNAVAILABLE"):
        runner._apply_child_limits(1)
