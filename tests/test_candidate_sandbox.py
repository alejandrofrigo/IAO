from __future__ import annotations

import subprocess

from tools import iao_candidate_sandbox as sandbox


def test_parse_pytest_summary_counts_all_outcomes():
    parsed = sandbox._parse_summary(
        "........\n8 passed, 2 skipped, 1 xfailed, 1 xpassed in 1.2s\n"
    )

    assert parsed == {
        "passed": 8,
        "failed": 0,
        "errors": 0,
        "skipped": 2,
        "xfailed": 1,
        "xpassed": 1,
    }


def test_parse_pytest_summary_rejects_missing_summary():
    assert sandbox._parse_summary("pytest crashed before collecting tests") is None


def test_docker_suite_uses_offline_read_only_restricted_container(tmp_path, monkeypatch):
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(
            command, 0, stdout="3 passed in 0.2s", stderr=""
        )

    monkeypatch.setattr(sandbox.subprocess, "run", fake_run)

    result = sandbox._docker_suite(tmp_path, "iao-candidate-sandbox:test")

    command = captured["command"]
    assert (tmp_path / ".state").is_dir()
    assert "--pull=never" in command
    assert "--network=none" in command
    assert "--tmpfs=/workspace/.state:rw,noexec,nosuid,nodev,size=256m" in command
    assert "--read-only" in command
    assert "--cap-drop=ALL" in command
    assert "--pids-limit=128" in command
    assert "--memory=1g" in command
    assert "--cpus=2" in command
    assert "--security-opt=no-new-privileges:true" in command
    assert "--user=65534:65534" in command
    assert result["returncode"] == 0
    assert result["summary"]["passed"] == 3
    assert captured["kwargs"]["timeout"] == sandbox.RUN_TIMEOUT_SECONDS


def test_docker_suite_reports_missing_docker_without_claiming_pass(tmp_path, monkeypatch):
    def unavailable(*_args, **_kwargs):
        raise FileNotFoundError("docker")

    monkeypatch.setattr(sandbox.subprocess, "run", unavailable)

    result = sandbox._docker_suite(tmp_path, "missing-image")

    assert result["returncode"] is None
    assert result["summary"] is None
    assert result["timed_out"] is False


def test_docker_suite_kills_container_after_timeout(tmp_path, monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        if command[1] == "run":
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(sandbox.subprocess, "run", fake_run)

    result = sandbox._docker_suite(tmp_path, "iao-candidate-sandbox:test")

    assert result["timed_out"] is True
    assert result["container_cleanup_returncode"] == 0
    assert calls[1][:4] == ["docker", "rm", "-f", calls[1][3]]
    assert calls[1][3].startswith("iao-candidate-")



def test_comparison_rejects_increased_xfailed_and_xpassed_counts():
    baseline = {
        "returncode": 0,
        "summary": {"passed": 10, "failed": 0, "errors": 0, "skipped": 0, "xfailed": 1, "xpassed": 0},
    }
    candidate_xfailed = {
        "returncode": 0,
        "summary": {"passed": 10, "failed": 0, "errors": 0, "skipped": 0, "xfailed": 2, "xpassed": 0},
    }
    candidate_xpassed = {
        "returncode": 0,
        "summary": {"passed": 10, "failed": 0, "errors": 0, "skipped": 0, "xfailed": 1, "xpassed": 1},
    }

    assert sandbox._compare_results(baseline, candidate_xfailed)["passed"] is False
    assert sandbox._compare_results(baseline, candidate_xpassed)["passed"] is False


def test_comparison_requires_both_complete_successful_summaries():
    baseline = {"returncode": 0, "summary": None}
    candidate = {
        "returncode": 0,
        "summary": {"passed": 1, "failed": 0, "errors": 0, "skipped": 0, "xfailed": 0, "xpassed": 0},
    }

    result = sandbox._compare_results(baseline, candidate)

    assert result["comparable"] is False
    assert result["baseline_ok"] is False
    assert result["passed"] is False
