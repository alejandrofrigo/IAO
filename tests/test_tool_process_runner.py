from __future__ import annotations

import os
import time

import pytest

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

def _inspect_child_environment(_payload):
    return {"secret_visible": "IAO_PROCESS_RUNNER_TEST_SECRET" in os.environ}


def _verify_secret_is_hidden(output):
    return "PASS" if output == {"secret_visible": False} else "FAIL"


def test_tool_child_does_not_receive_parent_environment(monkeypatch):
    monkeypatch.setenv("IAO_PROCESS_RUNNER_TEST_SECRET", "must-not-cross-boundary")

    output, verdict = run_tool_isolated(
        _inspect_child_environment,
        _verify_secret_is_hidden,
        {},
        5,
    )

    assert output == {"secret_visible": False}
    assert verdict == "PASS"
    # The isolation boundary must not mutate the API process environment.
    assert os.environ["IAO_PROCESS_RUNNER_TEST_SECRET"] == "must-not-cross-boundary"



def _inspect_child_resource_limits(_payload):
    import resource

    return {
        "nofile_soft": resource.getrlimit(resource.RLIMIT_NOFILE)[0],
        "core_soft": (
            resource.getrlimit(resource.RLIMIT_CORE)[0]
            if hasattr(resource, "RLIMIT_CORE") else None
        ),
        "address_space_soft": resource.getrlimit(resource.RLIMIT_AS)[0],
    }


def _verify_child_resource_limits(output):
    if os.name != "posix":
        return "SKIP"
    valid = (
        output["nofile_soft"] <= 64
        and output["core_soft"] == 0
        and output["address_space_soft"] <= 2_147_483_648
    )
    return "PASS" if valid else "FAIL"


@pytest.mark.skipif(os.name != "posix", reason="POSIX resource limits required")
def test_tool_child_applies_resource_limits():
    output, verdict = run_tool_isolated(
        _inspect_child_resource_limits,
        _verify_child_resource_limits,
        {},
        5,
    )

    assert verdict == "PASS"
    assert output["nofile_soft"] <= 64
    assert output["core_soft"] == 0
    assert output["address_space_soft"] <= 2_147_483_648
