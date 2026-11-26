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
        run_tool_isolated(_sleep_tool, _verify_sleep, {}, 2.0)
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
