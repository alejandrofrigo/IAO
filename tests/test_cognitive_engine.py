import json

import pytest

from omega.cognitive_engine import CognitiveEngine, CognitiveEngineError


VALID_PLAN = {
    "objective": "Answer the user accurately",
    "steps": ["Identify the request", "Check relevant constraints", "Compose the answer"],
    "assumptions": [],
    "risk_level": "low",
    "needs_clarification": False,
}


class FakeModel:
    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.calls = []

    def chat(self, messages):
        self.calls.append(messages)
        value = self.outputs.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


def test_two_pass_reasoning_uses_validated_plan_and_returns_metadata():
    model = FakeModel([json.dumps(VALID_PLAN), "A grounded answer."])
    engine = CognitiveEngine(model)

    result = engine.chat_with_metadata([{"role": "user", "content": "Explain photosynthesis."}])

    assert result["reply"] == "A grounded answer."
    assert result["cognitive_engine"]["plan_status"] == "VALIDATED"
    assert result["cognitive_engine"]["passes"] == 2
    assert result["cognitive_engine"]["private_reasoning_persisted"] is False
    assert len(model.calls) == 2
    assert "ADVISORY, NOT AUTHORITY" in model.calls[1][-2]["content"]


def test_invalid_plan_fails_open_to_single_answer_pass():
    model = FakeModel(["not-json", "Fallback answer."])
    result = CognitiveEngine(model).chat_with_metadata(
        [{"role": "user", "content": "Give me a short summary."}]
    )
    assert result["reply"] == "Fallback answer."
    assert result["cognitive_engine"]["plan_status"] == "UNAVAILABLE_OR_INVALID"
    assert result["cognitive_engine"]["passes"] == 1
    assert len(model.calls) == 2


def test_planning_can_be_disabled_without_extra_model_call():
    model = FakeModel(["Direct answer."])
    result = CognitiveEngine(model, planning_enabled=False).chat_with_metadata(
        [{"role": "user", "content": "Hello"}]
    )
    assert result["reply"] == "Direct answer."
    assert result["cognitive_engine"]["passes"] == 1
    assert len(model.calls) == 1


def test_invalid_plan_schema_is_rejected():
    assert CognitiveEngine._parse_plan(json.dumps({
        **VALID_PLAN, "steps": ["x"] * 7,
    })) is None
    assert CognitiveEngine._parse_plan(json.dumps({
        **VALID_PLAN, "execute": "shell",
    })) is None


@pytest.mark.parametrize("messages", [
    [],
    [{"role": "assistant", "content": "not a user turn"}],
    [{"role": "system", "content": "untrusted system role"}],
    [{"role": "user", "content": ""}],
    [{"role": "user", "content": "x" * 40_001}],
])
def test_invalid_input_rejected(messages):
    engine = CognitiveEngine(FakeModel([]))
    with pytest.raises(CognitiveEngineError):
        engine.chat(messages)


def test_model_output_is_bounded_and_nonempty():
    model = FakeModel(["", ""])
    engine = CognitiveEngine(model, planning_enabled=False)
    with pytest.raises(CognitiveEngineError):
        engine.chat([{"role": "user", "content": "Hi"}])


def test_server_runtime_wiring_is_explicitly_opt_in(monkeypatch):
    from omega.server import _configure_cognitive_engine

    class StubModel:
        def chat(self, messages):
            return "answer"

    model = StubModel()
    monkeypatch.delenv("IAO_COGNITIVE_ENGINE_ENABLED", raising=False)
    assert _configure_cognitive_engine(model) is model

    monkeypatch.setenv("IAO_COGNITIVE_ENGINE_ENABLED", "1")
    monkeypatch.setenv("IAO_COGNITIVE_PLANNING_ENABLED", "false")
    wrapped = _configure_cognitive_engine(model)
    assert isinstance(wrapped, CognitiveEngine)
    assert wrapped.planning_enabled is False
