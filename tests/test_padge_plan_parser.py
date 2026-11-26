
import pytest

from omega.padge import _parse_model_plan


def test_parse_plain_json():
    result = _parse_model_plan(
        '{"goal":"Mejora","reason":"Justificada","changes":[]}'
    )
    assert result["goal"] == "Mejora"
    assert result["changes"] == []


def test_parse_json_inside_markdown():
    result = _parse_model_plan(
        'Propuesta:\n```json\n'
        '{"goal":"Mejora","reason":"Prueba","changes":[]}'
        '\n```\n'
    )
    assert result["goal"] == "Mejora"


def test_reject_incomplete_json():
    with pytest.raises(ValueError):
        _parse_model_plan(
            '{"goal":"Mejora","reason":"Prueba","changes":['
        )


def test_reject_wrong_schema():
    with pytest.raises(ValueError):
        _parse_model_plan('{"goal":"Mejora","changes":[]}')


def test_reject_non_text_content():
    with pytest.raises(ValueError):
        _parse_model_plan(
            '{"goal":"X","reason":"Y","changes":['
            '{"path":"omega/x.py","content":123}]}'
        )


def test_reject_duplicate_paths():
    with pytest.raises(ValueError):
        _parse_model_plan(
            '{"goal":"X","reason":"Y","changes":['
            '{"path":"omega/x.py","content":"a"},'
            '{"path":"omega/x.py","content":"b"}]}'
        )


def test_reject_too_many_files():
    changes = [
        {"path": f"omega/m{i}.py", "content": ""}
        for i in range(16)
    ]
    import json
    with pytest.raises(ValueError):
        _parse_model_plan(json.dumps({
            "goal": "X", "reason": "Y", "changes": changes
        }))


def test_reject_oversized_file():
    import json
    with pytest.raises(ValueError):
        _parse_model_plan(json.dumps({
            "goal": "X",
            "reason": "Y",
            "changes": [{
                "path": "omega/x.py",
                "content": "x" * 100_001
            }]
        }))


@pytest.mark.parametrize(
    "error_type,message",
    [
        (ValueError, "No se encontró un objeto JSON completo"),
        (TypeError, "El router no devolvió texto"),
    ],
)
def test_cycle_rejects_invalid_model_plan_without_build(
    monkeypatch, tmp_path, error_type, message
):
    import sys
    import types
    import omega.padge as padge

    state = tmp_path / "padge-state"
    state.mkdir()
    monkeypatch.setattr(padge, "STATE", state)
    monkeypatch.setattr(padge, "padge_p2p_network_cycle", lambda: None)
    monkeypatch.setattr(
        padge,
        "inspect",
        lambda: {"branch": "test", "commit": "test", "files": []},
    )

    architecture = types.ModuleType("omega.architecture")
    architecture.run_inspection = lambda: {"status": "OK"}
    network = types.ModuleType("omega.network_intelligence")
    network.run_cycle = lambda: {"status": "OK"}
    monkeypatch.setitem(sys.modules, "omega.architecture", architecture)
    monkeypatch.setitem(sys.modules, "omega.network_intelligence", network)

    events = []
    monkeypatch.setattr(
        padge, "log", lambda event, **kwargs: events.append((event, kwargs))
    )

    def reject(_snapshot):
        raise error_type(message)

    def forbidden_build(_plan):
        raise AssertionError("build() no debe ejecutarse con un plan rechazado")

    monkeypatch.setattr(padge, "ask_iao", reject)
    monkeypatch.setattr(padge, "build", forbidden_build)

    result = padge.cycle()

    assert result["status"] == "MODEL_PLAN_REJECTED"
    assert result["reason"] == message
    assert result["action"] == "SKIP_BUILD_AND_RETRY_NEXT_CYCLE"

    saved = __import__("json").loads(
        (state / "last-plan.json").read_text(encoding="utf-8")
    )
    assert saved["status"] == "MODEL_PLAN_REJECTED"
    assert any(event == "model_plan_rejected" for event, _ in events)
