
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
