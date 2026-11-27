"""Keep the legacy requirements manifest aligned with pinned project metadata."""
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_REQUIREMENT = re.compile(
    r"([A-Za-z0-9_.-]+)(?:\\[([A-Za-z0-9_,.-]+)\\])?==([A-Za-z0-9_.+-]+)"
)


def _normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse(requirements: list[str]) -> dict[tuple[str, tuple[str, ...]], str]:
    parsed = {}
    for line in requirements:
        match = _REQUIREMENT.fullmatch(line.strip())
        assert match is not None, f"unlocked or invalid requirement: {line}"
        name, extras, version = match.groups()
        key = (_normalized(name), tuple(sorted((extras or "").split(","))) if extras else ())
        assert key not in parsed, f"duplicate requirement: {name}"
        parsed[key] = version
    return parsed


def test_requirements_manifest_matches_exact_project_runtime_dependencies():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = project["project"]["dependencies"]
    manifest = [
        line for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert project["project"]["requires-python"] == ">=3.12,<3.14"
    assert _parse(manifest) == _parse(dependencies)


def test_all_direct_project_dependencies_are_exactly_pinned():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    for dependency in project["project"]["dependencies"]:
        assert "==" in dependency and not any(op in dependency for op in (">", "<", "~", "!="))
