"""Keep the legacy requirements manifest aligned with pinned project metadata."""
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_NAME = re.compile(r"[A-Za-z0-9_.-]+")
_EXTRAS = re.compile(r"[A-Za-z0-9_.-]+(?:,[A-Za-z0-9_.-]+)*")
_VERSION = re.compile(r"[A-Za-z0-9_.+-]+")


def _normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse(requirements: list[str]) -> dict[tuple[str, tuple[str, ...]], str]:
    parsed = {}
    for line in requirements:
        parts = line.strip().split("==")
        assert len(parts) == 2, f"unlocked or invalid requirement: {line}"
        package, version = parts
        extras = ""
        if "[" in package:
            assert package.endswith("]") and package.count("[") == 1, line
            package, extras = package[:-1].split("[", 1)
        assert _NAME.fullmatch(package) and _VERSION.fullmatch(version), line
        assert not extras or _EXTRAS.fullmatch(extras), line
        key = (_normalized(package), tuple(sorted(extras.split(","))) if extras else ())
        assert key not in parsed, f"duplicate requirement: {package}"
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
