"""IAO deterministic autonomous promotion policy.

The language model proposes changes but never grants permissions.
This module independently evaluates candidate paths and test results.
"""

from pathlib import PurePosixPath


ALLOWED_ROOTS = ("omega/", "tools/", "docs/")

PROTECTED_PATHS = {
    "omega/auth.py",
    "omega/policy_gate.py",
    "omega/llm_router.py",
    "tools/iao_autonomy.py",
    "omega/iao_router.py",
    "omega/server.py",
    "omega/service.py",
    "omega/padge.py",
    "omega/padge_autonomy_policy.py",
}

PROTECTED_PREFIXES = (
    ".git/",
    ".env",
    "secrets/",
    "credentials/",
)


def _paths(changes):
    if isinstance(changes, dict):
        return list(changes.keys())
    if isinstance(changes, (list, tuple, set)):
        return list(changes)
    return []


def evaluate_candidate(changes, candidate):
    """Return a deterministic approval decision."""

    if not isinstance(candidate, dict):
        return {
            "approved": False,
            "reason": "INVALID_CANDIDATE_METADATA",
        }

    paths = _paths(changes)

    if not paths:
        return {
            "approved": False,
            "reason": "EMPTY_OR_INVALID_CHANGESET",
        }

    for raw in paths:
        if not isinstance(raw, str) or not raw:
            return {
                "approved": False,
                "reason": "INVALID_CHANGE_PATH",
            }

        path = PurePosixPath(raw)

        if path.is_absolute() or ".." in path.parts:
            return {
                "approved": False,
                "reason": "PATH_TRAVERSAL_OR_ABSOLUTE_PATH",
            }

        normalized = path.as_posix()

        if normalized in PROTECTED_PATHS:
            return {
                "approved": False,
                "reason": "PROTECTED_COMPONENT",
                "path": normalized,
            }

        if normalized.startswith(PROTECTED_PREFIXES):
            return {
                "approved": False,
                "reason": "PROTECTED_DATA",
                "path": normalized,
            }

        if not normalized.startswith(ALLOWED_ROOTS):
            return {
                "approved": False,
                "reason": "PATH_OUTSIDE_AUTONOMOUS_SCOPE",
                "path": normalized,
            }

    failed = candidate.get("failed")
    errors = candidate.get("errors")
    passed = candidate.get("passed")

    for value in (failed, errors, passed):
        if isinstance(value, bool) or not isinstance(value, int):
            return {
                "approved": False,
                "reason": "INVALID_TEST_RESULTS",
            }

    if failed < 0 or errors < 0 or passed < 0:
        return {
            "approved": False,
            "reason": "NEGATIVE_TEST_RESULTS",
        }

    if failed != 0 or errors != 0:
        return {
            "approved": False,
            "reason": "TESTS_NOT_CLEAN",
            "failed": failed,
            "errors": errors,
        }

    if passed < 1:
        return {
            "approved": False,
            "reason": "NO_PASSED_TESTS",
        }

    return {
        "approved": True,
        "reason": "AUTONOMOUS_POLICY_APPROVED",
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "files": paths,
    }
