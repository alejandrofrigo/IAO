"""Run evolution candidates in a disposable, offline Docker test boundary.

This runner never promotes or deploys a candidate. It requires a prebuilt image
from Dockerfile.candidate-sandbox and a Docker daemon with isolation support.
"""
from __future__ import annotations

import argparse
import io
import json
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from omega import evolution

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_IMAGE = "iao-candidate-sandbox:local"
RUN_TIMEOUT_SECONDS = 600
SUMMARY_PATTERN = re.compile(
    r"(?P<count>\d+)\s+(?P<kind>passed|failed|errors?|skipped|xfailed|xpassed)"
)


def _extract_git_archive(ref: str, destination: Path) -> None:
    archive = subprocess.run(
        ["git", "-C", str(ROOT), "archive", "--format=tar", ref],
        check=True,
        capture_output=True,
        timeout=60,
    ).stdout
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
        for member in bundle.getmembers():
            rel = PurePosixPath(member.name)
            if rel.is_absolute() or ".." in rel.parts or member.issym() or member.islnk():
                raise ValueError("UNSAFE_BASE_ARCHIVE_MEMBER")
            target = destination.joinpath(*rel.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise ValueError("UNSUPPORTED_BASE_ARCHIVE_MEMBER")
            target.parent.mkdir(parents=True, exist_ok=True)
            source = bundle.extractfile(member)
            if source is None:
                raise ValueError("BASE_ARCHIVE_MEMBER_UNREADABLE")
            with source, target.open("xb") as output:
                shutil.copyfileobj(source, output)


def _overlay_candidate(proposal_id: str, destination: Path) -> dict[str, Any]:
    metadata = evolution.evaluate(proposal_id)
    if metadata.get("status") != "STATIC_CHECKS_PASSED":
        raise ValueError("CANDIDATE_STATIC_VALIDATION_REQUIRED")
    candidate_root = evolution.CANDIDATES / proposal_id
    if candidate_root.is_symlink():
        raise ValueError("CANDIDATE_ROOT_SYMLINK_REFUSED")
    copied = []
    for name in metadata["files"]:
        rel = evolution._safe_path(name)
        source = candidate_root / rel
        cursor = candidate_root
        for part in rel.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise ValueError("CANDIDATE_SYMLINK_REFUSED")
        if not source.is_file():
            raise ValueError("CANDIDATE_FILE_MISSING")
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        with source.open("rb") as src, target.open("xb") as dst:
            shutil.copyfileobj(src, dst)
        copied.append(name)
    return {"proposal_id": proposal_id, "files": copied}


def _parse_summary(output: str) -> dict[str, int] | None:
    totals = {
        "passed": 0,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
        "xfailed": 0,
        "xpassed": 0,
    }
    matches = list(SUMMARY_PATTERN.finditer(output))
    if not matches:
        return None
    for match in matches:
        kind = match.group("kind")
        normalized = "errors" if kind in {"error", "errors"} else kind
        totals[normalized] += int(match.group("count"))
    return totals


def _docker_suite(workspace: Path, image: str) -> dict[str, Any]:
    if "," in str(workspace):
        raise ValueError("SANDBOX_PATH_CONTAINS_COMMA")
    command = [
        "docker", "run", "--rm",
        "--network=none",
        "--read-only",
        "--ipc=none",
        "--memory=1g",
        "--cpus=2",
        "--pids-limit=128",
        "--ulimit=nofile=64:64",
        "--ulimit=core=0:0",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--user=65534:65534",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=256m",
        "--mount", f"type=bind,src={workspace},dst=/workspace,readonly",
        "--workdir=/workspace",
        "--env=PYTHONPATH=/workspace",
        "--env=IAO_STATE_DIR=/tmp/iao-state",
        "--env=HOME=/tmp",
        "--env=TMPDIR=/tmp",
        image,
        "python", "-m", "pytest", "-q", "-p", "no:cacheprovider",
        "/workspace/tests",
    ]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True,
            timeout=RUN_TIMEOUT_SECONDS, check=False,
        )
        output = (result.stdout or "") + "\n" + (result.stderr or "")
        summary = _parse_summary(output)
        return {
            "returncode": result.returncode,
            "summary": summary,
            "output_tail": output[-6000:],
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "returncode": None,
            "summary": None,
            "output_tail": str(exc)[:1000],
            "timed_out": True,
        }
    except OSError as exc:
        return {
            "returncode": None,
            "summary": None,
            "output_tail": type(exc).__name__,
            "timed_out": False,
        }


def evaluate_in_sandbox(
    proposal_id: str,
    *,
    base_ref: str = "HEAD",
    image: str = DEFAULT_IMAGE,
) -> dict[str, Any]:
    """Compare baseline and candidate test suites in separate offline containers."""
    static = evolution.evaluate(proposal_id)
    if static.get("status") != "STATIC_CHECKS_PASSED":
        return {
            "status": "BLOCKED_STATIC_VALIDATION",
            "promotion_eligible": False,
            "candidate_code_executed": False,
        }
    try:
        subprocess.run(
            ["docker", "image", "inspect", image],
            check=True, capture_output=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "status": "BLOCKED_SANDBOX_UNAVAILABLE",
            "reason": type(exc).__name__,
            "promotion_eligible": False,
            "candidate_code_executed": False,
        }

    with tempfile.TemporaryDirectory(prefix="iao-candidate-sandbox-") as temporary:
        root = Path(temporary)
        baseline = root / "baseline"
        candidate = root / "candidate"
        baseline.mkdir()
        candidate.mkdir()
        try:
            _extract_git_archive(base_ref, baseline)
            shutil.copytree(baseline, candidate, dirs_exist_ok=True)
            overlay = _overlay_candidate(proposal_id, candidate)
        except (OSError, ValueError, subprocess.SubprocessError, tarfile.TarError) as exc:
            return {
                "status": "BLOCKED_WORKSPACE_PREPARATION",
                "reason": type(exc).__name__,
                "promotion_eligible": False,
                "candidate_code_executed": False,
            }

        baseline_result = _docker_suite(baseline, image)
        candidate_result = _docker_suite(candidate, image)
        base_summary = baseline_result["summary"]
        candidate_summary = candidate_result["summary"]
        baseline_ok = (
            baseline_result["returncode"] == 0
            and base_summary is not None
            and base_summary["failed"] == 0
            and base_summary["errors"] == 0
        )
        candidate_ok = (
            candidate_result["returncode"] == 0
            and candidate_summary is not None
            and candidate_summary["failed"] == 0
            and candidate_summary["errors"] == 0
        )
        comparable = bool(base_summary and candidate_summary)
        no_regression = bool(
            comparable
            and candidate_summary["passed"] >= base_summary["passed"]
            and candidate_summary["skipped"] <= base_summary["skipped"]
            and candidate_summary["xpassed"] <= base_summary["xpassed"]
        )
        passed = baseline_ok and candidate_ok and no_regression
        return {
            "status": "FUNCTIONAL_TESTS_PASSED" if passed else "FUNCTIONAL_TESTS_FAILED",
            "promotion_eligible": False,
            "candidate_code_executed": True,
            "sandbox": {
                "docker_image": image,
                "network": "none",
                "root_filesystem": "read_only",
                "workspace": "read_only_bind_mount",
                "user": "65534:65534",
                "memory_limit": "1g",
                "cpu_limit": 2,
                "pids_limit": 128,
                "capabilities": "dropped_all",
                "no_new_privileges": True,
                "tmpfs": "/tmp (256 MiB, noexec,nosuid,nodev)",
                "baseline_ref": base_ref,
            },
            "overlay": overlay,
            "baseline": baseline_result,
            "candidate": candidate_result,
            "no_regression": no_regression,
            "notice": (
                "Las pruebas funcionales se ejecutaron en contenedores Docker "
                "separados sin red. Esto no constituye una auditoría de seguridad "
                "del kernel/Docker ni autoriza promoción o despliegue."
            ),
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("proposal_id")
    parser.add_argument("--base-ref", default="HEAD")
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    args = parser.parse_args()
    result = evaluate_in_sandbox(
        args.proposal_id, base_ref=args.base_ref, image=args.image
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "FUNCTIONAL_TESTS_PASSED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
