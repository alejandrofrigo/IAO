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
import uuid
from pathlib import Path, PurePosixPath
from typing import Any

from omega import evolution

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_IMAGE = "iao-candidate-sandbox:local"
RUN_TIMEOUT_SECONDS = 600
SUMMARY_LINE_PATTERN = re.compile(
    r"^\\s*=+\\s*(?P<body>.*?)\\s+in\\s+[0-9]+(?:\\.[0-9]+)?s\\s*=+\\s*$"
)
SUMMARY_ITEM_PATTERN = re.compile(
    r"(?P<count>[0-9]+)\\s+(?P<kind>passed|failed|errors?|skipped|xfailed|xpassed)"
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
    """Parse exactly one complete, final-format pytest summary line."""
    totals = {
        "passed": 0,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
        "xfailed": 0,
        "xpassed": 0,
    }
    summaries = [
        match.group("body")
        for line in output.splitlines()
        if (match := SUMMARY_LINE_PATTERN.fullmatch(line))
    ]
    if len(summaries) != 1:
        return None
    body = summaries[0]
    matches = list(SUMMARY_ITEM_PATTERN.finditer(body))
    if not matches:
        return None
    # Reject any unparsed text, duplicate outcome categories, or malformed counts.
    cursor = 0
    seen = set()
    for match in matches:
        separator = body[cursor:match.start()]
        if separator.strip(" ,"):
            return None
        kind = match.group("kind")
        normalized = "errors" if kind in {"error", "errors"} else kind
        if normalized in seen:
            return None
        seen.add(normalized)
        totals[normalized] = int(match.group("count"))
        cursor = match.end()
    if body[cursor:].strip(" ,"):
        return None
    return totals


def _compare_results(
    baseline_result: dict[str, Any], candidate_result: dict[str, Any]
) -> dict[str, bool]:
    """Require complete successful runs and no regression in every non-pass outcome."""
    baseline = baseline_result.get("summary")
    candidate = candidate_result.get("summary")
    baseline_ok = (
        baseline_result.get("returncode") == 0
        and isinstance(baseline, dict)
        and baseline.get("failed") == 0
        and baseline.get("errors") == 0
    )
    candidate_ok = (
        candidate_result.get("returncode") == 0
        and isinstance(candidate, dict)
        and candidate.get("failed") == 0
        and candidate.get("errors") == 0
    )
    comparable = isinstance(baseline, dict) and isinstance(candidate, dict)
    no_regression = bool(
        comparable
        and candidate["passed"] >= baseline["passed"]
        and candidate["skipped"] <= baseline["skipped"]
        and candidate["xfailed"] <= baseline["xfailed"]
        and candidate["xpassed"] <= baseline["xpassed"]
        and candidate["failed"] == 0
        and candidate["errors"] == 0
    )
    return {
        "baseline_ok": baseline_ok,
        "candidate_ok": candidate_ok,
        "comparable": comparable,
        "no_regression": no_regression,
        "passed": baseline_ok and candidate_ok and no_regression,
    }


def _docker_suite(workspace: Path, image: str) -> dict[str, Any]:
    if "," in str(workspace):
        raise ValueError("SANDBOX_PATH_CONTAINS_COMMA")
    # Docker cannot create a tmpfs mountpoint beneath a read-only bind mount.
    # Create the empty mountpoint in the disposable workspace before binding it.
    (workspace / ".state").mkdir(mode=0o700, parents=True, exist_ok=True)
    container_name = "iao-candidate-" + uuid.uuid4().hex
    command = [
        "docker", "run", "--rm", "--pull=never",
        f"--name={container_name}",
        "--label=iao.candidate.sandbox=true",
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
        "--tmpfs=/workspace/.state:rw,noexec,nosuid,nodev,size=256m",
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
        try:
            cleanup = subprocess.run(
                ["docker", "rm", "-f", container_name],
                capture_output=True, text=True, timeout=30, check=False,
            )
            cleanup_code = cleanup.returncode
        except (OSError, subprocess.SubprocessError):
            cleanup_code = None
        return {
            "returncode": None,
            "summary": None,
            "output_tail": str(exc)[:1000],
            "timed_out": True,
            "container_cleanup_returncode": cleanup_code,
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
        comparison = _compare_results(baseline_result, candidate_result)
        no_regression = comparison["no_regression"]
        passed = comparison["passed"]
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
            "comparison": comparison,
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
