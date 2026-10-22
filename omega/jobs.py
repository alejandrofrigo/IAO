"""Durable, idempotent job records with checkpoints (file-backed; survives restarts)."""
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any


def idempotency_key(project: str, spec_version: str, document_sha256: str) -> str:
    return hashlib.sha256(f"{project}|{spec_version}|{document_sha256}".encode()).hexdigest()


class JobStore:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        return self.root / f"{key}.json"

    def create_or_resume(self, key: str, initial: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        """Return (job, created). Same key never creates a duplicate."""
        p = self._path(key)
        try:
            fd = os.open(p, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            return json.loads(p.read_text()), False
        job = {"key": key, "state": "RECEIVED", "checkpoint": {}, **initial}
        with os.fdopen(fd, "w") as f:
            json.dump(job, f, sort_keys=True)
        return job, True

    def checkpoint(self, key: str, state: str, data: dict[str, Any]) -> None:
        p = self._path(key)
        job = json.loads(p.read_text())
        job["state"] = state
        job["checkpoint"].update(data)
        fd, tmp = tempfile.mkstemp(dir=self.root)
        with os.fdopen(fd, "w") as f:
            json.dump(job, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)  # atomic

    def load(self, key: str) -> dict[str, Any]:
        return json.loads(self._path(key).read_text())  # type: ignore[no-any-return]
