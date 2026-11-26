"""Durable, idempotent job records with checkpoints (file-backed; survives restarts)."""
import fcntl
import hashlib
import json
import os
import tempfile
import threading
from pathlib import Path
from typing import Any


def idempotency_key(project: str, spec_version: str, document_sha256: str) -> str:
    return hashlib.sha256(f"{project}|{spec_version}|{document_sha256}".encode()).hexdigest()


class JobStore:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._create_lock = threading.Lock()

    def _path(self, key: str) -> Path:
        return self.root / f"{key}.json"

    def create_or_resume(self, key: str, initial: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        """Atomically create or resume a job across threads and processes."""
        p = self._path(key)
        lock_path = self.root / ".jobs.lock"

        with self._create_lock:
            with lock_path.open("a") as lock_file:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                try:
                    if p.exists():
                        return json.loads(p.read_text()), False

                    job = {"key": key, "state": "RECEIVED", "checkpoint": {}, **initial}
                    fd, tmp = tempfile.mkstemp(
                        dir=self.root, prefix=f".{key}.", suffix=".tmp"
                    )
                    try:
                        with os.fdopen(fd, "w") as f:
                            json.dump(job, f, sort_keys=True)
                            f.flush()
                            os.fsync(f.fileno())

                        os.replace(tmp, p)
                        return job, True
                    finally:
                        try:
                            os.unlink(tmp)
                        except FileNotFoundError:
                            pass
                finally:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

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
