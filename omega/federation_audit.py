"""Federation audit logging utilities.

This module provides a simple, thread‑safe audit logger that records
federation lifecycle events as newline‑delimited JSON objects. The log
location can be configured via the ``IAO_FEDERATION_AUDIT_LOG``
environment variable; otherwise it defaults to ``./audit/federation_audit.log``.
The implementation avoids external dependencies and never raises
exceptions to the caller, ensuring that audit failures do not disrupt
the federation process.
"""

import os
import json
import threading
import sys
from datetime import datetime
from typing import Any, Dict, Optional

# Internal lock to guarantee atomic writes from multiple threads.
_LOG_LOCK = threading.Lock()


class FederationAuditLog:
    """Thread‑safe audit logger for federation events.

    Each call to :meth:`record` writes a single JSON line containing a UTC
    timestamp, the event name, the candidate identifier and an optional
    ``details`` mapping.  The logger creates the target directory on first
    use and silently reports I/O errors to *stderr* to avoid breaking the
    caller's execution flow.
    """

    def __init__(self, log_path: Optional[str] = None) -> None:
        """Create a logger instance.

        Parameters
        ----------
        log_path: str | None
            Destination file for the audit trail. If ``None`` the path is
            taken from the ``IAO_FEDERATION_AUDIT_LOG`` environment variable
            or defaults to ``./audit/federation_audit.log`` relative to the
            current working directory.
        """
        self.log_path = log_path or os.getenv(
            "IAO_FEDERATION_AUDIT_LOG",
            os.path.join(os.getcwd(), "audit", "federation_audit.log"),
        )
        # Ensure the directory exists; ignore errors because they will be
        # handled later when attempting to write.
        try:
            os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        except OSError as exc:
            print(f"[FederationAuditLog] failed to create log directory: {exc}", file=sys.stderr)

    def record(self, event: str, candidate_id: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Append an audit entry.

        Parameters
        ----------
        event: str
            Name of the event (e.g., ``discovered``, ``validated``, ``proposal_signed``).
        candidate_id: str
            Unique identifier of the federation candidate.
        details: dict | None
            Additional structured information about the event.
        """
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event": event,
            "candidate_id": candidate_id,
            "details": details or {},
        }
        line = json.dumps(entry, separators=(",", ":"))
        try:
            with _LOG_LOCK, open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError as exc:
            # Never propagate I/O errors; they are logged to stderr.
            print(f"[FederationAuditLog] failed to write audit entry: {exc}", file=sys.stderr)
