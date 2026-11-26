'''\
Thread‑safe in‑memory audit log for federation operations.
\
This module provides a minimal, dependency‑free audit facility that records
security‑relevant actions performed by the federation pipeline. Each entry
contains a timestamp, an action identifier and an optional free‑form payload.
The implementation is deliberately simple to keep the runtime footprint low
and to avoid persistent side effects, which aligns with the policy of not
introducing external storage or network calls.
\
Usage example::
\n    from omega.federation_audit_log import audit_log
\n    audit_log.add('candidate_discovered', {'candidate_id': cid})
\n    recent = audit_log.query(since=time.time() - 3600)
\nThe module also exposes a singleton instance ``audit_log`` for convenient
import throughout the codebase.
'''\

import threading
import time
from typing import List, Dict, Any, Optional


class FederationAuditLog:
    """Thread‑safe in‑memory audit log.

    The log stores entries as dictionaries with the following keys:
        * ``timestamp`` – float epoch seconds when the entry was added.
        * ``action``    – a short string naming the operation (e.g., "candidate_discovered").
        * ``details``   – optional mapping with additional context.
    """

    def __init__(self) -> None:
        self._entries: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def add(self, action: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Record a new audit entry.

        Args:
            action: Identifier of the operation being logged.
            details: Optional additional information about the operation.
        """
        entry = {
            "timestamp": time.time(),
            "action": action,
            "details": details or {},
        }
        with self._lock:
            self._entries.append(entry)

    def query(
        self,
        *,
        action: Optional[str] = None,
        since: Optional[float] = None,
        until: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve audit entries optionally filtered by criteria.

        Parameters:
            action: If provided, only entries with this exact action are returned.
            since:  Minimum timestamp (inclusive) for entries.
            until:  Maximum timestamp (inclusive) for entries.
        """
        with self._lock:
            results = list(self._entries)
        if action is not None:
            results = [e for e in results if e["action"] == action]
        if since is not None:
            results = [e for e in results if e["timestamp"] >= since]
        if until is not None:
            results = [e for e in results if e["timestamp"] <= until]
        return results

    def clear(self) -> None:
        """Remove all stored audit entries."""
        with self._lock:
            self._entries.clear()


# A module‑level singleton for easy import throughout the codebase.
audit_log = FederationAuditLog()

__all__ = ["FederationAuditLog", "audit_log"]