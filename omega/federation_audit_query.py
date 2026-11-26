'''omega/federation_audit_query.py

Public utility to fetch audit‑log entries for a specific federation proposal.
The audit log is stored as a line‑delimited JSON file (``.jsonl``) where each
line represents an event dictionary that includes at least a ``"proposal_id"``
field.  This module provides a safe, deterministic function for reading the
log, filtering by proposal ID, and optionally limiting the number of returned
entries.

The implementation does not perform any network I/O and respects the
environment variable ``IAO_AUDIT_LOG_PATH`` for custom log locations.  If the
variable is unset, the log is assumed to live alongside this module under the
name ``audit_log.jsonl``.
''' 

import json
import os
from typing import List, Dict, Optional

def get_audit_log(proposal_id: str, *, limit: Optional[int] = None) -> List[Dict]:
    """Return audit‑log entries for *proposal_id*.

    The function reads the audit‑log file safely, skips malformed lines, and
    returns a list of dictionaries ordered chronologically (oldest first).  If
    *limit* is supplied, the most recent *limit* entries are returned in reverse
    chronological order (newest first).

    Args:
        proposal_id: Identifier of the federation proposal to filter on.
        limit: Optional maximum number of entries to return.  ``None`` returns
            all matching entries.

    Returns:
        A list of audit‑log entry dictionaries.  Returns an empty list if the
        log file does not exist or no entries match the given ``proposal_id``.
    """
    # Determine the path to the audit‑log file.
    log_path = os.getenv("IAO_AUDIT_LOG_PATH")
    if not log_path:
        # Default to a file named ``audit_log.jsonl`` located in the same
        # directory as this module.
        base_dir = os.path.dirname(__file__)
        log_path = os.path.join(base_dir, "audit_log.jsonl")

    entries: List[Dict] = []
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    # Skip malformed lines but continue processing the rest.
                    continue
                if entry.get("proposal_id") == proposal_id:
                    entries.append(entry)
    except FileNotFoundError:
        # No audit log present – return empty list.
        return []
    except OSError as exc:
        # Unexpected I/O error – re‑raise as a runtime error to surface the
        # problem while keeping the function signature simple.
        raise RuntimeError(f"Failed to read audit log at {log_path}: {exc}") from exc

    if limit is not None:
        # Return the most recent *limit* entries in newest‑first order.
        return entries[-limit:][::-1]
    return entries
