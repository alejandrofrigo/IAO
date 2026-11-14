# -*- coding: utf-8 -*-
"""omega.federation_network_overview
===================================

Utility module that produces a deterministic, high‑level summary of the current
federation network.  It aggregates information from the existing federation
sub‑system – registration data, health checks, capability validation and the
last‑seen timestamps of participants – into a single, JSON‑serialisable Python
structure.

The implementation follows the same *lazy‑import* philosophy used throughout
the ``omega`` package: heavy optional dependencies are imported only when the
corresponding attribute is accessed.  This guarantees that importing the module
or calling :func:`generate_overview` never raises an ``ImportError`` in
environments where some federation helpers are unavailable (for example, during
offline unit‑test execution).

The public API consists of a single function:

```
overview = generate_overview()
```

``overview`` is a ``dict`` with the following shape:

```json
{
  "participants": [
    {
      "id": "<participant‑id>",
      "registered": true,
      "last_seen": "2026-11-10T12:34:56Z",
      "health": "healthy" | "unreachable" | "degraded",
      "capabilities_valid": true | false,
      "errors": []
    },
    ...
  ],
  "total": 42,
  "generated_at": "2026-11-10T12:34:56Z"
}
```

All timestamps are ISO‑8601 strings in UTC.  Errors that occur while gathering a
participant's data are captured in the ``errors`` list so that callers can see
partial results without the whole operation failing.
"""

from __future__ import annotations

import datetime as _dt
import json as _json
import traceback as _tb
from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# Lazy import helpers (mirroring the pattern used in ``omega.__init__``)
# ---------------------------------------------------------------------------

def _lazy_import(module_name: str, attr_name: str | None = None):
    """Import *module_name* on demand and optionally return *attr_name*.

    This helper is used to keep the import side‑effects of optional federation
    utilities (e.g., network checks) out of the module import path.  If the
    import fails we return ``None`` – the calling code will handle the fallback
    gracefully.
    """
    try:
        module = __import__(module_name, fromlist=["*"])
        if attr_name:
            return getattr(module, attr_name)
        return module
    except Exception:  # pragma: no cover – defensive; should never crash
        return None

# Optional sub‑modules that provide the underlying data.  They are imported lazily
# when needed inside ``generate_overview``.

_get_registered_participants = lambda: _lazy_import("omega.store", "get_registered_participants")
_get_participant_last_seen = lambda: _lazy_import("omega.federation_candidate", "get_last_seen_timestamp")
_check_participant_health = lambda: _lazy_import("omega.federation_health", "check_participant_health")
_validate_capabilities = lambda: _lazy_import("omega.federation_capability_validator", "validate_capabilities")

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _iso_timestamp(dt: _dt.datetime) -> str:
    """Return an ISO‑8601 UTC timestamp string.

    ``dt`` may be naive (treated as UTC) or timezone‑aware.  The function always
    returns the representation in the "YYYY‑MM‑DDThh:mm:ssZ" format.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_overview() -> Dict[str, Any]:
    """Generate a deterministic overview of the federation network.

    The function follows a *best‑effort* approach: missing optional components are
    treated as empty, and per‑participant errors are collected rather than raising
    an exception.  This behaviour makes the utility safe to use in automated test
    suites where the environment may be deliberately constrained.
    """
    now = _dt.datetime.utcnow()
    overview: Dict[str, Any] = {
        "participants": [],
        "total": 0,
        "generated_at": _iso_timestamp(now),
    }

    # -------------------------------------------------------------------
    # 1. Retrieve the list of registered participant identifiers.
    # -------------------------------------------------------------------
    get_registered = _get_registered_participants()
    if not get_registered:
        # If the store module is unavailable we simply report an empty list.
        return overview

    try:
        participant_ids: List[str] = list(get_registered())  # type: ignore[arg-type]
    except Exception:  # pragma: no cover – defensive
        participant_ids = []

    overview["total"] = len(participant_ids)

    # -------------------------------------------------------------------
    # 2. Iterate over participants and collect details.
    # -------------------------------------------------------------------
    for pid in participant_ids:
        participant_entry: Dict[str, Any] = {
            "id": pid,
            "registered": True,
            "last_seen": None,
            "health": "unknown",
            "capabilities_valid": False,
            "errors": [],
        }
        # ----- last seen -------------------------------------------------
        get_last_seen = _get_participant_last_seen()
        if get_last_seen:
            try:
                ts = get_last_seen(pid)  # Expected to return a datetime
                if isinstance(ts, _dt.datetime):
                    participant_entry["last_seen"] = _iso_timestamp(ts)
                else:
                    participant_entry["last_seen"] = str(ts)
            except Exception as exc:  # pragma: no cover – defensive
                participant_entry["errors"].append(
                    f"last_seen_error: {exc!s}"
                )
                participant_entry["last_seen"] = None
        # ----- health ----------------------------------------------------
        health_check = _check_participant_health()
        if health_check:
            try:
                health_status = health_check(pid)  # Expected to return a string
                participant_entry["health"] = str(health_status)
            except Exception as exc:  # pragma: no cover
                participant_entry["errors"].append(
                    f"health_check_error: {exc!s}"
                )
        # ----- capability validation --------------------------------------
        validator = _validate_capabilities()
        if validator:
            try:
                is_valid = validator(pid)  # Expected to return bool
                participant_entry["capabilities_valid"] = bool(is_valid)
            except Exception as exc:  # pragma: no cover
                participant_entry["errors"].append(
                    f"capability_validation_error: {exc!s}"
                )
        overview["participants"].append(participant_entry)

    return overview


# ---------------------------------------------------------------------------
# Convenience: pretty‑print JSON for CLI debugging
# ---------------------------------------------------------------------------

def print_overview(pretty: bool = True) -> None:
    """Print the current federation overview to *stdout*.

    ``pretty`` controls whether the JSON is indented.  This helper is useful for
    manual inspection from the command line (e.g., ``python -m omega.federation_network_overview``).
    """
    data = generate_overview()
    if pretty:
        print(_json.dumps(data, indent=2, sort_keys=True))
    else:
        print(_json.dumps(data))


if __name__ == "__main__":  # pragma: no cover
    print_overview()
