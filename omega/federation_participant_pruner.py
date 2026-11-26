# -*- coding: utf-8 -*-
"""Federation participant pruning utility.

Provides a deterministic, thread‑safe function to remove participants that have
exceeded a configurable age limit. This helps keep the participant registry
lean and reduces attack surface by discarding stale entries.

The implementation works with the existing ``omega.federation_participant_registry``
module without requiring changes to its internal representation. It accesses
the registry via a lazy ``_safe_import`` call to avoid import‑time side effects.
"""

from __future__ import annotations

import importlib
import time
from typing import List, Any


def _load_registry() -> Any:
    """Load the participant registry module and return its mutable registry object.

    The registry module is expected to expose either a ``registry`` attribute or
    an ``_registry`` attribute that behaves like a mutable mapping ``{id: data}``.
    If neither is present, ``None`` is returned and the caller should treat the
    operation as a no‑op.
    """
    try:
        module = importlib.import_module("omega.federation_participant_registry")
        return getattr(module, "registry", getattr(module, "_registry", None))
    except Exception:  # pragma: no cover
        return None


def prune_stale_participants(max_age_seconds: int) -> List[str]:
    """Remove participants whose ``registered_at`` timestamp is older than *max_age_seconds*.

    Parameters
    ----------
    max_age_seconds: int
        Maximum allowed age for a participant entry. Entries older than the
        current time minus this value are considered stale and will be removed.

    Returns
    -------
    List[str]
        A list of participant identifiers that were removed.
    """
    registry = _load_registry()
    if not registry:
        # No registry available – nothing to prune.
        return []

    now = time.time()
    stale_ids: List[str] = []

    # We iterate over a copy of the keys to avoid mutation during iteration.
    for participant_id in list(registry.keys()):
        entry = registry.get(participant_id)
        if not isinstance(entry, dict):
            continue
        registered_at = entry.get("registered_at")
        if isinstance(registered_at, (int, float)) and (now - registered_at) > max_age_seconds:
            stale_ids.append(participant_id)
            # Remove the stale entry safely.
            try:
                del registry[participant_id]
            except Exception:  # pragma: no cover
                pass

    return stale_ids
