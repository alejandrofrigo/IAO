"""omega.env_loader
=====================
Utility module to load ``.env`` files safely.

- Does **not** overwrite already‑set environment variables unless ``overwrite`` is ``True``.
- Handles comments (including escaped ``#``), empty lines and whitespace.
- Supports values quoted with single or double quotes; escapes are interpreted
  (e.g. ``\"`` → `"`).
- Only loads keys that match the conventional environment variable pattern
  ``^[A-Z_][A-Z0-9_]*$`` to avoid accidental injection.
- Returns a dictionary of the variables that were actually added/updated.

The implementation is deliberately dependency‑free (standard library only) and
fits the existing IAO code‑style.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, Iterable

# Pattern for valid environment variable names (uppercase letters, digits and
# underscores, starting with a letter or underscore).
_ENV_KEY_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")


def _strip_comments(line: str) -> str:
    """Remove a trailing comment starting with an *unescaped* ``#``.

    The function walks the string character‑by‑character so that escaped hash
    symbols (``\\#``) are preserved as part of the value.
    """
    escaped = False
    for idx, ch in enumerate(line):
        if ch == "\\":
            escaped = not escaped
            continue
        if ch == "#" and not escaped:
            return line[:idx].rstrip()
        escaped = False
    return line.rstrip()


def _unquote(value: str) -> str:
    """Remove surrounding single or double quotes and unescape common sequences.

    This mirrors the behaviour of popular ``dotenv`` libraries while staying
    lightweight. If the value is not quoted, it is returned unchanged.
    """
    if len(value) >= 2 and ((value[0] == value[-1] == '"') or (value[0] == value[-1] == "'")):
        # Strip the surrounding quotes.
        value = value[1:-1]
        # Unescape escaped quotes and backslashes.
        value = value.replace('\\"', '"').replace("\\'", "'").replace('\\\\', '\\')
    return value


def load_env_files(
    env_files: Iterable[Path] | None = None,
    *,
    overwrite: bool = False,
) -> Dict[str, str]:
    """Load environment variables from a sequence of ``.env`` files.

    Parameters
    ----------
    env_files:
        Iterable of :class:`pathlib.Path` objects. If ``None`` (the default), the
        function looks for ``.env`` in the project root (two levels up from this
        file) and ``~/.iao-runtime.env`` – mirroring the behaviour of the original
        ``iao_router`` implementation.
    overwrite:
        When ``True`` existing ``os.environ`` entries are replaced; otherwise they
        are left untouched.

    Returns
    -------
    dict
        Mapping of variable names that were set/updated during the call.
    """
    if env_files is None:
        # Default locations: project‑root/.env and the user’s home directory.
        root = Path(__file__).resolve().parents[2]
        env_files = (root / ".env", Path.home() / ".iao-runtime.env")

    loaded: Dict[str, str] = {}
    for env_path in env_files:
        if not env_path.is_file():
            continue
        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                # Blank line or full‑line comment.
                continue
            line = _strip_comments(line)
            if "=" not in line:
                # Malformed line – ignore but keep processing the rest.
                continue
            key, raw_value = line.split("=", 1)
            key = key.strip()
            if not _ENV_KEY_RE.fullmatch(key):
                # Skip invalid keys.
                continue
            value = _unquote(raw_value.strip())
            if not overwrite and key in os.environ:
                # Respect the existing environment.
                continue
            os.environ[key] = value
            loaded[key] = value
    return loaded
