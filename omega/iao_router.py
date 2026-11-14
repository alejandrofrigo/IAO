"""IAO Router: deterministic loading of environment variables from .env files.

This module provides the public function ``load_env()`` that inspects, in order of
priority, the repository‑root ``.env`` file and the user ``~/.iao-runtime.env``
file. The loader follows the rules documented in the module docstring:

* Blank lines and lines beginning with ``#`` are ignored.
* Each line must match ``KEY=VALUE`` where ``KEY`` satisfies ``^[A-Z_][A-Z0-9_]*$``;
  malformed lines are safely skipped.
* ``VALUE`` may be unquoted or quoted with single or double quotes. When quoted,
  common escape sequences (``\\n``, ``\\t``, ``\\\\``, ``\\\"`` and ``\\'``) are
  interpreted. Unquoted values are taken verbatim.
* Existing variables in ``os.environ`` are never overwritten; only new variables are
  added. The function returns a dictionary of the variables that were added during
  the call, enabling deterministic tests.

The implementation relies solely on the Python standard library and does not
introduce external dependencies.
"""

from __future__ import annotations

import ast
import os
import pathlib
import re
from typing import Dict

__all__ = ["load_env"]

# Regular expression for a valid environment variable name (uppercase letters, digits, underscores).
_KEY_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")


def _parse_value(raw: str) -> str | None:
    """Parse a raw value from a .env line.

    - If the value is quoted with single or double quotes, ``ast.literal_eval`` is used
      to interpret escape sequences.
    - If the value is not quoted, it is returned unchanged.
    - On any parsing error ``None`` is returned, causing the line to be ignored.
    """
    if not raw:
        return ""
    if (raw.startswith('"') and raw.endswith('"')) or (raw.startswith("'") and raw.endswith("'")):
        try:
            return ast.literal_eval(raw)
        except Exception:
            return None
    return raw


def load_env() -> Dict[str, str]:
    """Load environment variables from ``.env`` (repo root) and ``~/.iao-runtime.env``.

    The files are processed in the order described above; variables from the first
    file that are not already present in ``os.environ`` are added, then the same
    logic is applied to the second file. The function returns a mapping of the keys
    that were newly inserted together with their values.
    """
    added: Dict[str, str] = {}

    # Candidate files: repository root .env and user‑specific runtime env.
    repo_root_env = pathlib.Path('.env')
    user_env = pathlib.Path.home() / '.iao-runtime.env'
    candidates = [repo_root_env, user_env]

    for candidate in candidates:
        if not candidate.is_file():
            continue
        try:
            with candidate.open('r', encoding='utf-8') as f:
                for line in f:
                    # Strip newline and surrounding whitespace.
                    stripped = line.strip()
                    # Skip blanks and comments.
                    if not stripped or stripped.startswith('#'):
                        continue
                    # Split on the first '='.
                    if '=' not in stripped:
                        continue
                    key, raw_value = stripped.split('=', 1)
                    key = key.strip()
                    raw_value = raw_value.strip()
                    # Validate key name.
                    if not _KEY_RE.fullmatch(key):
                        continue
                    # Parse the value respecting quoting.
                    parsed = _parse_value(raw_value)
                    if parsed is None:
                        continue
                    # Do not overwrite existing environment variables.
                    if key in os.environ:
                        continue
                    os.environ[key] = parsed
                    added[key] = parsed
        except OSError:
            # If a file cannot be read, ignore it – environment loading should be tolerant.
            continue

    return added
