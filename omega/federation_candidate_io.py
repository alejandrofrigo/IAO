'''omega/federation_candidate_io.py
---------------------------------
Utility functions to serialize and deserialize ``FederationCandidate`` objects
into JSON‑compatible dictionaries.

Why this module?
~~~~~~~~~~~~~~~~~
* The federation stack (discovery, validation, tracking, etc.) now fully manages
  candidate lifecycles, but there is no standardized way to persist a candidate
  or to emit its state for logging/auditing.
* Storing raw objects can expose private attributes (e.g., temporary secrets).
* By providing explicit conversion helpers we keep the serialization contract
  clear, avoid accidental leakage of internal fields and make it easy for tests
  to create fixtures from dictionary literals.

Design
~~~~~~
* ``candidate_to_dict`` – returns a ``dict`` that can be passed to ``json.dump``.
  It:
    - skips private attributes (those starting with an underscore);
    - converts ``Enum`` values to their ``value`` (or ``name`` if ``value`` is
      not JSON‑serializable);
    - ensures that any ``bytes`` fields are base64‑encoded to stay JSON‑friendly.
* ``candidate_from_dict`` – reconstructs a ``FederationCandidate`` instance
  from the dictionary produced by ``candidate_to_dict``.  It performs the
  reverse conversion for ``Enum`` and ``bytes`` fields.

Both functions are deliberately lightweight, have no side‑effects and do not
perform any network or file I/O, respecting the PADGE policy of not invoking
external resources.
''' 

import base64
import json
from typing import Any, Dict

from .federation_candidate import FederationCandidate
from .federation_manager import FederationState

__all__ = ["candidate_to_dict", "candidate_from_dict"]


def _enum_to_json(value: Any) -> Any:
    """Convert Enum instances to JSON‑compatible values.

    Preference is given to ``value`` if it is already JSON serializable; otherwise
    the Enum's name is used.
    """
    if hasattr(value, "value"):
        try:
            json.dumps(value.value)
            return value.value
        except TypeError:
            return value.name
    return value


def _bytes_to_base64(value: bytes) -> str:
    """Encode ``bytes`` as a base64 UTF‑8 string for JSON compatibility."""
    return base64.b64encode(value).decode("utf-8")


def candidate_to_dict(candidate: FederationCandidate) -> Dict[str, Any]:
    """Serialize a ``FederationCandidate`` to a JSON‑compatible ``dict``.

    The function intentionally excludes any attribute whose name starts with an
    underscore, treating them as internal/private.  Enums and ``bytes`` are
    transformed to portable representations.
    """
    result: Dict[str, Any] = {}
    for attr, value in vars(candidate).items():
        if attr.startswith("_"):
            continue  # Skip private/internal fields
        if isinstance(value, bytes):
            result[attr] = _bytes_to_base64(value)
        elif isinstance(value, (list, tuple)):
            # Recursively handle containers of Enums/bytes
            result[attr] = [
                _bytes_to_base64(v) if isinstance(v, bytes) else _enum_to_json(v) for v in value
            ]
        else:
            result[attr] = _enum_to_json(value)
    return result


def _json_to_enum(enum_cls, value: Any) -> Any:
    """Convert a JSON value back to an Enum member if possible."""
    if isinstance(value, str):
        # Try name first, then value
        try:
            return enum_cls[value]
        except KeyError:
            for member in enum_cls:
                if member.value == value:
                    return member
    return value


def _base64_to_bytes(value: Any) -> Any:
    """Decode a base64 string back to ``bytes`` if the input is a string.

    If the value is not a string, it is returned unchanged.
    """
    if isinstance(value, str):
        try:
            return base64.b64decode(value.encode("utf-8"))
        except Exception:
            # Not a valid base64 encoding – return original string
            return value
    return value


def candidate_from_dict(data: Dict[str, Any]) -> FederationCandidate:
    """Recreate a ``FederationCandidate`` from the dictionary produced by
    ``candidate_to_dict``.

    The function performs the inverse transformations for Enums and ``bytes``.
    It is tolerant to extra keys – they are passed to the constructor if the
    ``FederationCandidate`` signature accepts them; otherwise they are ignored.
    """
    # Prepare a clean argument dictionary for the constructor
    ctor_kwargs: Dict[str, Any] = {}
    for key, value in data.items():
        if key == "state":
            # ``state`` is stored as the Enum's value or name; convert back.
            ctor_kwargs[key] = _json_to_enum(FederationState, value)
            continue
        if isinstance(value, str):
            # Attempt to decode potential base64 payloads.
            decoded = _base64_to_bytes(value)
            ctor_kwargs[key] = decoded if isinstance(decoded, bytes) else value
        elif isinstance(value, list):
            # Recursively handle list elements that might be base64 strings.
            ctor_kwargs[key] = [_base64_to_bytes(v) for v in value]
        else:
            ctor_kwargs[key] = value

    # Instantiate the candidate.  Any unexpected keys will raise a TypeError;
    # we let that propagate because it signals a mismatch between the stored
    # representation and the current constructor contract.
    return FederationCandidate(**ctor_kwargs)
