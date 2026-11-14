"""Public interface for the `omega.tools` subpackage.

This module re‑exports the central `ToolRegistry` class so that callers can
simply write::

    from omega.tools import ToolRegistry

instead of having to know the exact implementation module
(`omega.tools.registry`). Keeping the import here maintains a stable public
API and helps static analysis tools discover the symbol.
"""

from .registry import ToolRegistry

__all__ = ["ToolRegistry"]
