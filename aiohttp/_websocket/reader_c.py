"""C extension shim fallback.

This module intentionally re-exports the pure-Python implementation
when the C-accelerated module is not available (for development and
testing). The upstream generated C file would replace this file when
extensions are built.
"""

from .reader_py import *  # noqa: F401, F403
