"""WebSocket protocol versions 13 and 8."""

import importlib.util
import os
import sys

# The mypyc-compiled reader shadows reader.py on import, so force .py import.
if os.environ.get("AIOHTTP_NO_EXTENSIONS"):
    _spec = importlib.util.spec_from_file_location(
        f"{__name__}.reader", os.path.join(os.path.dirname(__file__), "reader.py")
    )
    assert _spec is not None and _spec.loader is not None
    reader = importlib.util.module_from_spec(_spec)
    sys.modules[_spec.name] = reader
    _spec.loader.exec_module(reader)
    del _spec
