"""Reader for WebSocket protocol versions 13 and 8."""

from typing import TYPE_CHECKING

from ..helpers import NO_EXTENSIONS

if TYPE_CHECKING or NO_EXTENSIONS:  # pragma: no cover
    from .reader_py import WebSocketReader as WebSocketReaderPython

    WebSocketReader = WebSocketReaderPython
else:
    try:
        from ._reader_c import (  # type: ignore[import-not-found]
            WebSocketReader as WebSocketReaderCython,
        )

        WebSocketReader = WebSocketReaderCython
    except ImportError:  # pragma: no cover
        from .reader_py import WebSocketReader as WebSocketReaderPython

        WebSocketReader = WebSocketReaderPython
