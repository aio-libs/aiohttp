"""Reader for WebSocket protocol versions 13 and 8."""

import asyncio
from collections.abc import Callable
from typing import TYPE_CHECKING

from ..helpers import NO_EXTENSIONS

if TYPE_CHECKING or NO_EXTENSIONS:
    from .reader_py import (
        WebSocketDataQueue as WebSocketDataQueuePython,
        WebSocketReader as WebSocketReaderPython,
    )

    WebSocketReader = WebSocketReaderPython
    WebSocketDataQueue = WebSocketDataQueuePython
else:
    try:
        from .reader_c import (  # type: ignore[import-not-found]
            WebSocketDataQueue as WebSocketDataQueueCython,
            WebSocketReader as WebSocketReaderCython,
        )

        WebSocketReader = WebSocketReaderCython
        WebSocketDataQueue = WebSocketDataQueueCython
    except ImportError:  # pragma: no cover
        from .reader_py import (
            WebSocketDataQueue as WebSocketDataQueuePython,
            WebSocketReader as WebSocketReaderPython,
        )

        WebSocketReader = WebSocketReaderPython
        WebSocketDataQueue = WebSocketDataQueuePython


class _WebSocketDataReceivedCallbackWrapper:
    """Wrap a websocket parser and call a callback on any inbound bytes.

    This wrapper is intentionally kept in pure-Python so it works for both the
    pure-python websocket reader and the accelerated `reader_c` extension.
    """

    __slots__ = ("_parser", "_data_received_cb", "_loop", "_reset_handle")

    def __init__(
        self,
        parser: object,
        data_received_cb: Callable[[], None],
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        self._parser = parser
        self._data_received_cb = data_received_cb
        self._loop = loop
        self._reset_handle: asyncio.Handle | None = None

    def feed_data(self, data):  # type: ignore[no-untyped-def]
        if data:
            # Coalesce multiple feed_data() calls into one heartbeat reset
            # per event-loop iteration.
            if self._reset_handle is None:
                self._reset_handle = self._loop.call_soon(self._on_data_received)
        return self._parser.feed_data(data)  # type: ignore[attr-defined]

    def _on_data_received(self) -> None:
        self._reset_handle = None
        self._data_received_cb()

    def feed_eof(self) -> None:
        if self._reset_handle is not None:
            self._reset_handle.cancel()
            self._reset_handle = None
        self._parser.feed_eof()  # type: ignore[attr-defined]
