import asyncio
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import WSMessage
    from .reader import WebSocketDataQueue


class _WeakrefBase:
    """Hack for https://github.com/mypyc/mypyc/issues/1102"""


class _InterpretedReadMixin:
    """Hack for https://github.com/mypyc/mypyc/issues/1214"""

    async def read(self: "WebSocketDataQueue") -> "WSMessage":
        if not self._buffer and not self._eof:
            assert not self._waiter
            self._waiter = self._loop.create_future()
            try:
                await self._waiter
            except (asyncio.CancelledError, asyncio.TimeoutError):
                self._waiter = None
                raise
        return self._read_from_buffer()
