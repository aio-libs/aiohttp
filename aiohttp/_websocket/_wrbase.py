import asyncio
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from .models import WSMessage
    from .reader import WebSocketDataQueue


class _WeakrefBase:
    """Hack for https://github.com/mypyc/mypyc/issues/1102"""


class _InterpretedReadMixin:
    """Hack for https://github.com/mypyc/mypyc/issues/1214"""

    async def read(self) -> "WSMessage":
        q = cast("WebSocketDataQueue", self)
        if not q._buffer and not q._eof:
            assert not q._waiter
            waiter: "asyncio.Future[None]" = q._loop.create_future()
            q._waiter = waiter
            try:
                await waiter
            except (asyncio.CancelledError, asyncio.TimeoutError):
                q._waiter = None
                raise
        return q._read_from_buffer()
