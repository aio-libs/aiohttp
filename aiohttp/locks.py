import asyncio
import collections
from typing import Any, Optional

try:
    from typing import Deque
except ImportError:
    from typing_extensions import Deque


class EventResultOrError:
    """Event asyncio lock helper class.

    Wraps the Event asyncio lock allowing either to awake the
    locked Tasks without any error or raising an exception.

    thanks to @vorpalsmith for the simple design.
    """

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self._exc: Optional[BaseException] = None
        self._event = asyncio.Event()
        self._waiters: Deque[asyncio.Future[Any]] = collections.deque()

    def set(self, exc: Optional[BaseException] = None) -> None:
        self._exc = exc
        self._event.set()

    async def wait(self) -> Any:
        waiter = self._loop.create_task(self._event.wait())
        self._waiters.append(waiter)
        try:
            val = await waiter
        finally:
            self._waiters.remove(waiter)

        if self._exc is not None:
            raise self._exc

        return val

    def cancel(self) -> None:
        """Cancel all waiters"""
        for waiter in self._waiters:
            waiter.cancel()
