import asyncio
from typing import Optional, cast

from .helpers import get_running_loop
from .log import internal_logger


class BaseProtocol(asyncio.Protocol):
    __slots__ = ('_loop', '_paused', '_drain_waiter',
                 '_connection_lost', 'transport')

    def __init__(self, loop: Optional[asyncio.AbstractEventLoop]=None) -> None:
        self._loop = get_running_loop(loop)
        self._paused = False
        self._drain_waiter = None  # type: Optional[asyncio.Future[None]]
        self._connection_lost = False
        self._reading_paused = False

        self.transport = None  # type: Optional[asyncio.Transport]

    def pause_writing(self) -> None:
        assert not self._paused
        self._paused = True
        if self._loop.get_debug():
            internal_logger.debug("%r pauses writing", self)

    def resume_writing(self) -> None:
        assert self._paused
        self._paused = False
        if self._loop.get_debug():
            internal_logger.debug("%r resumes writing", self)

        waiter = self._drain_waiter
        if waiter is not None:
            self._drain_waiter = None
            if not waiter.done():
                waiter.set_result(None)

    def pause_reading(self) -> None:
        if not self._reading_paused and self.transport is not None:
            try:
                self.transport.pause_reading()
            except (AttributeError, NotImplementedError, RuntimeError):
                pass
            self._reading_paused = True

    def resume_reading(self) -> None:
        if self._reading_paused and self.transport is not None:
            try:
                self.transport.resume_reading()
            except (AttributeError, NotImplementedError, RuntimeError):
                pass
            self._reading_paused = False

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = cast(asyncio.Transport, transport)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self._connection_lost = True
        # Wake up the writer if currently paused.
        self.transport = None
        if not self._paused:
            return
        waiter = self._drain_waiter
        if waiter is None:
            return
        self._drain_waiter = None
        if waiter.done():
            return
        if exc is None:
            waiter.set_result(None)
        else:
            waiter.set_exception(exc)

    async def _drain_helper(self) -> None:
        if self._connection_lost:
            raise ConnectionResetError('Connection lost')
        if not self._paused:
            return
        waiter = self._drain_waiter
        assert waiter is None or waiter.cancelled()
        waiter = self._loop.create_future()
        self._drain_waiter = waiter
        await waiter
