import asyncio
import collections

from .helpers import ensure_future


class EventResultOrError:
    """
    This class wrappers the Event asyncio lock allowing either awake the
    locked Tasks without any error or raising an exception.

    thanks to @vorpalsmith for the simple design.
    """
    def __init__(self, loop):
        self._loop = loop
        self._exc = None
        self._event = asyncio.Event(loop=loop)
        self._waiters = collections.deque()

    def set(self, exc=None):
        self._exc = exc
        self._event.set()

    @asyncio.coroutine
    def wait(self):
        fut = ensure_future(self._event.wait(), loop=self._loop)
        self._waiters.append(fut)
        try:
            val = yield from fut
        finally:
            self._waiters.remove(fut)

        if self._exc is not None:
            raise self._exc

        return val

    def cancel(self):
        """ Cancel all waiters """
        for waiter in self._waiters:
            waiter.cancel()
