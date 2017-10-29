import asyncio
import collections


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

    async def wait(self):
        fut = asyncio.ensure_future(self._event.wait(), loop=self._loop)
        self._waiters.append(fut)
        try:
            val = await fut
        finally:
            self._waiters.remove(fut)

        if self._exc is not None:
            raise self._exc

        return val

    def cancel(self):
        """ Cancel all waiters """
        for fut in self._waiters:
            if not fut.done():
                fut.cancel()
