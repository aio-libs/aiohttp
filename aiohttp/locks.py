import asyncio


class ErrorfulOneShotEvent:
    """
    This class wrappers the Event asyncio lock allowing either awake the
    locked Tasks without any error or raising an exception.

    thanks to @vorpalsmith for the simple design.
    """
    def __init__(self, *, loop=None):
        self._event = asyncio.Event(loop=loop)
        self._exc = None

    def set(self, exc=None):
        self._exc = exc
        self._event.set()

    @asyncio.coroutine
    def wait(self):
        val = yield from self._event.wait()
        if self._exc is not None:
            raise self._exc

        return val
