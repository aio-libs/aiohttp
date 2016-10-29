import asyncio
from itertools import count

from aiohttp.helpers import FrozenList


class BaseSignal(FrozenList):

    __slots__ = ()

    @asyncio.coroutine
    def _send(self, *args, **kwargs):
        for receiver in self:
            res = receiver(*args, **kwargs)
            if asyncio.iscoroutine(res) or isinstance(res, asyncio.Future):
                yield from res


class Signal(BaseSignal):
    """Coroutine-based signal implementation.

    To connect a callback to a signal, use any list method.

    Signals are fired using the :meth:`send` coroutine, which takes named
    arguments.
    """

    __slots__ = ('_app', '_name', '_pre', '_post')

    def __init__(self, app):
        super().__init__()
        self._app = app
        klass = self.__class__
        self._name = klass.__module__ + ':' + klass.__qualname__
        self._pre = app.on_pre_signal
        self._post = app.on_post_signal

    @asyncio.coroutine
    def send(self, *args, **kwargs):
        """
        Sends data to all registered receivers.
        """
        ordinal = None
        debug = self._app._debug
        if debug:
            ordinal = self._pre.ordinal()
            yield from self._pre.send(ordinal, self._name, *args, **kwargs)
        yield from self._send(*args, **kwargs)
        if debug:
            yield from self._post.send(ordinal, self._name, *args, **kwargs)


class DebugSignal(BaseSignal):

    __slots__ = ()

    @asyncio.coroutine
    def send(self, ordinal, name, *args, **kwargs):
        yield from self._send(ordinal, name, *args, **kwargs)


class PreSignal(DebugSignal):

    __slots__ = ('_counter',)

    def __init__(self):
        super().__init__()
        self._counter = count(1)

    def ordinal(self):
        return next(self._counter)


class PostSignal(DebugSignal):

    __slots__ = ()
