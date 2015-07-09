import asyncio

class Signal(object):
    def __init__(self, parameters):
        self._parameters = frozenset(parameters)
        self._receivers = set()

    def connect(self, receiver):
        # Check that the callback can be called with the given parameter names
        signature(receiver).bind(**{p: None for p in self._parameters})
        self._receivers.add(receiver)

    def disconnect(self, receiver):
        self._receivers.remove(receiver)

    def send(self, **kwargs):
        for receiver in self._receivers:
            receiver(**kwargs)

class AsyncSignal(Signal):
    def connect(self, receiver):
        assert asyncio.iscoroutinefunction(receiver), receiver
        super().connect(receiver)

    @asyncio.coroutine
    def send(self, **kwargs):
        for receiver in self._receivers:
            yield from receiver(**kwargs)

