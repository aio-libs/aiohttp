import abc
from inspect import signature

import asyncio

class Signal(metaclass=abc.ABCMeta):
    def __init__(self, parameters):
        self._parameters = frozenset(parameters)
        self._receivers = set()

    def connect(self, receiver):
        # Check that the callback can be called with the given parameter names
        if __debug__:
            signature(receiver).bind(**{p: None for p in self._parameters})
        self._receivers.add(receiver)

    def disconnect(self, receiver):
        self._receivers.remove(receiver)

    @abc.abstractmethod
    def send(self, **kwargs):
        pass

class FunctionSignal(Signal):
    def connect(self, receiver):
        assert not asyncio.iscoroutinefunction(receiver), receiver
        super().connect(receiver)

    def send(self, **kwargs):
        for receiver in self._receivers:
            receiver(**kwargs)

class CoroutineSignal(Signal):
    def connect(self, receiver):
        assert asyncio.iscoroutinefunction(receiver), receiver
        super().connect(receiver)

    @asyncio.coroutine
    def send(self, **kwargs):
        for receiver in self._receivers:
            yield from receiver(**kwargs)

