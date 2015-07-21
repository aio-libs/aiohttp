import abc
from inspect import signature

import asyncio

class Signal(metaclass=abc.ABCMeta):
    """
    Abstract base class for signals.

    To connect a callback to a signal, use the :meth:`callback` method. If you
    wish to pass additional arguments to your callback,
    use :meth:`functools.partial`. Signals can be disconnected again using
    :meth:`disconnect`. Callbacks are executed in an arbitrary order.

    There are two declared concrete subclasses, :class:`FunctionSignal`, which
    dispatches to plain function callbacks, and :class:`CoroutineSignal`,
    which accepts coroutine functions as callbacks.

    Signals are fired using :meth:`send`, which takes named arguments. The
    :meth:`send` method for :class:`CoroutineSignal` is itself a coroutine
    function.
    """
    def __init__(self, parameters):
        self._parameters = frozenset(parameters)
        self._receivers = set()

    def connect(self, receiver):
        """
        Connect a receiver.

        :param collections.abc.Callable receiver: A function to be called
            whenever the signal is fired.
        :raises TypeError: if ``receiver`` isn't a callable, or doesn't have
            a call signature that supports the signals parameters.
        """
        # Check that the callback can be called with the given parameter names
        if __debug__:
            signature(receiver).bind(**{p: None for p in self._parameters})
        self._receivers.add(receiver)

    def disconnect(self, receiver):
        """
        Disconnect a receiver.

        :param collections.abc.Callable receiver: A function to no longer
            be called whenever the signal is fired.

        :raises KeyError: if the receiver wasn't already registered.
        """
        self._receivers.remove(receiver)

    @abc.abstractmethod
    def send(self, **kwargs):
        """
        Sends data to all registered receivers.
        """
        pass

class FunctionSignal(Signal):
    """
    A signal type that dispatches to plain functions.

    See :class:`Signal` for documentation.
    """
    def connect(self, receiver):
        assert not asyncio.iscoroutinefunction(receiver), receiver
        super().connect(receiver)

    def send(self, **kwargs):
        for receiver in self._receivers:
            receiver(**kwargs)

class CoroutineSignal(Signal):
    """
    A signal type that dispatches to coroutine functions.

    See :class:`Signal` for documentation.
    """
    def connect(self, receiver):
        assert asyncio.iscoroutinefunction(receiver), receiver
        super().connect(receiver)

    @asyncio.coroutine
    def send(self, **kwargs):
        for receiver in self._receivers:
            yield from receiver(**kwargs)

