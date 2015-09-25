import abc
import functools
from inspect import signature

import asyncio

class Signal(metaclass=abc.ABCMeta):
    """
    Coroutine-based signal implementation

    To connect a callback to a signal, use the :meth:`callback` method. If you
    wish to pass additional arguments to your callback,
    use :meth:`functools.partial`. Signals can be disconnected again using
    :meth:`disconnect`. Callbacks are executed in an arbitrary order and must
    be coroutines.

    Signals are fired using the :meth:`send` coroutine, which takes named
    arguments.
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
            # We suggest using functools.partial, but that hides the fact that
            # they are coroutine functions. So, let's check the underlying
            # function instead of the receiver itself.
            func = receiver
            while isinstance(func, functools.partial):
                func = func.func
            if not asyncio.iscoroutinefunction(func):
                raise TypeError("{} is not a coroutine function".format(receiver))
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

    @asyncio.coroutine
    def send(self, **kwargs):
        """
        Sends data to all registered receivers.
        """
        for receiver in self._receivers:
            yield from receiver(**kwargs)

