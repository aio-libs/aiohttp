import abc
import functools
from inspect import signature

import asyncio

class Signal(list):
    """
    Coroutine-based signal implementation

    To connect a callback to a signal, use any list method. If wish to pass
    additional arguments to your callback, use :meth:`functools.partial`.

    Signals are fired using the :meth:`send` coroutine, which takes named
    arguments.
    """
    def __init__(self, *args, parameters=None):
        self._parameters = parameters
        if args:
            self.extend(args[0])

    def _check_signature(self, receiver):
        if self._parameters is not None:
            signature(receiver).bind(**{p: None for p in self._parameters})
        return True

    # Only override these methods to check signatures if not optimised.
    if __debug__:
        def __iadd__(self, other):
            assert all(map(self._check_signature, other))
            super().__iadd__(other)

        def __setitem__(self, key, value):
            if isinstance(key, slice):
                value = list(value)
                assert all(map(self._check_signature, value))
            else:
                assert self._check_signature(value)
            super().__setitem__(key, value)

        def insert(self, index, obj):
            assert self._check_signature(obj)
            super().insert(index, obj)

        def append(self, obj):
            assert self._check_signature(obj)
            super().append(obj)

        def extend(self, other):
            other = list(other)
            assert all(map(self._check_signature, other))
            super().extend(other)

    @asyncio.coroutine
    def send(self, **kwargs):
        """
        Sends data to all registered receivers.
        """
        for receiver in self:
            res = receiver(**kwargs)
            if asyncio.iscoroutine(res) or isinstance(res, asyncio.Future):
                yield from res
