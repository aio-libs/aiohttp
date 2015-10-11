import asyncio


class Signal(list):
    """
    Coroutine-based signal implementation

    To connect a callback to a signal, use any list method. If wish to pass
    additional arguments to your callback, use :meth:`functools.partial`.

    Signals are fired using the :meth:`send` coroutine, which takes named
    arguments.
    """

    @asyncio.coroutine
    def send(self, **kwargs):
        """
        Sends data to all registered receivers.
        """
        for receiver in self:
            res = receiver(**kwargs)
            if asyncio.iscoroutine(res) or isinstance(res, asyncio.Future):
                yield from res

    def copy(self):
        raise NotImplementedError("copy() is forbidden")

    def sort(self):
        raise NotImplementedError("sort() is forbidden")
