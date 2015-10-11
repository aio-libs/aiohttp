import asyncio


class Signal(list):
    """
    Coroutine-based signal implementation

    To connect a callback to a signal, use any list method.

    Signals are fired using the :meth:`send` coroutine, which takes named
    arguments.
    """

    @asyncio.coroutine
    def send(self, *args, **kwargs):
        """
        Sends data to all registered receivers.
        """
        for receiver in self:
            res = receiver(*args, **kwargs)
            if asyncio.iscoroutine(res) or isinstance(res, asyncio.Future):
                yield from res

    def copy(self):
        raise NotImplementedError("copy() is forbidden")

    def sort(self):
        raise NotImplementedError("sort() is forbidden")
