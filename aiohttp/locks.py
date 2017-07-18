import asyncio
import collections

from .helpers import create_future


class Event:
    """
    Adhoc Event class mainly copied from the official asyncio.locks.Event, but
    modifying the `set` method. It allows to pass an exception to wake
    the waiters with an exception.

    This is used when the event creator cant accommplish the requirements
    due to an exception, instead of try to built a sophisticated solution
    the same exeption is passed to the waiters.
    """

    def __init__(self, *, loop=None):
        self._waiters = collections.deque()
        self._value = False
        if loop is not None:
            self._loop = loop
        else:
            self._loop = asyncio.get_event_loop()

    def __repr__(self):
        res = super().__repr__()
        extra = 'set' if self._value else 'unset'
        if self._waiters:
            extra = '{},waiters:{}'.format(extra, len(self._waiters))
        return '<{} [{}]>'.format(res[1:-1], extra)

    def is_set(self):
        """Return True if and only if the internal flag is true."""
        return self._value

    def set(self, exc=None):
        """Set the internal flag to true. All coroutines waiting for it to
        become true are awakened. Coroutine that call wait() once the flag is
        true will not block at all.

        If `exc` is different than None the `future.set_exception` is called
        """
        if not self._value:
            self._value = True

            for fut in self._waiters:
                if not fut.done():
                    if not exc:
                        fut.set_result(True)
                    else:
                        fut.set_exception(exc)

    def clear(self):
        """Reset the internal flag to false. Subsequently, coroutines calling
        wait() will block until set() is called to set the internal flag
        to true again."""
        self._value = False

    @asyncio.coroutine
    def wait(self):
        """Block until the internal flag is true.

        If the internal flag is true on entry, return True
        immediately.  Otherwise, block until another coroutine calls
        set() to set the flag to true, then return True.
        """
        if self._value:
            return True

        fut = create_future(self._loop)
        self._waiters.append(fut)
        try:
            yield from fut
            return True
        finally:
            self._waiters.remove(fut)
