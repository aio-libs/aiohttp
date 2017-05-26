import asyncio


class Event(asyncio.locks.Event):
    """
    Adhoc Event class that modifies the `set` method, it allows to
    pass an exception to wake the waiters with an exception.

    This is used when the event creator cant accommplish the requirements
    due to an exception, instead of try to built a sophisticated solution
    the same exeption is passed to the waiters.
    """

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
