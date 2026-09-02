import asyncio
from collections import defaultdict
from typing import Any, Dict, List, Set


class HostProbeSynchronizer:
    """
    A key‑based synchronisation primitive.

    For each key (e.g. a connection host) only the first task that calls
    `acquire(key)` is allowed to proceed immediately. All other tasks wait
    until `release(key)` is called. When `release(key)` happens, *all*
    waiting tasks are woken and may continue concurrently. After release,
    the key is unlocked, so the next `acquire(key)` will again lock it and
    proceed immediately.

    This is designed for the initial ALPN probe of an HTTP connection: only
    one task should perform the probe per host; once the protocol is known
    (h1 or h2), all waiting tasks can proceed (for h1 they may open
    connections in parallel, for h2 they reuse the single connection).
    """

    def __init__(self) -> None:
        # Keys that are currently locked (i.e. an acquire has succeeded and
        # release has not yet been called).
        self._locked: Set[Any] = set()
        self._done: Set[Any] = set()
        # For each locked key, a list of futures that waiting tasks are awaiting.
        self._waiters: Dict[Any, List[asyncio.Future[None]]] = defaultdict(list)

    async def acquire(self, key: Any) -> None:
        """
        Wait until the key is unlocked, then lock it and return.

        If the key is already locked, the task is suspended until `release`
        is called for that key. When release is called, all waiting tasks are
        woken and return from this method (they do not re‑acquire the lock).
        """
        if key in self._done:
            # Already released (no-op)
            return

        if key not in self._locked:
            # First to acquire: lock the key and proceed.
            self._locked.add(key)
            return

        # Key is locked; we must wait.
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[None] = loop.create_future()
        self._waiters[key].append(fut)
        try:
            await fut
        except asyncio.CancelledError:
            # Remove our future from the waiters list if we are cancelled.
            waiters = self._waiters.get(key)
            if waiters is not None and fut in waiters:
                waiters.remove(fut)
            # If the list becomes empty and the key is still locked, we may
            # optionally clean up the empty list to save memory.
            if waiters is not None and not waiters:
                del self._waiters[key]
            raise

    def release(self, key: Any) -> None:
        """
        Unlock the given key and wake all tasks waiting for it.

        After this call, all tasks that had called `acquire(key)` and were
        suspended will resume. The key becomes unlocked, so a subsequent
        `acquire(key)` will lock it again and return immediately.
        """
        if key not in self._locked:
            # this happens when any request after the first calls `release`
            return

        # Remove the lock.
        self._locked.remove(key)
        self._done.add(key)

        # Wake all waiters.
        waiters = self._waiters.pop(key, [])
        for fut in waiters:
            if not fut.done():
                fut.set_result(None)

    def is_locked(self, key: Any) -> bool:
        """Return True if the key is currently locked."""
        return key in self._locked

    def __contains__(self, key: Any) -> bool:
        return self.is_locked(key)


async def main() -> None:
    sync = HostProbeSynchronizer()
    host = "example.com"

    async def worker(name: str) -> None:
        print(f"{name}: before acquire")
        await sync.acquire(host)
        print(f"{name}: acquired")
        # Simulate some work
        await asyncio.sleep(1)
        print(f"{name}: releasing")
        sync.release(host)

    # First worker locks the host
    t1 = asyncio.create_task(worker("first"))
    await asyncio.sleep(0.1)  # ensure first has acquired
    # Two more workers wait
    t2 = asyncio.create_task(worker("second"))
    t3 = asyncio.create_task(worker("third"))
    await asyncio.sleep(0.1)
    # Now release will wake both t2 and t3
    await t1
    await t2
    await t3


if __name__ == "__main__":
    asyncio.run(main())
