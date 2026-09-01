import asyncio
import pytest

from aiohttp.http2.synchro import HostProbeSynchronizer


SLEEP_TIME = 0.0001


@pytest.fixture
def sync() -> HostProbeSynchronizer:
    return HostProbeSynchronizer()


@pytest.mark.asyncio
async def test_first_acquire_immediate_and_second_blocks(sync: HostProbeSynchronizer) -> None:
    key = "host"
    acquired_first = asyncio.Event()
    release_now = asyncio.Event()

    async def first_worker() -> None:
        await sync.acquire(key)
        acquired_first.set()
        await release_now.wait()
        sync.release(key)

    async def second_worker() -> bool:
        await sync.acquire(key)
        # If we get here, the second acquire succeeded
        return True

    # Start first worker; it should acquire immediately.
    t1 = asyncio.create_task(first_worker())
    await asyncio.wait_for(acquired_first.wait(), timeout=1.0)
    assert sync.is_locked(key)

    # Start second worker; it should block.
    t2 = asyncio.create_task(second_worker())
    await asyncio.sleep(SLEEP_TIME)
    assert not t2.done()

    # Release and let second worker proceed.
    release_now.set()
    result = await asyncio.wait_for(t2, timeout=1.0)
    assert result is True
    assert not sync.is_locked(key)

    # Clean up first worker (already finished release, but ensure it completes)
    await asyncio.wait_for(t1, timeout=1.0)


@pytest.mark.asyncio
async def test_release_wakes_all_waiters(sync: HostProbeSynchronizer) -> None:
    key = "host"
    num_waiters = 3
    acquired_events = [asyncio.Event() for _ in range(num_waiters)]
    release_now = asyncio.Event()

    async def worker(i: int) -> None:
        await sync.acquire(key)
        acquired_events[i].set()
        await release_now.wait()
        sync.release(key)

    # First worker acquires, others wait.
    t_first = asyncio.create_task(worker(0))
    await asyncio.wait_for(acquired_events[0].wait(), timeout=1.0)
    tasks = [t_first]
    for i in range(1, num_waiters):
        t = asyncio.create_task(worker(i))
        tasks.append(t)
        await asyncio.sleep(SLEEP_TIME)

    # Ensure none of the waiters acquired yet.
    for i in range(1, num_waiters):
        assert not acquired_events[i].is_set()

    # Release, all waiters should wake and set their events.
    release_now.set()
    for i in range(1, num_waiters):
        await asyncio.wait_for(acquired_events[i].wait(), timeout=1.0)

    # All tasks should complete.
    for t in tasks:
        await asyncio.wait_for(t, timeout=1.0)
    assert not sync.is_locked(key)


@pytest.mark.asyncio
async def test_cancellation_while_waiting(sync: HostProbeSynchronizer) -> None:
    key = "host"
    acquired = asyncio.Event()
    release_now = asyncio.Event()

    async def first_worker() -> None:
        await sync.acquire(key)
        acquired.set()
        await release_now.wait()
        sync.release(key)

    t1 = asyncio.create_task(first_worker())
    await asyncio.wait_for(acquired.wait(), timeout=1.0)

    # Start a waiter that will be cancelled.
    async def waiter() -> None:
        await sync.acquire(key)

    t2 = asyncio.create_task(waiter())
    await asyncio.sleep(SLEEP_TIME)
    assert not t2.done()

    # Cancel the waiter.
    t2.cancel()
    with pytest.raises(asyncio.CancelledError):
        await t2

    # Ensure the key is still locked by first worker.
    assert sync.is_locked(key)

    # Release and verify no errors, key unlocked.
    release_now.set()
    await asyncio.wait_for(t1, timeout=1.0)
    assert not sync.is_locked(key)


@pytest.mark.asyncio
async def test_reacquire_after_release(sync: HostProbeSynchronizer) -> None:
    key = "host"
    await sync.acquire(key)
    assert sync.is_locked(key)
    sync.release(key)
    assert not sync.is_locked(key)

    # Acquire again – should not block.
    await sync.acquire(key)
    assert not sync.is_locked(key)

@pytest.mark.asyncio
async def test_is_locked_reflects_state(sync: HostProbeSynchronizer) -> None:
    key = "host"
    assert not sync.is_locked(key)
    await sync.acquire(key)
    assert sync.is_locked(key)
    sync.release(key)
    assert not sync.is_locked(key)


@pytest.mark.asyncio
async def test_different_keys_are_independent(sync: HostProbeSynchronizer) -> None:
    key1 = "host1"
    key2 = "host2"

    await sync.acquire(key1)
    assert sync.is_locked(key1)
    assert not sync.is_locked(key2)

    # Acquiring key2 should not block because it's a different key.
    await sync.acquire(key2)
    assert sync.is_locked(key2)

    # Release key1; key2 remains locked.
    sync.release(key1)
    assert not sync.is_locked(key1)
    assert sync.is_locked(key2)

    sync.release(key2)
    assert not sync.is_locked(key2)


@pytest.mark.asyncio
async def test_release_without_acquire_does_not_raise(sync: HostProbeSynchronizer) -> None:
    key = "never_acquired"
    # Should not raise.
    sync.release(key)
    assert not sync.is_locked(key)


@pytest.mark.asyncio
async def test_release_after_cancelled_waiter(sync: HostProbeSynchronizer) -> None:
    key = "host"
    acquired = asyncio.Event()
    release_now = asyncio.Event()

    async def first_worker() -> None:
        await sync.acquire(key)
        acquired.set()
        await release_now.wait()
        sync.release(key)

    t1 = asyncio.create_task(first_worker())
    await asyncio.wait_for(acquired.wait(), timeout=1.0)

    # Start a waiter, let it block, then cancel it.
    async def waiter() -> None:
        await sync.acquire(key)

    t2 = asyncio.create_task(waiter())
    await asyncio.sleep(SLEEP_TIME)
    assert not t2.done()
    t2.cancel()
    with pytest.raises(asyncio.CancelledError):
        await t2

    # Release and ensure no exception.
    release_now.set()
    await asyncio.wait_for(t1, timeout=1.0)
    assert not sync.is_locked(key)

    # A new acquire should work.
    await sync.acquire(key)
    # This is not the first request
    # therefore it does not lock
    assert not sync.is_locked(key)


@pytest.mark.asyncio
async def test_concurrent_acquire_after_release(sync: HostProbeSynchronizer) -> None:
    key = "host"
    # First acquire and release immediately.
    await sync.acquire(key)
    sync.release(key)

    # Now start two tasks that both try to acquire.
    # Both should run without locking
    t1 = asyncio.create_task(sync.acquire(key))
    t2 = asyncio.create_task(sync.acquire(key))

    # Allow both to run; one will lock, the other will wait.
    await asyncio.sleep(SLEEP_TIME)
    assert not sync.is_locked(key)
    # All tasks are done
    done = [t for t in (t1, t2) if t.done()]
    assert len(done) == 2

    # Release, the second task should complete.
    sync.release(key)
    for t in (t1, t2):
        await asyncio.wait_for(t, timeout=1.0)
    assert not sync.is_locked(key)
