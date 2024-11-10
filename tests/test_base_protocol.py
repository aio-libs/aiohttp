import asyncio
from contextlib import suppress
from unittest import mock

import pytest

from aiohttp.base_protocol import BaseProtocol


async def test_loop() -> None:
    loop = asyncio.get_event_loop()
    asyncio.set_event_loop(None)
    pr = BaseProtocol(loop)
    assert pr._loop is loop


async def test_pause_writing() -> None:
    loop = asyncio.get_event_loop()
    pr = BaseProtocol(loop)
    assert not pr._paused
    assert pr.writing_paused is False
    pr.pause_writing()
    assert pr._paused
    assert pr.writing_paused is True  # type: ignore[unreachable]


async def test_pause_reading_no_transport() -> None:
    loop = asyncio.get_event_loop()
    pr = BaseProtocol(loop)
    assert not pr._reading_paused
    pr.pause_reading()
    assert not pr._reading_paused


async def test_pause_reading_stub_transport() -> None:
    loop = asyncio.get_event_loop()
    pr = BaseProtocol(loop)
    tr = asyncio.Transport()
    pr.transport = tr
    assert not pr._reading_paused
    pr.pause_reading()
    assert pr._reading_paused


async def test_resume_reading_no_transport() -> None:
    loop = asyncio.get_event_loop()
    pr = BaseProtocol(loop)
    pr._reading_paused = True
    pr.resume_reading()
    assert pr._reading_paused


async def test_resume_reading_stub_transport() -> None:
    loop = asyncio.get_event_loop()
    pr = BaseProtocol(loop)
    tr = asyncio.Transport()
    pr.transport = tr
    pr._reading_paused = True
    pr.resume_reading()
    assert not pr._reading_paused


async def test_resume_writing_no_waiters() -> None:
    loop = asyncio.get_event_loop()
    pr = BaseProtocol(loop=loop)
    pr.pause_writing()
    assert pr._paused
    pr.resume_writing()
    assert not pr._paused


async def test_resume_writing_waiter_done() -> None:
    loop = asyncio.get_event_loop()
    pr = BaseProtocol(loop=loop)
    waiter = mock.Mock(done=mock.Mock(return_value=True))
    pr._drain_waiter = waiter
    pr._paused = True
    pr.resume_writing()
    assert not pr._paused
    assert waiter.mock_calls == [mock.call.done()]


async def test_connection_made() -> None:
    loop = asyncio.get_event_loop()
    pr = BaseProtocol(loop=loop)
    tr = mock.Mock()
    assert pr.transport is None
    pr.connection_made(tr)
    assert pr.transport is not None


async def test_connection_lost_not_paused() -> None:
    loop = asyncio.get_event_loop()
    pr = BaseProtocol(loop=loop)
    tr = mock.Mock()
    pr.connection_made(tr)
    assert pr.connected
    pr.connection_lost(None)
    assert pr.transport is None
    assert not pr.connected


async def test_connection_lost_paused_without_waiter() -> None:
    loop = asyncio.get_event_loop()
    pr = BaseProtocol(loop=loop)
    tr = mock.Mock()
    pr.connection_made(tr)
    assert pr.connected
    pr.pause_writing()
    pr.connection_lost(None)
    assert pr.transport is None
    assert not pr.connected


async def test_connection_lost_waiter_done() -> None:
    loop = asyncio.get_event_loop()
    pr = BaseProtocol(loop=loop)
    pr._paused = True
    waiter = mock.Mock(done=mock.Mock(return_value=True))
    pr._drain_waiter = waiter
    pr.connection_lost(None)
    assert pr._drain_waiter is None
    assert waiter.mock_calls == [mock.call.done()]


async def test_drain_lost() -> None:
    loop = asyncio.get_event_loop()
    pr = BaseProtocol(loop=loop)
    tr = mock.Mock()
    pr.connection_made(tr)
    pr.connection_lost(None)
    with pytest.raises(ConnectionResetError):
        await pr._drain_helper()


async def test_drain_not_paused() -> None:
    loop = asyncio.get_event_loop()
    pr = BaseProtocol(loop=loop)
    tr = mock.Mock()
    pr.connection_made(tr)
    assert pr._drain_waiter is None
    await pr._drain_helper()
    assert pr._drain_waiter is None


async def test_resume_drain_waited() -> None:
    loop = asyncio.get_event_loop()
    pr = BaseProtocol(loop=loop)
    tr = mock.Mock()
    pr.connection_made(tr)
    pr.pause_writing()

    t = loop.create_task(pr._drain_helper())
    await asyncio.sleep(0)

    assert pr._drain_waiter is not None
    pr.resume_writing()
    assert (await t) is None
    assert pr._drain_waiter is None


async def test_lost_drain_waited_ok() -> None:
    loop = asyncio.get_event_loop()
    pr = BaseProtocol(loop=loop)
    tr = mock.Mock()
    pr.connection_made(tr)
    pr.pause_writing()

    t = loop.create_task(pr._drain_helper())
    await asyncio.sleep(0)

    assert pr._drain_waiter is not None
    pr.connection_lost(None)
    assert (await t) is None
    assert pr._drain_waiter is None


async def test_lost_drain_waited_exception() -> None:
    loop = asyncio.get_event_loop()
    pr = BaseProtocol(loop=loop)
    tr = mock.Mock()
    pr.connection_made(tr)
    pr.pause_writing()

    t = loop.create_task(pr._drain_helper())
    await asyncio.sleep(0)

    assert pr._drain_waiter is not None
    exc = RuntimeError()
    pr.connection_lost(exc)
    with pytest.raises(ConnectionError, match=r"^Connection lost$") as cm:
        await t
    assert cm.value.__cause__ is exc
    assert pr._drain_waiter is None


async def test_lost_drain_cancelled() -> None:
    loop = asyncio.get_event_loop()
    pr = BaseProtocol(loop=loop)
    tr = mock.Mock()
    pr.connection_made(tr)
    pr.pause_writing()

    fut = loop.create_future()

    async def wait():
        fut.set_result(None)
        await pr._drain_helper()

    t = loop.create_task(wait())
    await fut
    t.cancel()

    assert pr._drain_waiter is not None
    pr.connection_lost(None)
    with suppress(asyncio.CancelledError):
        await t
    assert pr._drain_waiter is None


async def test_resume_drain_cancelled() -> None:
    loop = asyncio.get_event_loop()
    pr = BaseProtocol(loop=loop)
    tr = mock.Mock()
    pr.connection_made(tr)
    pr.pause_writing()

    fut = loop.create_future()

    async def wait():
        fut.set_result(None)
        await pr._drain_helper()

    t = loop.create_task(wait())
    await fut
    t.cancel()

    assert pr._drain_waiter is not None
    pr.resume_writing()
    with suppress(asyncio.CancelledError):
        await t
    assert pr._drain_waiter is None


async def test_parallel_drain_race_condition() -> None:
    loop = asyncio.get_event_loop()
    pr = BaseProtocol(loop=loop)
    tr = mock.Mock()
    pr.connection_made(tr)
    pr.pause_writing()

    ts = [loop.create_task(pr._drain_helper()) for _ in range(5)]
    assert not (await asyncio.wait(ts, timeout=0.5))[
        0
    ], "All draining tasks must be pending"

    assert pr._drain_waiter is not None
    pr.resume_writing()
    await asyncio.gather(*ts)
    assert pr._drain_waiter is None
