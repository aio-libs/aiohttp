# Tests of custom aiohttp locks implementations
import asyncio

import pytest

from aiohttp.locks import EventResultOrError


class TestEventResultOrError:
    async def test_set_exception(self, loop) -> None:
        ev = EventResultOrError(loop=loop)

        async def c():
            try:
                await ev.wait()
            except Exception as e:
                return e
            return 1

        t = loop.create_task(c())
        await asyncio.sleep(0)
        e = Exception()
        ev.set(exc=e)
        assert (await t) == e

    async def test_set(self, loop) -> None:
        ev = EventResultOrError(loop=loop)

        async def c():
            await ev.wait()
            return 1

        t = loop.create_task(c())
        await asyncio.sleep(0)
        ev.set()
        assert (await t) == 1

    async def test_cancel_waiters(self, loop) -> None:
        ev = EventResultOrError(loop=loop)

        async def c():
            await ev.wait()

        t1 = loop.create_task(c())
        t2 = loop.create_task(c())
        await asyncio.sleep(0)
        ev.cancel()
        ev.set()

        with pytest.raises(asyncio.CancelledError):
            await t1

        with pytest.raises(asyncio.CancelledError):
            await t2
