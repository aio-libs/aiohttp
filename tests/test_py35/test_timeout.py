import asyncio
import time

import pytest
from aiohttp.helpers import Timeout


def test_timeout_without_error_raising(loop):
    canceled_raised = False

    async def long_running_task():
        try:
            await asyncio.sleep(10, loop=loop)
        except asyncio.CancelledError:
            nonlocal canceled_raised
            canceled_raised = True
            raise

    async def run():
        async with Timeout(0.01, loop=loop) as t:
            await long_running_task()
            assert t._loop is loop
        assert canceled_raised, 'CancelledError was not raised'

    loop.run_until_complete(run())


def test_timeout_raise_error(loop):
    async def long_running_task():
        await asyncio.sleep(10, loop=loop)

    async def run():
        with pytest.raises(asyncio.TimeoutError):
            async with Timeout(0.01, raise_error=True, loop=loop):
                await long_running_task()

    loop.run_until_complete(run())


def test_timeout_cancel(loop):
    canceled_raised = False

    async def long_running_task():
        try:
            await asyncio.sleep(0.1, loop=loop)
        except Exception:
            nonlocal canceled_raised
            canceled_raised = True
            raise

    async def run():
        async with Timeout(0.01, raise_error=True, loop=loop) as t:
            t.cancel()
            await long_running_task()
        assert not canceled_raised, 'CancelledError should not be raised'
    loop.run_until_complete(run())


def test_timeout_finish_in_time(loop):
    async def run():
        async with Timeout(0.1, raise_error=True, loop=loop):
            await asyncio.sleep(0.01, loop=loop)
            return 'done'

    loop.run_until_complete(run())


def test_timeout_gloabal_loop(loop):
    asyncio.set_event_loop(loop)

    async def run():
        async with Timeout(0.1) as t:
            await asyncio.sleep(0.01)
            assert t._loop is loop

    loop.run_until_complete(run())


def test_timeout_not_relevant_exception(loop):

    async def run():
        with pytest.raises(KeyError):
            async with Timeout(0.1, loop=loop):
                raise KeyError

    loop.run_until_complete(run())


def test_timeout_blocking_loop(loop):
    async def long_running_task():
        time.sleep(0.1)
        return 'done'

    async def run():
        async with Timeout(0.01, raise_error=True, loop=loop):
            result = await long_running_task()
            assert result == 'done'

    loop.run_until_complete(run())


# ported tests from asyncio.wait_for
def test_timeout_is_none(loop):

    async def long_running_task():
        return 'done'

    async def run():
        async with Timeout(None, raise_error=True, loop=loop):
            value = await long_running_task()
        assert value == 'done'

    loop.run_until_complete(run())


def test_for_race_conditions(loop):
    async def run():
        fut = asyncio.Future(loop=loop)
        loop.call_later(0.1, fut.set_result('ok'))
        async with Timeout(0.2, raise_error=True, loop=loop):
            resp = await fut
            assert resp == 'ok'

    loop.run_until_complete(run())


def test_timeout(loop):

    async def go():
        foo_running = None

        start = loop.time()
        with pytest.raises(asyncio.TimeoutError):
            async with Timeout(0.1, raise_error=True, loop=loop):
                foo_running = True
                try:
                    await asyncio.sleep(0.2, loop=loop)
                finally:
                    foo_running = False

        assert abs(0.1 - (loop.time() - start)) < 0.002
        assert not foo_running

    loop.run_until_complete(go())
