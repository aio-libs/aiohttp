"""Tests of custom aiohttp locks implementations"""
import asyncio

import pytest

from aiohttp import helpers
from aiohttp.locks import EventResultOrError


class TestEventResultOrError:

    @asyncio.coroutine
    def test_set_exception(self, loop):
        ev = EventResultOrError(loop=loop)

        @asyncio.coroutine
        def c():
            try:
                yield from ev.wait()
            except Exception as e:
                return e
            return 1

        t = helpers.ensure_future(c(), loop=loop)
        yield from asyncio.sleep(0, loop=loop)
        e = Exception()
        ev.set(exc=e)
        assert (yield from t) == e

    @asyncio.coroutine
    def test_set(self, loop):
        ev = EventResultOrError(loop=loop)

        @asyncio.coroutine
        def c():
            yield from ev.wait()
            return 1

        t = helpers.ensure_future(c(), loop=loop)
        yield from asyncio.sleep(0, loop=loop)
        ev.set()
        assert (yield from t) == 1

    @asyncio.coroutine
    def test_cancel_waiters(self, loop):
        ev = EventResultOrError(loop=loop)

        @asyncio.coroutine
        def c():
            yield from ev.wait()

        t1 = helpers.ensure_future(c(), loop=loop)
        t2 = helpers.ensure_future(c(), loop=loop)
        yield from asyncio.sleep(0, loop=loop)
        ev.cancel()
        ev.set()

        with pytest.raises(asyncio.futures.CancelledError):
            yield from t1

        with pytest.raises(asyncio.futures.CancelledError):
            yield from t2
