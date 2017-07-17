"""Tests of custom aiohttp locks implementations"""
import asyncio

from aiohttp import helpers
from aiohttp.locks import Event


class TestEvent:

    @asyncio.coroutine
    def test_set_exception(self, loop):
        ev = Event(loop=loop)

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
        yield from asyncio.sleep(0, loop=loop)
        assert t.result() == e

    @asyncio.coroutine
    def test_set(self, loop):
        ev = Event(loop=loop)

        @asyncio.coroutine
        def c():
            yield from ev.wait()
            return 1

        t = helpers.ensure_future(c(), loop=loop)
        yield from asyncio.sleep(0, loop=loop)
        ev.set()
        yield from asyncio.sleep(0, loop=loop)
        assert t.result() == 1

        # next lines help to get the 100% coverage.
        ev.set()
        ev.clear()
        t = helpers.ensure_future(c(), loop=loop)
        yield from asyncio.sleep(0, loop=loop)
        t.cancel()
        ev.set()

    @asyncio.coroutine
    def test_set_no_blocking(self, loop):
        ev = Event(loop=loop)
        ev.set()

        @asyncio.coroutine
        def c():
            yield from ev.wait()
            return 1

        t = helpers.ensure_future(c(), loop=loop)
        yield from asyncio.sleep(0, loop=loop)
        assert t.result() == 1

    @asyncio.coroutine
    def test_repr(self, loop):
        ev = Event(loop=loop)
        assert "waiters" not in repr(ev)

        @asyncio.coroutine
        def c():
            yield from ev.wait()

        helpers.ensure_future(c(), loop=loop)
        yield from asyncio.sleep(0, loop=loop)
        assert "waiters" in repr(ev)

    @asyncio.coroutine
    def test_is_set(self, loop):
        ev = Event(loop=loop)
        assert not ev.is_set()
