"""Tests of custom aiohttp locks implementations"""
import asyncio

from aiohttp.locks import Event


class TestEvent:

    @asyncio.coroutine
    def test_set_exception(self):
        ev = Event()

        @asyncio.coroutine
        def c():
            try:
                yield from ev.wait()
            except Exception as e:
                return e
            return 1

        t = asyncio.ensure_future(c())
        yield from asyncio.sleep(0)
        e = Exception()
        ev.set(exc=e)
        yield from asyncio.sleep(0)
        assert t.result() == e

    @asyncio.coroutine
    def test_set(self):
        ev = Event()

        @asyncio.coroutine
        def c():
            yield from ev.wait()
            return 1

        t = asyncio.ensure_future(c())
        yield from asyncio.sleep(0)
        ev.set()
        yield from asyncio.sleep(0)
        assert t.result() == 1
