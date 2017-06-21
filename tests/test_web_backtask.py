import asyncio
import pytest


from aiohttp.web_backtask import BackTaskManager


@pytest.fixture
def mgr(loop):
    ret = BackTaskManager(loop=loop)
    yield ret
    ret.cancel()
    loop.run_until_complete(ret.wait())


def test_ctor(mgr):
    assert len(mgr) == 0


def test_exec(mgr, loop):
    @asyncio.coroutine
    def coro():
        yield from asyncio.sleep(1, loop=loop)
    task = mgr.exec(coro())
    assert not task.done()

    assert len(mgr) == 1
    assert list(mgr) == [task]
