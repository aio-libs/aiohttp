import asyncio
import pytest


from aiohttp.web_jobs import JobRunner


@pytest.fixture
def runner(loop):
    ret = JobRunner(loop=loop)
    yield ret
    loop.run_until_complete(ret.close())


def test_ctor(runner):
    assert len(runner) == 0


def test_exec(runner, loop):
    @asyncio.coroutine
    def coro():
        yield from asyncio.sleep(1, loop=loop)
    job = runner.exec(coro())
    assert not job.done()

    assert len(runner) == 1
    assert list(runner) == [job]
