import asyncio
from unittest import mock

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
    assert job in runner


@asyncio.coroutine
def test_exec_retval(runner, loop):
    @asyncio.coroutine
    def coro():
        return 1
    job = runner.exec(coro())
    ret = yield from job.wait()
    assert ret == 1

    assert job.done()

    assert len(runner) == 0
    assert list(runner) == []
    assert job not in runner


@asyncio.coroutine
def test_exception_in_explicit_waiting(runner, loop):
    @asyncio.coroutine
    def coro():
        yield from asyncio.sleep(0, loop=loop)
        raise RuntimeError()

    exc_handler = mock.Mock()
    runner.set_exception_handler(exc_handler)
    job = runner.exec(coro())

    with pytest.raises(RuntimeError):
        yield from job.wait()

    assert job.done()

    assert len(runner) == 0
    assert list(runner) == []
    assert job not in runner
    assert not exc_handler.called


@asyncio.coroutine
def test_exception_non_waited_job(runner, loop):
    exc = RuntimeError()

    @asyncio.coroutine
    def coro():
        yield from asyncio.sleep(0, loop=loop)
        raise exc

    exc_handler = mock.Mock()
    runner.set_exception_handler(exc_handler)
    runner.exec(coro())
    assert len(runner) == 1

    yield from runner.wait()

    assert len(runner) == 0

    expect = {'exception': exc,
              'job': mock.ANY,
              'message': 'Job processing failed'}
    if loop.get_debug():
        expect['source_traceback'] = mock.ANY
    exc_handler.assert_called_with(expect)
