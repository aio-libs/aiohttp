import asyncio
from unittest import mock

import pytest

from aiohttp.helpers import create_future
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
    exc_handler.assert_called_with(runner, expect)


def test_close_timeout(runner):
    assert runner.close_timeout == 0.1
    runner.close_timeout = 1
    assert runner.close_timeout == 1


@asyncio.coroutine
def test_job_repr(runner, loop):
    @asyncio.coroutine
    def coro():
        return

    job = runner.exec(coro())
    assert repr(job).startswith('<Job')
    assert repr(job).endswith('>')


@asyncio.coroutine
def test_runner_repr(runner, loop):
    @asyncio.coroutine
    def coro():
        return

    assert repr(runner) == '<JobRunner: 0 jobs>'

    runner.exec(coro())
    assert repr(runner) == '<JobRunner: 1 jobs>'


@asyncio.coroutine
def test_wait_without_jobs(runner):
    yield from runner.wait()
    assert not runner


@asyncio.coroutine
def test_close_jobs(runner, loop):
    @asyncio.coroutine
    def coro():
        yield from asyncio.sleep(1, loop=loop)

    job = runner.exec(coro())
    yield from runner.close()
    assert job.done()


def test_exception_handler_api(runner):
    assert runner.get_exception_handler() is None
    handler = mock.Mock()
    runner.set_exception_handler(handler)
    assert runner.get_exception_handler() is handler
    with pytest.raises(TypeError):
        runner.set_exception_handler(1)
    runner.set_exception_handler(None)
    assert runner.get_exception_handler() is None


def test_exception_handler_default(runner, loop):
    handler = mock.Mock()
    loop.set_exception_handler(handler)
    d = {'a': 'b'}
    runner.call_exception_handler(d)
    handler.assert_called_with(loop, d)


@asyncio.coroutine
def test_wait_with_timeout(runner, loop):
    @asyncio.coroutine
    def coro():
        yield from asyncio.sleep(1, loop=loop)

    job = runner.exec(coro())
    with pytest.raises(asyncio.TimeoutError):
        yield from job.wait(0.01)
    assert job.done()
    assert len(runner) == 0


@asyncio.coroutine
def test_timeout_on_closing(runner, loop):

    @asyncio.coroutine
    def coro():
        try:
            yield from asyncio.shield(asyncio.sleep(1, loop=loop),
                                      loop=loop)
        except:
            import ipdb;ipdb.set_trace()
            print('1')
            yield from fut1
            print('2')
            fut2.set_result(None)

    exc_handler = mock.Mock()
    runner.set_exception_handler(exc_handler)
    runner.close_timeout = 0.01
    job = runner.exec(coro())
    yield from job.close()
    assert job.done()
    expect = {}
    assert exc_handler.called
    exc_handler.assert_called_with()#runner, expect)
