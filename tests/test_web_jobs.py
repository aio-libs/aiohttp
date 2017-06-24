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
    assert not job.closed

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

    assert job.closed

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

    assert job.closed

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

    yield from asyncio.sleep(0.01, loop=loop)

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

    assert repr(runner) == '<JobRunner jobs=0>'

    runner.exec(coro())
    assert repr(runner) == '<JobRunner jobs=1>'

    yield from runner.close()
    assert repr(runner) == '<JobRunner closed jobs=0>'


@asyncio.coroutine
def test_close_jobs(runner, loop):
    @asyncio.coroutine
    def coro():
        yield from asyncio.sleep(1, loop=loop)

    assert not runner.closed

    job = runner.exec(coro())
    yield from runner.close()
    assert job.closed
    assert runner.closed


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
    assert job.closed
    assert len(runner) == 0


@asyncio.coroutine
def test_timeout_on_closing(runner, loop):

    fut1 = create_future(loop)
    fut2 = create_future(loop)

    @asyncio.coroutine
    def coro():
        try:
            yield from fut1
        except asyncio.CancelledError:
            yield from fut2

    exc_handler = mock.Mock()
    runner.set_exception_handler(exc_handler)
    runner.close_timeout = 0.01
    job = runner.exec(coro())
    yield from asyncio.sleep(0.001, loop=loop)
    yield from job.close()
    assert job.closed
    assert fut1.cancelled()
    expect = {'message': 'Job closing timed out',
              'job': job,
              'exception': mock.ANY}
    if loop.get_debug():
        expect['source_traceback'] = mock.ANY
    exc_handler.assert_called_with(runner, expect)


def test_concurrency(runner):
    assert runner.concurrency == 100
    runner.concurrency = 2
    assert runner.concurrency == 2


@asyncio.coroutine
def test_runner_councurrency_limit(runner, loop):
    @asyncio.coroutine
    def coro(fut):
        yield from fut

    runner.concurrency = 1
    assert runner.active_count == 0

    fut1 = create_future(loop)
    job1 = runner.exec(coro(fut1))

    assert runner.active_count == 1
    assert 'pending' not in repr(job1)
    assert 'closed' not in repr(job1)

    fut2 = create_future(loop)
    job2 = runner.exec(coro(fut2))

    assert runner.active_count == 1
    assert 'pending' in repr(job2)
    assert 'closed' not in repr(job2)

    fut1.set_result(None)
    yield from job1.wait()

    assert runner.active_count == 1
    assert 'pending' not in repr(job1)
    assert 'closed' in repr(job1)
    assert 'pending' not in repr(job2)
    assert 'closed' not in repr(job2)

    fut2.set_result(None)
    yield from job2.wait()

    assert runner.active_count == 0
    assert 'pending' not in repr(job1)
    assert 'closed' in repr(job1)
    assert 'pending' not in repr(job2)
    assert 'closed' in repr(job2)


@asyncio.coroutine
def test_resume_closed_task(runner, loop):
    @asyncio.coroutine
    def coro(fut):
        yield from fut

    runner.concurrency = 1
    assert runner.active_count == 0

    fut1 = create_future(loop)
    job1 = runner.exec(coro(fut1))

    assert runner.active_count == 1

    fut2 = create_future(loop)
    job2 = runner.exec(coro(fut2))

    assert runner.active_count == 1

    yield from job2.close()
    assert job2.closed
    assert 'closed' in repr(job2)
    assert 'pending' not in repr(job2)

    fut1.set_result(None)
    yield from job1.wait()

    assert runner.active_count == 0
    assert len(runner) == 0
