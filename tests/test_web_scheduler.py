import asyncio
from unittest import mock

import pytest

from aiohttp.helpers import create_future
from aiohttp.web_scheduler import Scheduler


@pytest.fixture
def scheduler(loop):
    ret = Scheduler(loop=loop)
    yield ret
    loop.run_until_complete(ret.close())


def test_ctor(scheduler):
    assert len(scheduler) == 0


@asyncio.coroutine
def test_run(scheduler, loop):
    @asyncio.coroutine
    def coro():
        yield from asyncio.sleep(1, loop=loop)
    job = yield from scheduler.run(coro())
    assert not job.closed

    assert len(scheduler) == 1
    assert list(scheduler) == [job]
    assert job in scheduler


@asyncio.coroutine
def test_run_retval(scheduler, loop):
    @asyncio.coroutine
    def coro():
        return 1
    job = yield from scheduler.run(coro())
    ret = yield from job.wait()
    assert ret == 1

    assert job.closed

    assert len(scheduler) == 0
    assert list(scheduler) == []
    assert job not in scheduler


@asyncio.coroutine
def test_exception_in_explicit_waiting(scheduler, loop):
    @asyncio.coroutine
    def coro():
        yield from asyncio.sleep(0, loop=loop)
        raise RuntimeError()

    exc_handler = mock.Mock()
    scheduler.set_exception_handler(exc_handler)
    job = yield from scheduler.run(coro())

    with pytest.raises(RuntimeError):
        yield from job.wait()

    assert job.closed

    assert len(scheduler) == 0
    assert list(scheduler) == []
    assert job not in scheduler
    assert not exc_handler.called


@asyncio.coroutine
def test_exception_non_waited_job(scheduler, loop):
    exc = RuntimeError()

    @asyncio.coroutine
    def coro():
        yield from asyncio.sleep(0, loop=loop)
        raise exc

    exc_handler = mock.Mock()
    scheduler.set_exception_handler(exc_handler)
    yield from scheduler.run(coro())
    assert len(scheduler) == 1

    yield from asyncio.sleep(0.05, loop=loop)

    assert len(scheduler) == 0

    expect = {'exception': exc,
              'job': mock.ANY,
              'message': 'Job processing failed'}
    if loop.get_debug():
        expect['source_traceback'] = mock.ANY
    exc_handler.assert_called_with(scheduler, expect)


def test_close_timeout(scheduler):
    assert scheduler.close_timeout == 0.1
    scheduler.close_timeout = 1
    assert scheduler.close_timeout == 1


@asyncio.coroutine
def test_job_repr(scheduler, loop):
    @asyncio.coroutine
    def coro():
        return

    job = yield from scheduler.run(coro())
    assert repr(job).startswith('<Job')
    assert repr(job).endswith('>')


@asyncio.coroutine
def test_scheduler_repr(scheduler, loop):
    @asyncio.coroutine
    def coro():
        return

    assert repr(scheduler) == '<Scheduler jobs=0>'

    yield from scheduler.run(coro())
    assert repr(scheduler) == '<Scheduler jobs=1>'

    yield from scheduler.close()
    assert repr(scheduler) == '<Scheduler closed jobs=0>'


@asyncio.coroutine
def test_close_jobs(scheduler, loop):
    @asyncio.coroutine
    def coro():
        yield from asyncio.sleep(1, loop=loop)

    assert not scheduler.closed

    job = yield from scheduler.run(coro())
    yield from scheduler.close()
    assert job.closed
    assert scheduler.closed
    assert len(scheduler) == 0
    assert scheduler.active_count == 0
    assert scheduler.pending_count == 0


def test_exception_handler_api(scheduler):
    assert scheduler.get_exception_handler() is None
    handler = mock.Mock()
    scheduler.set_exception_handler(handler)
    assert scheduler.get_exception_handler() is handler
    with pytest.raises(TypeError):
        scheduler.set_exception_handler(1)
    scheduler.set_exception_handler(None)
    assert scheduler.get_exception_handler() is None


def test_exception_handler_default(scheduler, loop):
    handler = mock.Mock()
    loop.set_exception_handler(handler)
    d = {'a': 'b'}
    scheduler.call_exception_handler(d)
    handler.assert_called_with(loop, d)


@asyncio.coroutine
def test_wait_with_timeout(scheduler, loop):
    @asyncio.coroutine
    def coro():
        yield from asyncio.sleep(1, loop=loop)

    job = yield from scheduler.run(coro())
    with pytest.raises(asyncio.TimeoutError):
        yield from job.wait(0.01)
    assert job.closed
    assert len(scheduler) == 0


@asyncio.coroutine
def test_timeout_on_closing(scheduler, loop):

    fut1 = create_future(loop)
    fut2 = create_future(loop)

    @asyncio.coroutine
    def coro():
        try:
            yield from fut1
        except asyncio.CancelledError:
            yield from fut2

    exc_handler = mock.Mock()
    scheduler.set_exception_handler(exc_handler)
    scheduler.close_timeout = 0.01
    job = yield from scheduler.run(coro())
    yield from asyncio.sleep(0.001, loop=loop)
    yield from job.close()
    assert job.closed
    assert fut1.cancelled()
    expect = {'message': 'Job closing timed out',
              'job': job,
              'exception': mock.ANY}
    if loop.get_debug():
        expect['source_traceback'] = mock.ANY
    exc_handler.assert_called_with(scheduler, expect)


def test_concurrency(scheduler):
    assert scheduler.concurrency == 100
    scheduler.concurrency = 2
    assert scheduler.concurrency == 2


@asyncio.coroutine
def test_scheduler_councurrency_limit(scheduler, loop):
    @asyncio.coroutine
    def coro(fut):
        yield from fut

    scheduler.concurrency = 1
    assert scheduler.active_count == 0
    assert scheduler.pending_count == 0

    fut1 = create_future(loop)
    job1 = yield from scheduler.run(coro(fut1))

    assert scheduler.active_count == 1
    assert scheduler.pending_count == 0
    assert 'pending' not in repr(job1)
    assert 'closed' not in repr(job1)

    fut2 = create_future(loop)
    job2 = yield from scheduler.run(coro(fut2))

    assert scheduler.active_count == 1
    assert scheduler.pending_count == 1
    assert 'pending' in repr(job2)
    assert 'closed' not in repr(job2)

    fut1.set_result(None)
    yield from job1.wait()

    assert scheduler.active_count == 1
    assert scheduler.pending_count == 0
    assert 'pending' not in repr(job1)
    assert 'closed' in repr(job1)
    assert 'pending' not in repr(job2)
    assert 'closed' not in repr(job2)

    fut2.set_result(None)
    yield from job2.wait()

    assert scheduler.active_count == 0
    assert scheduler.pending_count == 0
    assert 'pending' not in repr(job1)
    assert 'closed' in repr(job1)
    assert 'pending' not in repr(job2)
    assert 'closed' in repr(job2)


@asyncio.coroutine
def test_resume_closed_task(scheduler, loop):
    @asyncio.coroutine
    def coro(fut):
        yield from fut

    scheduler.concurrency = 1
    assert scheduler.active_count == 0

    fut1 = create_future(loop)
    job1 = yield from scheduler.run(coro(fut1))

    assert scheduler.active_count == 1

    fut2 = create_future(loop)
    job2 = yield from scheduler.run(coro(fut2))

    assert scheduler.active_count == 1

    yield from job2.close()
    assert job2.closed
    assert 'closed' in repr(job2)
    assert 'pending' not in repr(job2)

    fut1.set_result(None)
    yield from job1.wait()

    assert scheduler.active_count == 0
    assert len(scheduler) == 0


@asyncio.coroutine
def test_concurreny_disabled(scheduler, loop):
    fut1 = create_future(loop)
    fut2 = create_future(loop)

    @asyncio.coroutine
    def coro():
        fut1.set_result(None)
        yield from fut2

    scheduler.concurrency = None
    job = yield from scheduler.run(coro())
    yield from fut1
    assert scheduler.active_count == 1

    fut2.set_result(None)
    yield from job.wait()
    assert scheduler.active_count == 0
