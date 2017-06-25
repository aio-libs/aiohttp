import asyncio
import sys
import traceback
from collections import deque
from collections.abc import Container

import async_timeout

from .helpers import ensure_future


class Job:
    _source_traceback = None
    _closed = False
    _explicit_wait = False
    _task = None

    def __init__(self, coro, scheduler, loop):
        self._loop = loop
        self._coro = coro
        self._scheduler = scheduler

        if loop.get_debug():
            self._source_traceback = traceback.extract_stack(sys._getframe(2))

    def _start(self):
        assert not self._closed
        self._task = ensure_future(self._coro, loop=self._loop)
        self._task.add_done_callback(self._done_callback)

    def __repr__(self):
        info = []
        if self._closed:
            info.append('closed')
        elif self._task is None:
            info.append('pending')
        info = ' '.join(info)
        if info:
            info += ' '
        return '<Job {}coro=<{}>>'.format(info, self._coro)

    @asyncio.coroutine
    def wait(self, timeout=None):
        self._explicit_wait = True
        try:
            with async_timeout.timeout(timeout=timeout, loop=self._loop):
                return (yield from self._task)
        except asyncio.TimeoutError as exc:
            yield from self.close()
            raise exc

    @property
    def closed(self):
        return self._closed

    @asyncio.coroutine
    def close(self):
        if self._task is None:
            self._closed = True
            self._scheduler._done(self, True)
            self._scheduler = None
            return
        if self._closed:
            return
        self._task.cancel()
        # self._scheduler is None after _done_callback()
        scheduler = self._scheduler
        try:
            with async_timeout.timeout(timeout=self._scheduler._close_timeout,
                                       loop=self._loop):
                yield from self._task
        except asyncio.CancelledError:
            pass
        except asyncio.TimeoutError as exc:
            context = {'message': "Job closing timed out",
                       'job': self,
                       'exception': exc}
            if self._source_traceback is not None:
                context['source_traceback'] = self._source_traceback
            scheduler.call_exception_handler(context)

    def _done_callback(self, task):
        scheduler = self._scheduler
        scheduler._done(self, False)
        try:
            exc = task.exception()
        except asyncio.CancelledError:
            pass
        else:
            if exc is not None and not self._explicit_wait:
                context = {'message': "Job processing failed",
                           'job': self,
                           'exception': exc}
                if self._source_traceback is not None:
                    context['source_traceback'] = self._source_traceback
                scheduler.call_exception_handler(context)
                scheduler._failed_tasks.put_nowait(task)
        self._runner = None  # drop backref
        self._closed = True


class Scheduler(Container):
    def __init__(self, *, loop):
        self._loop = loop
        self._jobs = set()
        self._close_timeout = 0.1
        self._concurrency = 100
        self._exception_handler = None
        self._failed_tasks = asyncio.Queue(loop=loop)
        self._failed_waiter = ensure_future(self._wait_failed(), loop=loop)
        self._pending = deque()
        self._closed = False

    @asyncio.coroutine
    def run(self, coro):
        if self._closed:
            raise RuntimeError("Scheduling a new job after closing")
        job = Job(coro, self, self._loop)
        if self._concurrency is None or self.active_count < self._concurrency:
            job._start()
        else:
            self._pending.append(job)
        self._jobs.add(job)
        return job

    def __iter__(self):
        return iter(list(self._jobs))

    def __len__(self):
        return len(self._jobs)

    def __contains__(self, job):
        return job in self._jobs

    def __repr__(self):
        info = []
        if self._closed:
            info.append('closed')
        info = ' '.join(info)
        if info:
            info += ' '
        return '<Scheduler {}jobs={}>'.format(info, len(self))

    @property
    def closed(self):
        return self._closed

    @asyncio.coroutine
    def close(self):
        if self._closed:
            return
        self._closed = True
        jobs = self._jobs
        if jobs:
            yield from asyncio.gather(*[job.close() for job in jobs],
                                      loop=self._loop, return_exceptions=True)
        self._pending.clear()
        self._jobs.clear()
        self._failed_tasks.put_nowait(None)
        yield from self._failed_waiter

    @property
    def concurrency(self):
        return self._concurrency

    @concurrency.setter
    def concurrency(self, concurrency):
        self._concurrency = concurrency

    @property
    def active_count(self):
        return len(self._jobs) - len(self._pending)

    @property
    def pending_count(self):
        return len(self._pending)

    @property
    def close_timeout(self):
        return self._close_timeout

    @close_timeout.setter
    def close_timeout(self, timeout):
        self._close_timeout = timeout

    def call_exception_handler(self, context):
        handler = self._exception_handler
        if handler is None:
            handler = self._loop.call_exception_handler(context)
        else:
            handler(self, context)

    def get_exception_handler(self):
        return self._exception_handler

    def set_exception_handler(self, handler):
        if handler is not None and not callable(handler):
            raise TypeError('A callable object or None is expected, '
                            'got {!r}'.format(handler))
        self._exception_handler = handler

    def _done(self, job, pending):
        self._jobs.remove(job)
        if pending:
            self._pending.remove(job)
        while (self._pending and
               (self._concurrency is None or
                self.active_count < self._concurrency)):
            new_job = self._pending.popleft()
            if new_job.closed:
                continue
            new_job._start()

    @asyncio.coroutine
    def _wait_failed(self):
        # a coroutine for waiting failed tasks
        # without awaiting for failed tasks async raises a warning
        while True:
            task = yield from self._failed_tasks.get()
            if task is None:
                return  # closing
            try:
                yield from task
            except Exception as exc:
                # cleanup a warning
                # self.call_exception_handler() is already called
                # by Job._add_done_callback
                pass
