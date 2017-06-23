import asyncio
import sys
import traceback
from collections.abc import Container

import async_timeout


def create_task(coro, loop):
    return loop.create_task(coro)


class Job:
    __slots__ = ('_task', '_manager', '_loop', '_explicit_wait',
                 '_source_traceback')

    def __init__(self, coro, manager, loop):
        self._loop = loop
        self._task = task = create_task(coro, loop)
        self._explicit_wait = False
        self._manager = manager

        if loop.get_debug():
            self._source_traceback = traceback.extract_stack(sys._getframe(2))
        else:
            self._source_traceback = None

        task.add_done_callback(self._done_callback)
        manager._jobs.add(self)

    def __repr__(self):
        return '<Job {!r}>'.format(self._task)

    @asyncio.coroutine
    def wait(self, timeout=None):
        self._explicit_wait = True
        return (yield from self._wait(timeout))

    @asyncio.coroutine
    def _wait(self, timeout):
        try:
            with async_timeout.timeout(timeout=timeout, loop=self._loop):
                return (yield from self._task)
        except asyncio.TimeoutError as exc:
            yield from self.close()
            raise exc

    def done(self):
        return self._task.done()

    @asyncio.coroutine
    def close(self):
        self._task.cancel()
        try:
            with async_timeout.timeout(timeout=self._manager._timeout,
                                       loop=self._loop):
                yield from self._task
        except asyncio.CancelledError:
            pass
        except asyncio.TimeoutError as exc:
            context = {'message': "Job closing reached timeout",
                       'job': self,
                       'exception': exc}
            if self._source_traceback is not None:
                context['source_traceback'] = self._source_traceback
            self._manager.call_exception_handler(context)

    def _done_callback(self, task):
        runner = self._manager
        runner._jobs.remove(self)
        exc = task.exception()
        if exc is not None and not self._explicit_wait:
            context = {'message': "Job processing failed",
                       'job': self,
                       'exception': exc}
            if self._source_traceback is not None:
                context['source_traceback'] = self._source_traceback
            runner.call_exception_handler(context)
            runner._failed_tasks.put_nowait(task)
        self._manager = None  # drop backref


class JobRunner(Container):
    def __init__(self, *, loop, timeout=0.1):
        self._loop = loop
        self._jobs = set()
        self._timeout = timeout
        self._exception_handler = None
        self._failed_tasks = asyncio.Queue(loop=loop)
        self._failed_waiter = create_task(self._wait_failed(), loop)

    def exec(self, coro):
        job = Job(coro, self, self._loop)
        return job

    def __iter__(self):
        return iter(list(self._jobs))

    def __len__(self):
        return len(self._jobs)

    def __contains__(self, job):
        return job in self._jobs

    @asyncio.coroutine
    def wait(self, timeout=None):
        """Wait for completion"""
        jobs = self._jobs
        if not jobs:
            return
        yield from asyncio.gather(*[job._wait(timeout) for job in jobs],
                                  loop=self._loop, return_exceptions=True)

    @asyncio.coroutine
    def close(self):
        jobs = self._jobs
        if jobs:
            yield from asyncio.gather(*[job.close() for job in jobs],
                                      loop=self._loop, return_exceptions=True)
        self._failed_tasks.put_nowait(None)
        yield from self._failed_waiter

    def get_timeout(self):
        return self._timeout

    def set_timeout(self, timeout):
        self._timeout = timeout

    def call_exception_handler(self, context):
        handler = self._exception_handler
        if handler is None:
            handler = self._loop.call_exception_handler
        return handler(context)

    def get_exception_handler(self):
        return self._exception_handler

    def set_exception_handler(self, handler):
        if handler is not None and not callable(handler):
            raise TypeError('A callable object or None is expected, '
                            'got {!r}'.format(handler))
        self._exception_handler = handler

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
