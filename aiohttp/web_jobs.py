import asyncio
import traceback
import sys
from collections.abc import Container

import async_timeout


class Job:
    __slots__ = ('_task', '_manager', '_loop', '_explicit_await',
                 '_source_traceback')

    def __init__(self, coro, manager, loop):
        self._loop = loop
        self._task = task = self._loop.create_task(coro)
        self._explicit_await = False
        self._manager = manager

        if loop.get_debug():
            self._source_traceback = traceback.extract_stack(sys._getframe(2))

        task.add_done_callback(self._done_callback)
        manager._jobs.add(self)

    def __repr__(self):
        return '<Job {!r}>'.format(self._task)

    @asyncio.coroutine
    def wait(self, timeout=None):
        self._explicit_await = True
        try:
            with async_timeout.timeout(timeout=timeout, loop=self._loop):
                return (yield from self._task)
        except asyncio.TimeoutError as exc:
            yield from self.close()
            raise exc

    @asyncio.coroutine
    def close(self):
        if self._task is None:
            return
        self._task.cancel()
        try:
            with async_timeout.timeout(timeout=self._manager._timeout,
                                       loop=self._loop):
                yield from self._task
        except asyncio.CancelledError:
            pass

    def _done_callback(self, task):
        self._manager._jobs.remove(self)
        self._manager = None  # drop backref
        self._task = None
        # TODO: process task exception
        exc = task.exception()
        if exc is not None and not self._explicit_await:
            context = {'message': "Job processing failed",
                       'job': self,
                       'exception': exc}
            if self._source_traceback is not None:
                context['source_traceback'] = self._source_traceback
            self._manager.call_exception_handler(context)


class JobManager(Container):
    def __init__(self, *, loop, timeout=0.1):
        self._loop = loop
        self._jobs = set()
        self._timeout = timeout
        self._exception_handler = None

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
        yield from asyncio.wait([job.wait(timeout) for job in self._jobs],
                                loop=self._loop)

    @asyncio.coroutine
    def close(self):
        yield from asyncio.wait([job.close() for job in self._jobs],
                                loop=self._loop)

    def default_exception_handler(self, context):
        self._loop.call_exception_handler(context)

    def call_exception_handler(self, context):
        handler = self._exception_handler
        if handler is None:
            handler = self.default_exception_handler
        return handler(context)

    def get_exception_handler(self):
        return self._exception_handler

    def set_exception_handler(self, handler):
        if handler is not None and not callable(handler):
            raise TypeError('A callable object or None is expected, '
                            'got {!r}'.format(handler))
        self._exception_handler = handler

    def get_timeout(self):
        return self._timeout

    def set_timeout(self, timeout):
        self._timeout = timeout
