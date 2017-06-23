import asyncio
from collections.abc impor Container

import async_timeout


class Job:
    __slots__ = ('_task', '_manager', '_loop', '_explicit_await')

    def __init__(self, coro, manager, loop):
        self._loop = loop
        self._task = task = self._loop.create_task(coro)
        self._explicit_await = False
        self._manager = manager

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
            yield from self.cancel()
            raise exc

    @asyncio.coroutine
    def cancel(self):
        if self._task is None:
            return
        self._task.cancel()
        # TODO: wait for actual cancellation
        try:
            with async_timeout.timeout(timeout=self._manager._closing_timeout,
                                       loop=self._loop):
                yield from self._task
        except asyncio.CancelledError:
            pass

    def _done_callback(self, task):
        self._manager._jobs.remove(self)
        self._manager = None  # drop backref
        self._task = None
        # TODO: process task exception


class JobManager(Container):
    def __init__(self, *, loop, cancellation_timeout=0.1):
        self._loop = loop
        self._jobs = set()
        self._cancellation_timeout = cancellation_timeout

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
    def cancel(self):
        yield from asyncio.wait([job.cancel() for job in self._jobs],
                                loop=self._loop)

    def default_error_handler(self, job):
        context = {'message': ("Job {!r} has failed with exception "
                               "but the error was not "
                               "explicitly handled".format(job)),
                   'job': job}
        self._loop.call_exception_handler(context)
