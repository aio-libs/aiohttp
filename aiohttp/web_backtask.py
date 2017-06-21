import asyncio
import async_timeout


class TaskWrapper:
    __slots__ = ('_task', '_manager')

    def __init__(self, task, manager):
        self._task = task
        self._manager = manager

    @property
    def task(self):
        return self._task

    def __await__(self):
        return self._task.__await__()


class BackTaskManager:
    def __init__(self, *, loop):
        self._loop = loop
        self._tasks = set()

    def exec(self, coro):
        task = self._loop.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._on_complete)
        return task

    def __iter__(self):
        return iter(list(self._tasks))

    def __len__(self):
        return len(self._tasks)

    async def wait(self, timeout=None):
        """Wait for completion"""
        with async_timeout.timeout(timeout):
            asyncio.wait(self._tasks)

    def cancel(self):
        for task in self._tasks:
            task.cancel()

    def _on_complete(self, task):
        self._tasks.remove(task)

    def default_error_handler(self, task):
        context = {'message': ("Task {!r} has failed with exception "
                               "but the error was not "
                               "explicitly handled".format(task)),
                   'task': task}
        self._loop.call_exception_handler(context)
