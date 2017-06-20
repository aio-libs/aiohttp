import asyncio
import async_timeout


class BackgroundManager:
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

    def count(self):
        return len(self._tasks)

    def __len__(self):
        return self.count()

    async def wait(self, timeout=None):
        """Wait for completion"""
        with async_timeout.timeout(timeout):
            asyncio.wait(self._tasks)

    def cancel(self):
        for task in self._tasks:
            task.cancel()

    def _on_complete(self, task):
        self._tasks.remove(task)
