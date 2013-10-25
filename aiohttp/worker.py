"""Async gunicorn worker."""
import os
import asyncio
import gunicorn.workers.base as base

from aiohttp.wsgi import WSGIServerHttpProtocol


class AsyncGunicornWorker(base.Worker):

    def __init__(self, *args, **kw):  # pragma: no cover
        super().__init__(*args, **kw)
        self.servers = []

    def init_process(self):
        # create new event_loop after fork
        asyncio.get_event_loop().close()

        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        super().init_process()

    def run(self):
        self._runner = asyncio.async(self._run(), loop=self.loop)

        try:
            self.loop.run_until_complete(self._runner)
        finally:
            self.loop.close()

    def factory(self):
        return WSGIServerHttpProtocol(
            self.wsgi, loop=self.loop,
            log=self.log,
            access_log=self.log.access_log,
            access_log_format=self.cfg.access_log_format)

    @asyncio.coroutine
    def _run(self):
        def add_server(t):
            self.servers.append(t.result())

        for sock in self.sockets:
            t = asyncio.async(
                self.loop.create_server(self.factory, sock=sock.sock))
            t.add_done_callback(add_server)

        # If our parent changed then we shut down.
        pid = os.getpid()
        try:
            while self.alive:
                self.notify()

                if pid == os.getpid() and self.ppid != os.getppid():
                    self.log.info("Parent changed, shutting down: %s", self)
                    break

                yield from asyncio.sleep(1.0)
        except KeyboardInterrupt:
            pass

        for server in self.servers:
            server.close()
