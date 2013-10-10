"""Async gunicorn worker."""
import os
import tulip
import gunicorn.workers.base as base

from asynchttp.wsgi import WSGIServerHttpProtocol


class AsyncGunicornWorker(base.Worker):

    def init_process(self):
        # create new event_loop after fork
        tulip.get_event_loop().close()

        self.loop = tulip.new_event_loop()
        tulip.set_event_loop(self.loop)

        super().init_process()

    def run(self):
        self._runner = tulip.async(self._run(), loop=self.loop)

        try:
            self.loop.run_until_complete(self._runner)
        finally:
            self.loop.close()

    def factory(self):
        return WSGIServerHttpProtocol(self.wsgi, loop=self.loop)

    @tulip.coroutine
    def _run(self):
        servers = []
        def add_server(t):
            servers.append(t.result())

        for sock in self.sockets:
            t = tulip.async(
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

                yield from tulip.sleep(1.0)
        except KeyboardInterrupt:
            pass

        for server in servers:
            server.close()
