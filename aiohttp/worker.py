"""Async gunicorn worker for auihttp.wen.Application."""
__all__ = ['GunicornWebWorker']

import asyncio
import functools
import os
import signal
import sys
import gunicorn.workers.base as base


class GunicornWebWorker(base.Worker):

    def __init__(self, *args, **kw):  # pragma: no cover
        super().__init__(*args, **kw)

        self.servers = []
        self.exit_code = 0

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

        sys.exit(self.exit_code)

    def factory(self, app, host, port):
        return app.make_handler(
            host=host,
            port=port,
            log=self.log,
            debug=self.cfg.debug,
            keep_alive=self.cfg.keepalive,
            access_log=self.log.access_log,
            access_log_format=self.cfg.access_log_format)

    def get_factory(self, sock, host, port):
        return functools.partial(self.factory, self.wsgi, host, port)

    @asyncio.coroutine
    def close(self):
        if self.servers:
            self.log.info("Stopping server: %s, connections: %s",
                          self.pid, len(self.wsgi.connections))

            # stop accepting connections
            for server in self.servers:
                server.close()
            self.servers.clear()

            # stop alive connections
            yield from self.wsgi.finish_connections(
                timeout=self.cfg.graceful_timeout / 100 * 80)

            # stop application
            yield from self.wsgi.finish()

    @asyncio.coroutine
    def _run(self):
        for sock in self.sockets:
            factory = self.get_factory(sock.sock, *sock.cfg_addr)
            self.servers.append(
                (yield from self.loop.create_server(factory, sock=sock.sock)))

        # If our parent changed then we shut down.
        pid = os.getpid()
        try:
            while self.alive:
                self.notify()

                if pid == os.getpid() and self.ppid != os.getppid():
                    self.alive = False
                    self.log.info("Parent changed, shutting down: %s", self)
                else:
                    yield from asyncio.sleep(1.0, loop=self.loop)
        except (Exception, BaseException, GeneratorExit, KeyboardInterrupt):
            pass

        yield from self.close()

    def init_signal(self):
        # init new signaling
        self.loop.add_signal_handler(signal.SIGQUIT, self.handle_quit)
        self.loop.add_signal_handler(signal.SIGTERM, self.handle_exit)
        self.loop.add_signal_handler(signal.SIGINT, self.handle_quit)
        self.loop.add_signal_handler(signal.SIGWINCH, self.handle_winch)
        self.loop.add_signal_handler(signal.SIGUSR1, self.handle_usr1)
        self.loop.add_signal_handler(signal.SIGABRT, self.handle_abort)

        # Don't let SIGTERM and SIGUSR1 disturb active requests
        # by interrupting system calls
        if hasattr(signal, 'siginterrupt'):  # python >= 2.6
            signal.siginterrupt(signal.SIGTERM, False)
            signal.siginterrupt(signal.SIGUSR1, False)

    def handle_quit(self, sig, frame):
        self.alive = False

    def handle_abort(self, sig, frame):
        self.alive = False
        self.exit_code = 1
