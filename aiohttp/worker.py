"""Async gunicorn worker for aiohttp.web"""

import asyncio
import logging
import os
import signal
import sys
import gunicorn.workers.base as base

__all__ = ('GunicornWebWorker',)


class GunicornWebWorker(base.Worker):

    def __init__(self, *args, **kw):  # pragma: no cover
        super().__init__(*args, **kw)

        self.servers = {}
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

    def make_handler(self, app, host, port):
        if hasattr(self.cfg, 'debug'):
            is_debug = self.cfg.debug
        else:
            is_debug = self.log.loglevel == logging.DEBUG

        return app.make_handler(
            host=host,
            port=port,
            logger=self.log,
            debug=is_debug,
            timeout=self.cfg.timeout,
            keep_alive=self.cfg.keepalive,
            access_log=self.log.access_log,
            access_log_format=self.cfg.access_log_format)

    @asyncio.coroutine
    def close(self):
        if self.servers:
            servers = self.servers
            self.servers = None

            # stop accepting connections
            for server, handler in servers.items():
                self.log.info("Stopping server: %s, connections: %s",
                              self.pid, len(handler.connections))
                server.close()

            # stop alive connections
            tasks = [
                handler.finish_connections(
                    timeout=self.cfg.graceful_timeout / 100 * 95)
                for handler in servers.values()]
            yield from asyncio.wait(tasks, loop=self.loop)

            # stop application
            yield from self.wsgi.finish()

    @asyncio.coroutine
    def _run(self):
        for sock in self.sockets:
            handler = self.make_handler(self.wsgi, *sock.cfg_addr)
            srv = yield from self.loop.create_server(handler, sock=sock.sock)
            self.servers[srv] = handler

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
        signal.siginterrupt(signal.SIGTERM, False)
        signal.siginterrupt(signal.SIGUSR1, False)

    def handle_quit(self, sig, frame):
        self.alive = False

    def handle_abort(self, sig, frame):
        self.alive = False
        self.exit_code = 1
