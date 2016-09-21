"""Async gunicorn worker for aiohttp.web"""

import asyncio
import os
import re
import signal
import ssl
import sys

import gunicorn.workers.base as base
from gunicorn.config import AccessLogFormat as GunicornAccessLogFormat

from aiohttp.helpers import AccessLogger, ensure_future

__all__ = ('GunicornWebWorker', 'GunicornUVLoopWebWorker')


class GunicornWebWorker(base.Worker):

    DEFAULT_AIOHTTP_LOG_FORMAT = AccessLogger.LOG_FORMAT
    DEFAULT_GUNICORN_LOG_FORMAT = GunicornAccessLogFormat.default

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
        self.loop.run_until_complete(self.wsgi.startup())
        self._runner = ensure_future(self._run(), loop=self.loop)

        try:
            self.loop.run_until_complete(self._runner)
        finally:
            self.loop.close()

        sys.exit(self.exit_code)

    def make_handler(self, app):
        return app.make_handler(
            logger=self.log,
            slow_request_timeout=self.cfg.timeout,
            keepalive_timeout=self.cfg.keepalive,
            access_log=self.log.access_log,
            access_log_format=self._get_valid_log_format(
                self.cfg.access_log_format))

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
                yield from server.wait_closed()

            # send on_shutdown event
            yield from self.wsgi.shutdown()

            # stop alive connections
            tasks = [
                handler.finish_connections(
                    timeout=self.cfg.graceful_timeout / 100 * 95)
                for handler in servers.values()]
            yield from asyncio.gather(*tasks, loop=self.loop)

            # cleanup application
            yield from self.wsgi.cleanup()

    @asyncio.coroutine
    def _run(self):

        ctx = self._create_ssl_context(self.cfg) if self.cfg.is_ssl else None

        for sock in self.sockets:
            handler = self.make_handler(self.wsgi)
            srv = yield from self.loop.create_server(handler, sock=sock.sock,
                                                     ssl=ctx)
            self.servers[srv] = handler

        # If our parent changed then we shut down.
        pid = os.getpid()
        try:
            while self.alive:
                self.notify()

                cnt = sum(handler.requests_count
                          for handler in self.servers.values())
                if self.cfg.max_requests and cnt > self.cfg.max_requests:
                    self.alive = False
                    self.log.info("Max requests, shutting down: %s", self)

                elif pid == os.getpid() and self.ppid != os.getppid():
                    self.alive = False
                    self.log.info("Parent changed, shutting down: %s", self)
                else:
                    yield from asyncio.sleep(1.0, loop=self.loop)

        except BaseException:
            pass

        yield from self.close()

    def init_signals(self):
        # Set up signals through the event loop API.

        self.loop.add_signal_handler(signal.SIGQUIT, self.handle_quit,
                                     signal.SIGQUIT, None)

        self.loop.add_signal_handler(signal.SIGTERM, self.handle_exit,
                                     signal.SIGTERM, None)

        self.loop.add_signal_handler(signal.SIGINT, self.handle_quit,
                                     signal.SIGINT, None)

        self.loop.add_signal_handler(signal.SIGWINCH, self.handle_winch,
                                     signal.SIGWINCH, None)

        self.loop.add_signal_handler(signal.SIGUSR1, self.handle_usr1,
                                     signal.SIGUSR1, None)

        self.loop.add_signal_handler(signal.SIGABRT, self.handle_abort,
                                     signal.SIGABRT, None)

        # Don't let SIGTERM and SIGUSR1 disturb active requests
        # by interrupting system calls
        signal.siginterrupt(signal.SIGTERM, False)
        signal.siginterrupt(signal.SIGUSR1, False)

    def handle_quit(self, sig, frame):
        self.alive = False

    def handle_abort(self, sig, frame):
        self.alive = False
        self.exit_code = 1

    @staticmethod
    def _create_ssl_context(cfg):
        """ Creates SSLContext instance for usage in asyncio.create_server.

        See ssl.SSLSocket.__init__ for more details.
        """
        ctx = ssl.SSLContext(cfg.ssl_version)
        ctx.load_cert_chain(cfg.certfile, cfg.keyfile)
        ctx.verify_mode = cfg.cert_reqs
        if cfg.ca_certs:
            ctx.load_verify_locations(cfg.ca_certs)
        if cfg.ciphers:
            ctx.set_ciphers(cfg.ciphers)
        return ctx

    def _get_valid_log_format(self, source_format):
        if source_format == self.DEFAULT_GUNICORN_LOG_FORMAT:
            return self.DEFAULT_AIOHTTP_LOG_FORMAT
        elif re.search(r'%\([^\)]+\)', source_format):
            raise ValueError(
                "Gunicorn's style options in form of `%(name)s` are not "
                "supported for the log formatting. Please use aiohttp's "
                "format specification to configure access log formatting: "
                "http://aiohttp.readthedocs.io/en/stable/logging.html"
                "#format-specification"
            )
        else:
            return source_format


class GunicornUVLoopWebWorker(GunicornWebWorker):

    def init_process(self):
        import uvloop

        # Close any existing event loop before setting a
        # new policy.
        asyncio.get_event_loop().close()

        # Setup uvloop policy, so that every
        # asyncio.get_event_loop() will create an instance
        # of uvloop event loop.
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

        super().init_process()
