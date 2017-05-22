"""Async gunicorn worker for aiohttp.web"""

import asyncio
import os
import re
import signal
import socket
import ssl
import sys

from gunicorn.config import AccessLogFormat as GunicornAccessLogFormat
from gunicorn.workers import base

from .helpers import AccessLogger, create_future, ensure_future


__all__ = ('GunicornWebWorker',
           'GunicornUVLoopWebWorker',
           'GunicornTokioWebWorker')


class GunicornWebWorker(base.Worker):

    DEFAULT_AIOHTTP_LOG_FORMAT = AccessLogger.LOG_FORMAT
    DEFAULT_GUNICORN_LOG_FORMAT = GunicornAccessLogFormat.default

    def __init__(self, *args, **kw):  # pragma: no cover
        super().__init__(*args, **kw)

        self.servers = {}
        self.exit_code = 0
        self._notify_waiter = None

    def init_process(self):
        # create new event_loop after fork
        asyncio.get_event_loop().close()

        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        super().init_process()

    def run(self):
        if hasattr(self.wsgi, 'startup'):
            self.loop.run_until_complete(self.wsgi.startup())
        self._runner = ensure_future(self._run(), loop=self.loop)

        try:
            self.loop.run_until_complete(self._runner)
        finally:
            self.loop.close()

        sys.exit(self.exit_code)

    def make_handler(self, app):
        if hasattr(self.wsgi, 'make_handler'):
            access_log = self.log.access_log if self.cfg.accesslog else None
            return app.make_handler(
                loop=self.loop,
                logger=self.log,
                slow_request_timeout=self.cfg.timeout,
                keepalive_timeout=self.cfg.keepalive,
                access_log=access_log,
                access_log_format=self._get_valid_log_format(
                    self.cfg.access_log_format))
        else:
            raise RuntimeError(
                "aiohttp.wsgi is not supported anymore, "
                "consider to switch to aiohttp.web.Application")

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
            if hasattr(self.wsgi, 'shutdown'):
                yield from self.wsgi.shutdown()

            # stop alive connections
            tasks = [
                handler.shutdown(
                    timeout=self.cfg.graceful_timeout / 100 * 95)
                for handler in servers.values()]
            yield from asyncio.gather(*tasks, loop=self.loop)

            # cleanup application
            if hasattr(self.wsgi, 'cleanup'):
                yield from self.wsgi.cleanup()

    @asyncio.coroutine
    def _run(self):

        ctx = self._create_ssl_context(self.cfg) if self.cfg.is_ssl else None

        for sock in self.sockets:
            handler = self.make_handler(self.wsgi)

            if hasattr(socket, 'AF_UNIX') and sock.family == socket.AF_UNIX:
                srv = yield from self.loop.create_unix_server(
                    handler, sock=sock.sock, ssl=ctx)
            else:
                srv = yield from self.loop.create_server(
                    handler, sock=sock.sock, ssl=ctx)
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
                    yield from self._wait_next_notify()

        except BaseException:
            pass

        yield from self.close()

    def _wait_next_notify(self):
        self._notify_waiter_done()

        self._notify_waiter = waiter = create_future(self.loop)
        self.loop.call_later(1.0, self._notify_waiter_done)

        return waiter

    def _notify_waiter_done(self):
        waiter = self._notify_waiter
        if waiter is not None and not waiter.done():
            waiter.set_result(True)

        self._notify_waiter = None

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

        # worker_int callback
        self.cfg.worker_int(self)

        # init closing process
        self._closing = ensure_future(self.close(), loop=self.loop)

        # close loop
        self.loop.call_later(0.1, self._notify_waiter_done)

    def handle_abort(self, sig, frame):
        self.alive = False
        self.exit_code = 1
        self.cfg.worker_abort(self)
        sys.exit(1)

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


class GunicornTokioWebWorker(GunicornWebWorker):

    def init_process(self):
        import tokio

        # Close any existing event loop before setting a
        # new policy.
        asyncio.get_event_loop().close()

        # Setup tokio policy, so that every
        # asyncio.get_event_loop() will create an instance
        # of tokio event loop.
        asyncio.set_event_loop_policy(tokio.EventLoopPolicy())

        super().init_process()
