from . import web_reqrep
from . import web_exceptions
from . import web_urldispatcher
from . import web_ws
from .web_reqrep import *  # noqa
from .web_exceptions import *  # noqa
from .web_urldispatcher import *  # noqa
from .web_ws import *  # noqa
from .protocol import HttpVersion  # noqa

__all__ = (web_reqrep.__all__ +
           web_exceptions.__all__ +
           web_urldispatcher.__all__ +
           web_ws.__all__ +
           ('Application', 'RequestHandler',
            'RequestHandlerFactory', 'HttpVersion'))


import asyncio

from . import hdrs
from .abc import AbstractRouter, AbstractMatchInfo
from .log import web_logger
from .server import ServerHttpProtocol


class RequestHandler(ServerHttpProtocol):

    _meth = 'none'
    _path = 'none'

    def __init__(self, manager, app, router, *,
                 secure_proxy_ssl_header=None, **kwargs):
        super().__init__(**kwargs)

        self._manager = manager
        self._app = app
        self._router = router
        self._middlewares = app.middlewares
        self._secure_proxy_ssl_header = secure_proxy_ssl_header

    def __repr__(self):
        return "<{} {}:{} {}>".format(
            self.__class__.__name__, self._meth, self._path,
            'connected' if self.transport is not None else 'disconnected')

    def connection_made(self, transport):
        super().connection_made(transport)

        self._manager.connection_made(self, transport)

    def connection_lost(self, exc):
        self._manager.connection_lost(self, exc)

        super().connection_lost(exc)

    @asyncio.coroutine
    def handle_request(self, message, payload):
        if self.access_log:
            now = self._loop.time()

        app = self._app
        request = Request(
            app, message, payload,
            self.transport, self.reader, self.writer,
            secure_proxy_ssl_header=self._secure_proxy_ssl_header)
        self._meth = request.method
        self._path = request.path
        try:
            match_info = yield from self._router.resolve(request)

            assert isinstance(match_info, AbstractMatchInfo), match_info

            resp = None
            request._match_info = match_info
            expect = request.headers.get(hdrs.EXPECT)
            if expect and expect.lower() == "100-continue":
                resp = (
                    yield from match_info.route.handle_expect_header(request))

            if resp is None:
                handler = match_info.handler
                for factory in reversed(self._middlewares):
                    handler = yield from factory(app, handler)
                resp = yield from handler(request)

            assert isinstance(resp, StreamResponse), \
                ("Handler {!r} should return response instance, "
                 "got {!r} [middlewares {!r}]").format(
                     match_info.handler, type(resp), self._middlewares)
        except HTTPException as exc:
            resp = exc

        resp_msg = resp.start(request)
        yield from resp.write_eof()

        # notify server about keep-alive
        self.keep_alive(resp_msg.keep_alive())

        # log access
        if self.access_log:
            self.log_access(message, None, resp_msg, self._loop.time() - now)

        # for repr
        self._meth = 'none'
        self._path = 'none'


class RequestHandlerFactory:

    def __init__(self, app, router, *,
                 handler=RequestHandler, loop=None,
                 secure_proxy_ssl_header=None, **kwargs):
        self._app = app
        self._router = router
        self._handler = handler
        self._loop = loop
        self._connections = {}
        self._secure_proxy_ssl_header = secure_proxy_ssl_header
        self._kwargs = kwargs
        self._kwargs.setdefault('logger', app.logger)

    @property
    def secure_proxy_ssl_header(self):
        return self._secure_proxy_ssl_header

    @property
    def connections(self):
        return list(self._connections.keys())

    def connection_made(self, handler, transport):
        self._connections[handler] = transport

    def connection_lost(self, handler, exc=None):
        if handler in self._connections:
            del self._connections[handler]

    @asyncio.coroutine
    def finish_connections(self, timeout=None):
        # try to close connections in 90% of graceful timeout
        timeout90 = None
        if timeout:
            timeout90 = timeout / 100 * 90

        for handler in self._connections.keys():
            handler.closing(timeout=timeout90)

        @asyncio.coroutine
        def cleanup():
            sleep = 0.05
            while self._connections:
                yield from asyncio.sleep(sleep, loop=self._loop)
                if sleep < 5:
                    sleep = sleep * 2

        if timeout:
            try:
                yield from asyncio.wait_for(
                    cleanup(), timeout, loop=self._loop)
            except asyncio.TimeoutError:
                self._app.logger.warning(
                    "Not all connections are closed (pending: %d)",
                    len(self._connections))

        for transport in self._connections.values():
            transport.close()

        self._connections.clear()

    def __call__(self):
        return self._handler(
            self, self._app, self._router, loop=self._loop,
            secure_proxy_ssl_header=self._secure_proxy_ssl_header,
            **self._kwargs)


class Application(dict):

    def __init__(self, *, logger=web_logger, loop=None,
                 router=None, handler_factory=RequestHandlerFactory,
                 middlewares=()):
        if loop is None:
            loop = asyncio.get_event_loop()
        if router is None:
            router = UrlDispatcher()
        assert isinstance(router, AbstractRouter), router

        self._router = router
        self._handler_factory = handler_factory
        self._finish_callbacks = []
        self._loop = loop
        self.logger = logger

        for factory in middlewares:
            assert asyncio.iscoroutinefunction(factory), factory
        self._middlewares = list(middlewares)

    @property
    def router(self):
        return self._router

    @property
    def loop(self):
        return self._loop

    @property
    def middlewares(self):
        return self._middlewares

    def make_handler(self, **kwargs):
        return self._handler_factory(
            self, self.router, loop=self.loop, **kwargs)

    @asyncio.coroutine
    def finish(self):
        callbacks = self._finish_callbacks
        self._finish_callbacks = []

        for (cb, args, kwargs) in callbacks:
            try:
                res = cb(self, *args, **kwargs)
                if (asyncio.iscoroutine(res) or
                        isinstance(res, asyncio.Future)):
                    yield from res
            except Exception as exc:
                self._loop.call_exception_handler({
                    'message': "Error in finish callback",
                    'exception': exc,
                    'application': self,
                })

    def register_on_finish(self, func, *args, **kwargs):
        self._finish_callbacks.insert(0, (func, args, kwargs))

    def __call__(self):
        """gunicorn compatibility"""
        return self

    def __repr__(self):
        return "<Application>"
