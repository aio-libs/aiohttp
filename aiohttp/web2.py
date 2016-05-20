"""HTTP/2 version of classes from web.py"""

import asyncio

import aiohttp.abc
import aiohttp.hdrs
import aiohttp.web
import aiohttp.web_exceptions
import aiohttp.web_reqrep
import aiohttp.server2


class Http2RequestHandler(aiohttp.server2.ServerHTTP2Protocol):

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
    def handle_request(self, message, payload, stream_id):
        if self.access_log:
            now = self._loop.time()

        app = self._app
        request = aiohttp.web_reqrep.Request(
            app, message, payload,
            self.transport, self.reader, self.writer,
            secure_proxy_ssl_header=self._secure_proxy_ssl_header,
            h2_conn=self._conn, h2_stream_id=stream_id)
        self._meth = request.method
        self._path = request.path
        try:
            match_info = yield from self._router.resolve(request)

            assert isinstance(match_info, aiohttp.abc.AbstractMatchInfo), \
                match_info

            resp = None
            request._match_info = match_info
            expect = request.headers.get(aiohttp.hdrs.EXPECT)
            if expect:
                resp = (
                    yield from match_info.expect_handler(request))

            if resp is None:
                handler = match_info.handler
                for factory in reversed(self._middlewares):
                    handler = yield from factory(app, handler)
                resp = yield from handler(request)

            assert isinstance(resp, aiohttp.web_reqrep.StreamResponse), \
                ("Handler {!r} should return response instance, "
                 "got {!r} [middlewares {!r}]").format(
                     match_info.handler, type(resp), self._middlewares)
        except aiohttp.web_exceptions.HTTPException as exc:
            resp = exc

        resp_msg = yield from resp.prepare(request)
        yield from resp.write_eof()

        # notify server about keep-alive
        self.keep_alive(resp_msg.keep_alive())

        # log access
        if self.access_log:
            self.log_access(message, None, resp_msg, self._loop.time() - now)

        # for repr
        self._meth = 'none'
        self._path = 'none'


class Http2RequestHandlerFactory(aiohttp.web.RequestHandlerFactory):
    def __init__(self, *args, **kwargs):
        kwargs['handler'] = Http2RequestHandler
        super().__init__(*args, **kwargs)
