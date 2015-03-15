import abc
import asyncio
import collections
import mimetypes
import re
import os

from urllib.parse import urlencode

from . import hdrs
from .abc import AbstractRouter, AbstractMatchInfo
from .log import web_logger
from .protocol import HttpVersion, HttpVersion11
from .server import ServerHttpProtocol

from .web_exceptions import (HTTPException,
                             HTTPError,
                             HTTPRedirection,
                             HTTPSuccessful,
                             HTTPOk,
                             HTTPCreated,
                             HTTPAccepted,
                             HTTPNonAuthoritativeInformation,
                             HTTPNoContent,
                             HTTPResetContent,
                             HTTPPartialContent,
                             HTTPMultipleChoices,
                             HTTPMovedPermanently,
                             HTTPFound,
                             HTTPSeeOther,
                             HTTPNotModified,
                             HTTPUseProxy,
                             HTTPTemporaryRedirect,
                             HTTPClientError,
                             HTTPBadRequest,
                             HTTPUnauthorized,
                             HTTPPaymentRequired,
                             HTTPForbidden,
                             HTTPNotFound,
                             HTTPMethodNotAllowed,
                             HTTPNotAcceptable,
                             HTTPProxyAuthenticationRequired,
                             HTTPRequestTimeout,
                             HTTPConflict,
                             HTTPGone,
                             HTTPLengthRequired,
                             HTTPPreconditionFailed,
                             HTTPRequestEntityTooLarge,
                             HTTPRequestURITooLong,
                             HTTPUnsupportedMediaType,
                             HTTPRequestRangeNotSatisfiable,
                             HTTPExpectationFailed,
                             HTTPServerError,
                             HTTPInternalServerError,
                             HTTPNotImplemented,
                             HTTPBadGateway,
                             HTTPServiceUnavailable,
                             HTTPGatewayTimeout,
                             HTTPVersionNotSupported)

from .web_reqrep import Request, StreamResponse, Response
from .websocket import do_handshake, MSG_BINARY, MSG_CLOSE, MSG_PING, MSG_TEXT
from .errors import HttpProcessingError, WSClientDisconnectedError


__all__ = [
    'WSClientDisconnectedError',
    'Application',
    'HttpVersion',
    'RequestHandler',
    'RequestHandlerFactory',
    'Request',
    'StreamResponse',
    'Response',
    'WebSocketResponse',
    'UrlDispatcher',
    'UrlMappingMatchInfo',
    'HTTPException',
    'HTTPError',
    'HTTPRedirection',
    'HTTPSuccessful',
    'HTTPOk',
    'HTTPCreated',
    'HTTPAccepted',
    'HTTPNonAuthoritativeInformation',
    'HTTPNoContent',
    'HTTPResetContent',
    'HTTPPartialContent',
    'HTTPMultipleChoices',
    'HTTPMovedPermanently',
    'HTTPFound',
    'HTTPSeeOther',
    'HTTPNotModified',
    'HTTPUseProxy',
    'HTTPTemporaryRedirect',
    'HTTPClientError',
    'HTTPBadRequest',
    'HTTPUnauthorized',
    'HTTPPaymentRequired',
    'HTTPForbidden',
    'HTTPNotFound',
    'HTTPMethodNotAllowed',
    'HTTPNotAcceptable',
    'HTTPProxyAuthenticationRequired',
    'HTTPRequestTimeout',
    'HTTPConflict',
    'HTTPGone',
    'HTTPLengthRequired',
    'HTTPPreconditionFailed',
    'HTTPRequestEntityTooLarge',
    'HTTPRequestURITooLong',
    'HTTPUnsupportedMediaType',
    'HTTPRequestRangeNotSatisfiable',
    'HTTPExpectationFailed',
    'HTTPServerError',
    'HTTPInternalServerError',
    'HTTPNotImplemented',
    'HTTPBadGateway',
    'HTTPServiceUnavailable',
    'HTTPGatewayTimeout',
    'HTTPVersionNotSupported',
]


############################################################
# Server WebSocket
############################################################


class WebSocketResponse(StreamResponse):

    def __init__(self, *, protocols=()):
        super().__init__(status=101)
        self._protocols = protocols
        self._protocol = None
        self._writer = None
        self._reader = None
        self._closing = False
        self._loop = None
        self._closing_fut = None

    def start(self, request):
        # make pre-check to don't hide it by do_handshake() exceptions
        resp_impl = self._start_pre_check(request)
        if resp_impl is not None:
            return resp_impl

        try:
            status, headers, parser, writer, protocol = do_handshake(
                request.method, request.headers, request.transport,
                self._protocols)
        except HttpProcessingError as err:
            if err.code == 405:
                raise HTTPMethodNotAllowed(request.method, ['GET'])
            elif err.code == 400:
                raise HTTPBadRequest(text=err.message, headers=err.headers)
            else:  # pragma: no cover
                raise HTTPInternalServerError() from err

        if self.status != status:
            self.set_status(status)
        for k, v in headers:
            self.headers[k] = v
        self.force_close()

        resp_impl = super().start(request)

        self._reader = request._reader.set_parser(parser)
        self._writer = writer
        self._protocol = protocol
        self._loop = request.app.loop
        self._closing_fut = asyncio.Future(loop=self._loop)

        return resp_impl

    def can_start(self, request):
        if self._writer is not None:
            raise RuntimeError('Already started')
        try:
            _, _, _, _, protocol = do_handshake(
                request.method, request.headers, request.transport,
                self._protocols)
        except HttpProcessingError:
            return False, None
        else:
            return True, protocol

    @property
    def closing(self):
        return self._closing

    @property
    def protocol(self):
        return self._protocol

    def ping(self, message='b'):
        if self._writer is None:
            raise RuntimeError('Call .start() first')
        if self._closing:
            raise RuntimeError('websocket connection is closing')
        self._writer.ping(message)

    def pong(self, message='b'):
        # unsolicited pong
        if self._writer is None:
            raise RuntimeError('Call .start() first')
        if self._closing:
            raise RuntimeError('websocket connection is closing')
        self._writer.pong(message)

    def send_str(self, data):
        if self._writer is None:
            raise RuntimeError('Call .start() first')
        if self._closing:
            raise RuntimeError('websocket connection is closing')
        if not isinstance(data, str):
            raise TypeError('data argument must be str (%r)' % type(data))
        self._writer.send(data, binary=False)

    def send_bytes(self, data):
        if self._writer is None:
            raise RuntimeError('Call .start() first')
        if self._closing:
            raise RuntimeError('websocket connection is closing')
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError('data argument must be byte-ish (%r)' %
                            type(data))
        self._writer.send(data, binary=True)

    def close(self, *, code=1000, message=b''):
        if self._writer is None:
            raise RuntimeError('Call .start() first')
        if not self._closing:
            self._closing = True
            self._writer.close(code, message)
        else:
            raise RuntimeError('Already closing')

    @asyncio.coroutine
    def wait_closed(self):
        if self._closing_fut is None:
            raise RuntimeError('Call .start() first')
        yield from self._closing_fut

    @asyncio.coroutine
    def write_eof(self):
        if self._eof_sent:
            return
        if self._resp_impl is None:
            raise RuntimeError("Response has not been started")

        yield from self.wait_closed()
        self._eof_sent = True

    @asyncio.coroutine
    def receive_msg(self):
        if self._reader is None:
            raise RuntimeError('Call .start() first')
        while True:
            try:
                msg = yield from self._reader.read()
            except Exception as exc:
                self._closing_fut.set_exception(exc)
                raise

            if msg.tp == MSG_CLOSE:
                if self._closing:
                    exc = WSClientDisconnectedError(msg.data, msg.extra)
                    self._closing_fut.set_exception(exc)
                    raise exc
                else:
                    self._closing = True
                    self._writer.close(msg.data, msg.extra)
                    yield from self.drain()
                    exc = WSClientDisconnectedError(msg.data, msg.extra)
                    self._closing_fut.set_exception(exc)
                    raise exc
            elif not self._closing:
                if msg.tp == MSG_PING:
                    self._writer.pong(msg.data)
                elif msg.tp in (MSG_TEXT, MSG_BINARY):
                    return msg

    @asyncio.coroutine
    def receive_str(self):
        msg = yield from self.receive_msg()
        if msg.tp != MSG_TEXT:
            raise TypeError(
                "Received message {}:{!r} is not str".format(msg.tp, msg.data))
        return msg.data

    @asyncio.coroutine
    def receive_bytes(self):
        msg = yield from self.receive_msg()
        if msg.tp != MSG_BINARY:
            raise TypeError(
                "Received message {}:{!r} is not bytes".format(msg.tp,
                                                               msg.data))
        return msg.data

    def write(self, data):
        raise RuntimeError("Cannot call .write() for websocket")


############################################################
# UrlDispatcher implementation
############################################################


class UrlMappingMatchInfo(dict, AbstractMatchInfo):

    def __init__(self, match_dict, route):
        super().__init__(match_dict)
        self._route = route

    @property
    def handler(self):
        return self._route.handler

    @property
    def route(self):
        return self._route

    def __repr__(self):
        return "<MatchInfo {}: {}>".format(super().__repr__(), self._route)


@asyncio.coroutine
def defaultExpectHandler(request):
    """Default handler for Except: 100-continue"""
    if request.version == HttpVersion11:
        request.transport.write(b"HTTP/1.1 100 Continue\r\n\r\n")


class Route(metaclass=abc.ABCMeta):

    def __init__(self, method, handler, name, expect_handler=None):
        if expect_handler is None:
            expect_handler = defaultExpectHandler
        assert asyncio.iscoroutinefunction(expect_handler), \
            'Coroutine is expected, got {!r}'.format(expect_handler)

        self._method = method
        self._handler = handler
        self._name = name
        self._expect_handler = expect_handler

    @property
    def method(self):
        return self._method

    @property
    def handler(self):
        return self._handler

    @property
    def name(self):
        return self._name

    @abc.abstractmethod
    def match(self, path):
        """Return dict with info for given path or
        None if route cannot process path."""

    @abc.abstractmethod
    def url(self, **kwargs):
        """Construct url for route with additional params."""

    @asyncio.coroutine
    def handle_expect_header(self, request):
        return (yield from self._expect_handler(request))

    @staticmethod
    def _append_query(url, query):
        if query is not None:
            return url + "?" + urlencode(query)
        else:
            return url


class PlainRoute(Route):

    def __init__(self, method, handler, name, path, expect_handler=None):
        super().__init__(method, handler, name, expect_handler=expect_handler)
        self._path = path

    def match(self, path):
        # string comparison is about 10 times faster than regexp matching
        if self._path == path:
            return {}
        else:
            return None

    def url(self, *, query=None):
        return self._append_query(self._path, query)

    def __repr__(self):
        name = "'" + self.name + "' " if self.name is not None else ""
        return "<PlainRoute {name}[{method}] {path} -> {handler!r}".format(
            name=name, method=self.method, path=self._path,
            handler=self.handler)


class DynamicRoute(Route):

    def __init__(self, method, handler, name, pattern, formatter,
                 expect_handler=None):
        super().__init__(method, handler, name, expect_handler=expect_handler)
        self._pattern = pattern
        self._formatter = formatter

    def match(self, path):
        match = self._pattern.match(path)
        if match is None:
            return None
        else:
            return match.groupdict()

    def url(self, *, parts, query=None):
        url = self._formatter.format_map(parts)
        return self._append_query(url, query)

    def __repr__(self):
        name = "'" + self.name + "' " if self.name is not None else ""
        return ("<DynamicRoute {name}[{method}] {formatter} -> {handler!r}"
                .format(name=name, method=self.method,
                        formatter=self._formatter, handler=self.handler))


class StaticRoute(Route):

    limit = 8192

    def __init__(self, name, prefix, directory, expect_handler=None):
        assert prefix.startswith('/'), prefix
        assert prefix.endswith('/'), prefix
        super().__init__(
            'GET', self.handle, name, expect_handler=expect_handler)
        self._prefix = prefix
        self._prefix_len = len(self._prefix)
        self._directory = directory

    def match(self, path):
        if not path.startswith(self._prefix):
            return None
        return {'filename': path[self._prefix_len:]}

    def url(self, *, filename, query=None):
        while filename.startswith('/'):
            filename = filename[1:]
        url = self._prefix + filename
        return self._append_query(url, query)

    @asyncio.coroutine
    def handle(self, request):
        resp = StreamResponse()
        filename = request.match_info['filename']
        filepath = os.path.join(self._directory, filename)
        if '..' in filename:
            raise HTTPNotFound()
        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            raise HTTPNotFound()

        ct = mimetypes.guess_type(filename)[0]
        if not ct:
            ct = 'application/octet-stream'
        resp.content_type = ct

        file_size = os.stat(filepath).st_size
        single_chunk = file_size < self.limit

        if single_chunk:
            resp.content_length = file_size
        resp.start(request)

        with open(filepath, 'rb') as f:
            chunk = f.read(self.limit)
            if single_chunk:
                resp.write(chunk)
            else:
                while chunk:
                    resp.write(chunk)
                    chunk = f.read(self.limit)

        return resp

    def __repr__(self):
        name = "'" + self.name + "' " if self.name is not None else ""
        return "<StaticRoute {name}[{method}] {path} -> {directory!r}".format(
            name=name, method=self.method, path=self._prefix,
            directory=self._directory)


class _NotFoundMatchInfo(UrlMappingMatchInfo):

    def __init__(self):
        super().__init__({}, None)

    @property
    def handler(self):
        return self._not_found

    @property
    def route(self):
        return None

    @asyncio.coroutine
    def _not_found(self, request):
        raise HTTPNotFound()

    def __repr__(self):
        return "<MatchInfo: not found>"


class _MethodNotAllowedMatchInfo(UrlMappingMatchInfo):

    def __init__(self, method, allowed_methods):
        super().__init__({}, None)
        self._method = method
        self._allowed_methods = allowed_methods

    @property
    def handler(self):
        return self._not_allowed

    @property
    def route(self):
        return None

    @asyncio.coroutine
    def _not_allowed(self, request):
        raise HTTPMethodNotAllowed(self._method, self._allowed_methods)

    def __repr__(self):
        return ("<MatchInfo: method {} is not allowed (allowed methods: {}>"
                .format(self._method,
                        ', '.join(sorted(self._allowed_methods))))


class UrlDispatcher(AbstractRouter, collections.abc.Mapping):

    DYN = re.compile(r'^\{(?P<var>[a-zA-Z][_a-zA-Z0-9]*)\}$')
    DYN_WITH_RE = re.compile(
        r'^\{(?P<var>[a-zA-Z][_a-zA-Z0-9]*):(?P<re>.+)\}$')
    GOOD = r'[^{}/]+'
    ROUTE_RE = re.compile(r'(\{[_a-zA-Z][^{}]*(?:\{[^{}]*\}[^{}]*)*\})')

    METHODS = {'POST', 'GET', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'}

    def __init__(self):
        super().__init__()
        self._urls = []
        self._routes = {}

    @asyncio.coroutine
    def resolve(self, request):
        path = request.path
        method = request.method
        allowed_methods = set()
        for route in self._urls:
            match_dict = route.match(path)
            if match_dict is None:
                continue
            route_method = route.method
            if route_method != method:
                allowed_methods.add(route_method)
            else:
                return UrlMappingMatchInfo(match_dict, route)
        else:
            if allowed_methods:
                return _MethodNotAllowedMatchInfo(method, allowed_methods)
            else:
                return _NotFoundMatchInfo()

    def __iter__(self):
        return iter(self._routes)

    def __len__(self):
        return len(self._routes)

    def __contains__(self, name):
        return name in self._routes

    def __getitem__(self, name):
        return self._routes[name]

    def _register_endpoint(self, route):
        name = route.name
        if name is not None:
            if name in self._routes:
                raise ValueError('Duplicate {!r}, '
                                 'already handled by {!r}'
                                 .format(name, self._routes[name]))
            else:
                self._routes[name] = route
        self._urls.append(route)

    def add_route(self, method, path, handler,
                  *, name=None, expect_handler=None):

        assert callable(handler), handler
        if not asyncio.iscoroutinefunction(handler):
            handler = asyncio.coroutine(handler)
        method = method.upper()
        assert method in self.METHODS, method

        if not ('{' in path or '}' in path or self.ROUTE_RE.search(path)):
            route = PlainRoute(
                method, handler, name, path, expect_handler=expect_handler)
            self._register_endpoint(route)
            return route

        pattern = ''
        formatter = ''
        for part in self.ROUTE_RE.split(path):
            match = self.DYN.match(part)
            if match:
                pattern += '(?P<{}>{})'.format(match.group('var'), self.GOOD)
                formatter += '{' + match.group('var') + '}'
                continue

            match = self.DYN_WITH_RE.match(part)
            if match:
                pattern += '(?P<{var}>{re})'.format(**match.groupdict())
                formatter += '{' + match.group('var') + '}'
                continue

            if '{' in part or '}' in part:
                raise ValueError("Invalid path '{}'['{}']".format(path, part))

            formatter += part
            pattern += re.escape(part)

        try:
            compiled = re.compile('^' + pattern + '$')
        except re.error as exc:
            raise ValueError(
                "Bad pattern '{}': {}".format(pattern, exc)) from None
        route = DynamicRoute(
            method, handler, name, compiled,
            formatter, expect_handler=expect_handler)
        self._register_endpoint(route)
        return route

    def add_static(self, prefix, path, *, name=None, expect_handler=None):
        """
        Adds static files view
        :param prefix - url prefix
        :param path - folder with files
        """
        assert prefix.startswith('/')
        assert os.path.isdir(path), 'Path does not directory %s' % path
        path = os.path.abspath(path)
        if not prefix.endswith('/'):
            prefix += '/'
        route = StaticRoute(name, prefix, path, expect_handler=expect_handler)
        self._register_endpoint(route)
        return route


############################################################
# Application implementation
############################################################


class RequestHandler(ServerHttpProtocol):

    def __init__(self, manager, app, router, **kwargs):
        super().__init__(**kwargs)

        self._manager = manager
        self._app = app
        self._router = router
        self._middlewares = app.middlewares

    def connection_made(self, transport):
        super().connection_made(transport)

        self._manager.connection_made(self, transport)

    def connection_lost(self, exc):
        self._manager.connection_lost(self, exc)

        super().connection_lost(exc)

    @asyncio.coroutine
    def handle_request(self, message, payload):
        now = self._loop.time()

        app = self._app
        request = Request(app, message, payload,
                          self.transport, self.reader, self.writer)
        try:
            match_info = yield from self._router.resolve(request)

            assert isinstance(match_info, AbstractMatchInfo), match_info

            resp = None
            request._match_info = match_info
            if request.headers.get(hdrs.EXPECT, '').lower() == "100-continue":
                resp = (
                    yield from match_info.route.handle_expect_header(request))

            if resp is None:
                handler = match_info.handler
                for factory in reversed(self._middlewares):
                    handler = yield from factory(app, handler)
                resp = yield from handler(request)

            if not isinstance(resp, StreamResponse):
                raise RuntimeError(
                    ("Handler {!r} should return response instance, "
                     "got {!r} [middlewares {!r}]").format(
                         match_info.handler,
                         type(resp),
                         self._middlewares))
        except HTTPException as exc:
            resp = exc

        resp_msg = resp.start(request)
        yield from resp.write_eof()

        # notify server about keep-alive
        self.keep_alive(resp_msg.keep_alive())

        # log access
        self.log_access(message, None, resp_msg, self._loop.time() - now)


class RequestHandlerFactory:

    def __init__(self, app, router, *,
                 handler=RequestHandler, loop=None, **kwargs):
        self._app = app
        self._router = router
        self._handler = handler
        self._loop = loop
        self._connections = {}
        self._kwargs = kwargs
        self._kwargs.setdefault('logger', app.logger)

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
        for handler in self._connections.keys():
            handler.closing()

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
            self, self._app, self._router, loop=self._loop, **self._kwargs)


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
        self._middlewares = tuple(middlewares)

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
