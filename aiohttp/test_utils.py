"""Utilities shared by tests."""

import asyncio
import contextlib
import functools
import gc
import socket
import unittest
from abc import ABC, abstractmethod
from contextlib import contextmanager
from unittest import mock

from multidict import CIMultiDict
from yarl import URL

import aiohttp
from aiohttp.client import _RequestContextManager

from . import ClientSession, hdrs
from .helpers import PY_35, noop, sentinel
from .http import HttpVersion, RawRequestMessage
from .signals import Signal
from .web import Application, Request, Server, UrlMappingMatchInfo


def run_briefly(loop):
    @asyncio.coroutine
    def once():
        pass
    t = asyncio.Task(once(), loop=loop)
    loop.run_until_complete(t)


def unused_port():
    """Return a port that is unused on the current host."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class BaseTestServer(ABC):
    def __init__(self, *, scheme=sentinel, loop=None,
                 host='127.0.0.1', skip_url_asserts=False, **kwargs):
        self._loop = loop
        self.port = None
        self.server = None
        self.handler = None
        self._root = None
        self.host = host
        self._closed = False
        self.scheme = scheme
        self.skip_url_asserts = skip_url_asserts

    @asyncio.coroutine
    def start_server(self, loop=None, **kwargs):
        if self.server:
            return
        self._loop = loop
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.bind((self.host, 0))
        self.port = self._socket.getsockname()[1]
        self._ssl = kwargs.pop('ssl', None)
        if self.scheme is sentinel:
            if self._ssl:
                scheme = 'https'
            else:
                scheme = 'http'
            self.scheme = scheme
        self._root = URL('{}://{}:{}'.format(self.scheme,
                                             self.host,
                                             self.port))

        handler = yield from self._make_factory(**kwargs)
        self.server = yield from self._loop.create_server(
            handler, ssl=self._ssl, sock=self._socket)

    @abstractmethod  # pragma: no cover
    @asyncio.coroutine
    def _make_factory(self, **kwargs):
        pass

    def make_url(self, path):
        url = URL(path)
        if not self.skip_url_asserts:
            assert not url.is_absolute()
            return self._root.join(url)
        else:
            return URL(str(self._root) + path)

    @property
    def started(self):
        return self.server is not None

    @property
    def closed(self):
        return self._closed

    @asyncio.coroutine
    def close(self):
        """Close all fixtures created by the test client.

        After that point, the TestClient is no longer usable.

        This is an idempotent function: running close multiple times
        will not have any additional effects.

        close is also run when the object is garbage collected, and on
        exit when used as a context manager.

        """
        if self.started and not self.closed:
            self.server.close()
            yield from self.server.wait_closed()
            self._root = None
            self.port = None
            yield from self._close_hook()
            self._closed = True

    @abstractmethod
    @asyncio.coroutine
    def _close_hook(self):
        pass  # pragma: no cover

    def __enter__(self):
        self._loop.run_until_complete(self.start_server(loop=self._loop))
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._loop.run_until_complete(self.close())

    if PY_35:
        @asyncio.coroutine
        def __aenter__(self):
            yield from self.start_server(loop=self._loop)
            return self

        @asyncio.coroutine
        def __aexit__(self, exc_type, exc_value, traceback):
            yield from self.close()


class TestServer(BaseTestServer):

    def __init__(self, app, *,
                 scheme=sentinel, host='127.0.0.1', **kwargs):
        self.app = app
        super().__init__(scheme=scheme, host=host, **kwargs)

    @asyncio.coroutine
    def _make_factory(self, **kwargs):
        yield from self.app.startup()
        self.handler = self.app.make_handler(loop=self._loop, **kwargs)
        return self.handler

    @asyncio.coroutine
    def _close_hook(self):
        yield from self.app.shutdown()
        yield from self.handler.shutdown()
        yield from self.app.cleanup()


class RawTestServer(BaseTestServer):

    def __init__(self, handler, *,
                 scheme=sentinel, host='127.0.0.1', **kwargs):
        self._handler = handler
        super().__init__(scheme=scheme, host=host, **kwargs)

    @asyncio.coroutine
    def _make_factory(self, debug=True, **kwargs):
        self.handler = Server(
            self._handler, loop=self._loop, debug=True, **kwargs)
        return self.handler

    @asyncio.coroutine
    def _close_hook(self):
        return


class TestClient:
    """
    A test client implementation.

    To write functional tests for aiohttp based servers.

    """

    def __init__(self, app_or_server, *, scheme=sentinel, host=sentinel,
                 cookie_jar=None, server_kwargs=None, loop=None, **kwargs):
        if isinstance(app_or_server, BaseTestServer):
            if scheme is not sentinel or host is not sentinel:
                raise ValueError("scheme and host are mutable exclusive "
                                 "with TestServer parameter")
            self._server = app_or_server
        elif isinstance(app_or_server, Application):
            scheme = "http" if scheme is sentinel else scheme
            host = '127.0.0.1' if host is sentinel else host
            server_kwargs = server_kwargs or {}
            self._server = TestServer(
                app_or_server,
                scheme=scheme, host=host, **server_kwargs)
        else:
            raise TypeError("app_or_server should be either web.Application "
                            "or TestServer instance")
        self._loop = loop
        if cookie_jar is None:
            cookie_jar = aiohttp.CookieJar(unsafe=True, loop=loop)
        self._session = ClientSession(loop=loop,
                                      cookie_jar=cookie_jar,
                                      **kwargs)
        self._closed = False
        self._responses = []
        self._websockets = []

    @asyncio.coroutine
    def start_server(self):
        yield from self._server.start_server(loop=self._loop)

    @property
    def host(self):
        return self._server.host

    @property
    def port(self):
        return self._server.port

    @property
    def server(self):
        return self._server

    @property
    def session(self):
        """An internal aiohttp.ClientSession.

        Unlike the methods on the TestClient, client session requests
        do not automatically include the host in the url queried, and
        will require an absolute path to the resource.

        """
        return self._session

    def make_url(self, path):
        return self._server.make_url(path)

    @asyncio.coroutine
    def request(self, method, path, *args, **kwargs):
        """Routes a request to tested http server.

        The interface is identical to asyncio.ClientSession.request,
        except the loop kwarg is overridden by the instance used by the
        test server.

        """
        resp = yield from self._session.request(
            method, self.make_url(path), *args, **kwargs
        )
        # save it to close later
        self._responses.append(resp)
        return resp

    def get(self, path, *args, **kwargs):
        """Perform an HTTP GET request."""
        return _RequestContextManager(
            self.request(hdrs.METH_GET, path, *args, **kwargs)
        )

    def post(self, path, *args, **kwargs):
        """Perform an HTTP POST request."""
        return _RequestContextManager(
            self.request(hdrs.METH_POST, path, *args, **kwargs)
        )

    def options(self, path, *args, **kwargs):
        """Perform an HTTP OPTIONS request."""
        return _RequestContextManager(
            self.request(hdrs.METH_OPTIONS, path, *args, **kwargs)
        )

    def head(self, path, *args, **kwargs):
        """Perform an HTTP HEAD request."""
        return _RequestContextManager(
            self.request(hdrs.METH_HEAD, path, *args, **kwargs)
        )

    def put(self, path, *args, **kwargs):
        """Perform an HTTP PUT request."""
        return _RequestContextManager(
            self.request(hdrs.METH_PUT, path, *args, **kwargs)
        )

    def patch(self, path, *args, **kwargs):
        """Perform an HTTP PATCH request."""
        return _RequestContextManager(
            self.request(hdrs.METH_PATCH, path, *args, **kwargs)
        )

    def delete(self, path, *args, **kwargs):
        """Perform an HTTP PATCH request."""
        return _RequestContextManager(
            self.request(hdrs.METH_DELETE, path, *args, **kwargs)
        )

    @asyncio.coroutine
    def ws_connect(self, path, *args, **kwargs):
        """Initiate websocket connection.

        The api corresponds to aiohttp.ClientSession.ws_connect.

        """
        ws = yield from self._session.ws_connect(
            self.make_url(path), *args, **kwargs)
        self._websockets.append(ws)
        return ws

    @asyncio.coroutine
    def close(self):
        """Close all fixtures created by the test client.

        After that point, the TestClient is no longer usable.

        This is an idempotent function: running close multiple times
        will not have any additional effects.

        close is also run on exit when used as a(n) (asynchronous)
        context manager.

        """
        if not self._closed:
            for resp in self._responses:
                resp.close()
            for ws in self._websockets:
                yield from ws.close()
            self._session.close()
            yield from self._server.close()
            self._closed = True

    def __enter__(self):
        self._loop.run_until_complete(self.start_server())
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._loop.run_until_complete(self.close())

    if PY_35:
        @asyncio.coroutine
        def __aenter__(self):
            yield from self.start_server()
            return self

        @asyncio.coroutine
        def __aexit__(self, exc_type, exc_value, traceback):
            yield from self.close()


class AioHTTPTestCase(unittest.TestCase):
    """A base class to allow for unittest web applications using
    aiohttp.

    Provides the following:

    * self.client (aiohttp.test_utils.TestClient): an aiohttp test client.
    * self.loop (asyncio.BaseEventLoop): the event loop in which the
        application and server are running.
    * self.app (aiohttp.web.Application): the application returned by
        self.get_application()

    Note that the TestClient's methods are asynchronous: you have to
    execute function on the test client using asynchronous methods.
    """

    @asyncio.coroutine
    def get_application(self):
        """
        This method should be overridden
        to return the aiohttp.web.Application
        object to test.

        """
        return self.get_app()

    def get_app(self):
        """Obsolete method used to constructing web application.

        Use .get_application() coroutine instead

        """
        pass  # pragma: no cover

    def setUp(self):
        self.loop = setup_test_loop()

        self.app = self.loop.run_until_complete(self.get_application())
        self.client = self.loop.run_until_complete(self._get_client(self.app))

        self.loop.run_until_complete(self.client.start_server())

    def tearDown(self):
        self.loop.run_until_complete(self.client.close())
        teardown_test_loop(self.loop)

    @asyncio.coroutine
    def _get_client(self, app):
        """Return a TestClient instance."""
        return TestClient(self.app, loop=self.loop)


def unittest_run_loop(func, *args, **kwargs):
    """A decorator dedicated to use with asynchronous methods of an
    AioHTTPTestCase.

    Handles executing an asynchronous function, using
    the self.loop of the AioHTTPTestCase.
    """

    @functools.wraps(func, *args, **kwargs)
    def new_func(self, *inner_args, **inner_kwargs):
        return self.loop.run_until_complete(
            func(self, *inner_args, **inner_kwargs))

    return new_func


@contextlib.contextmanager
def loop_context(loop_factory=asyncio.new_event_loop, fast=False):
    """A contextmanager that creates an event_loop, for test purposes.

    Handles the creation and cleanup of a test loop.
    """
    loop = setup_test_loop(loop_factory)
    yield loop
    teardown_test_loop(loop, fast=fast)


def setup_test_loop(loop_factory=asyncio.new_event_loop):
    """Create and return an asyncio.BaseEventLoop
    instance.

    The caller should also call teardown_test_loop,
    once they are done with the loop.
    """
    loop = loop_factory()
    asyncio.set_event_loop(None)
    return loop


def teardown_test_loop(loop, fast=False):
    """Teardown and cleanup an event_loop created
    by setup_test_loop.

    """
    closed = loop.is_closed()
    if not closed:
        loop.call_soon(loop.stop)
        loop.run_forever()
        loop.close()

    if not fast:
        gc.collect()

    asyncio.set_event_loop(None)


def _create_app_mock():
    app = mock.Mock()
    app._debug = False
    app.on_response_prepare = Signal(app)
    return app


def _create_transport(sslcontext=None):
    transport = mock.Mock()

    def get_extra_info(key):
        if key == 'sslcontext':
            return sslcontext
        else:
            return None

    transport.get_extra_info.side_effect = get_extra_info
    return transport


def make_mocked_request(method, path, headers=None, *,
                        version=HttpVersion(1, 1), closing=False,
                        app=None,
                        writer=sentinel,
                        payload_writer=sentinel,
                        protocol=sentinel,
                        transport=sentinel,
                        payload=sentinel,
                        sslcontext=None,
                        secure_proxy_ssl_header=None,
                        client_max_size=1024**2):
    """Creates mocked web.Request testing purposes.

    Useful in unit tests, when spinning full web server is overkill or
    specific conditions and errors are hard to trigger.

    """

    task = mock.Mock()
    loop = mock.Mock()
    loop.create_future.return_value = ()

    if version < HttpVersion(1, 1):
        closing = True

    if headers:
        headers = CIMultiDict(headers)
        raw_hdrs = tuple(
            (k.encode('utf-8'), v.encode('utf-8')) for k, v in headers.items())
    else:
        headers = CIMultiDict()
        raw_hdrs = ()

    chunked = 'chunked' in headers.get(hdrs.TRANSFER_ENCODING, '').lower()

    message = RawRequestMessage(
        method, path, version, headers,
        raw_hdrs, closing, False, False, chunked, URL(path))
    if app is None:
        app = _create_app_mock()

    if protocol is sentinel:
        protocol = mock.Mock()

    if transport is sentinel:
        transport = _create_transport(sslcontext)

    if writer is sentinel:
        writer = mock.Mock()
        writer.transport = transport

    if payload_writer is sentinel:
        payload_writer = mock.Mock()
        payload_writer.write_eof.side_effect = noop
        payload_writer.drain.side_effect = noop

    protocol.transport = transport
    protocol.writer = writer

    if payload is sentinel:
        payload = mock.Mock()

    time_service = mock.Mock()
    time_service.time.return_value = 12345
    time_service.strtime.return_value = "Tue, 15 Nov 1994 08:12:31 GMT"

    @contextmanager
    def timeout(*args, **kw):
        yield

    time_service.timeout = mock.Mock()
    time_service.timeout.side_effect = timeout

    req = Request(message, payload,
                  protocol, payload_writer, time_service, task,
                  secure_proxy_ssl_header=secure_proxy_ssl_header,
                  client_max_size=client_max_size)

    match_info = UrlMappingMatchInfo({}, mock.Mock())
    match_info.add_app(app)
    req._match_info = match_info

    return req


def make_mocked_coro(return_value=sentinel, raise_exception=sentinel):
    """Creates a coroutine mock."""
    @asyncio.coroutine
    def mock_coro(*args, **kwargs):
        if raise_exception is not sentinel:
            raise raise_exception
        return return_value

    return mock.Mock(wraps=mock_coro)
