"""Utilities shared by tests."""

import asyncio
import contextlib
import functools
import gc
import socket
import sys
import unittest
from abc import ABC, abstractmethod
from contextlib import contextmanager
from unittest import mock

from multidict import CIMultiDict
from yarl import URL

import aiohttp
from aiohttp.client import _RequestContextManager

from . import ClientSession, hdrs
from .helpers import TimeService, sentinel
from .protocol import HttpVersion, RawRequestMessage
from .signals import Signal
from .web import Application, Request, Server, UrlMappingMatchInfo

PY_35 = sys.version_info >= (3, 5)


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
    def __init__(self, *, scheme=sentinel,
                 host='127.0.0.1', skip_url_asserts=False, **kwargs):
        self.port = None
        self.server = None
        self.handler = None
        self._root = None
        self.host = host
        self._closed = False
        self.scheme = scheme
        self.skip_url_asserts = skip_url_asserts

    @asyncio.coroutine
    def start_server(self, **kwargs):
        if self.server:
            return
        self.port = unused_port()
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
        self.server = yield from self._loop.create_server(handler,
                                                          self.host,
                                                          self.port,
                                                          ssl=self._ssl)

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


class TestServer(BaseTestServer):
    def __init__(self, app, *, scheme=sentinel, host='127.0.0.1', **kwargs):
        self.app = app
        self._loop = app.loop
        super().__init__(scheme=scheme, host=host, **kwargs)

    @asyncio.coroutine
    def _make_factory(self, **kwargs):
        yield from self.app.startup()
        self.handler = self.app.make_handler(**kwargs)
        return self.handler

    @asyncio.coroutine
    def _close_hook(self):
        yield from self.app.shutdown()
        yield from self.handler.shutdown()
        yield from self.app.cleanup()


class RawTestServer(BaseTestServer):
    def __init__(self, handler, *,
                 loop=None, scheme=sentinel, host='127.0.0.1', **kwargs):
        if loop is None:
            loop = asyncio.get_event_loop()
        self._loop = loop
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
                 cookie_jar=None, server_kwargs=None, **kwargs):
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
        self._loop = self._server._loop
        if cookie_jar is None:
            cookie_jar = aiohttp.CookieJar(unsafe=True,
                                           loop=self._loop)
        kwargs['time_service'] = TimeService(self._loop, interval=0.1)
        self._session = ClientSession(loop=self._loop,
                                      cookie_jar=cookie_jar,
                                      **kwargs)
        self._closed = False
        self._responses = []
        self._websockets = []

    @asyncio.coroutine
    def start_server(self):
        yield from self._server.start_server()

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
            yield from self._session.close()
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
    def get_application(self, loop):
        """
        This method should be overridden
        to return the aiohttp.web.Application
        object to test.

        """
        return self.get_app(loop)

    def get_app(self, loop):
        """Obsolete method used to constructing web application.

        Use .get_application() coroutine instead

        """
        pass  # pragma: no cover

    def setUp(self):
        self.loop = setup_test_loop()

        self.app = self.loop.run_until_complete(
            self.get_application(self.loop))
        self.client = self.loop.run_until_complete(self._get_client(self.app))

        self.loop.run_until_complete(self.client.start_server())

    def tearDown(self):
        self.loop.run_until_complete(self.client.close())
        teardown_test_loop(self.loop)

    @asyncio.coroutine
    def _get_client(self, app):
        """Return a TestClient instance."""
        return TestClient(self.app)


def unittest_run_loop(func):
    """A decorator dedicated to use with asynchronous methods of an
    AioHTTPTestCase.

    Handles executing an asynchronous function, using
    the self.loop of the AioHTTPTestCase.
    """

    @functools.wraps(func)
    def new_func(self):
        return self.loop.run_until_complete(func(self))

    return new_func


@contextlib.contextmanager
def loop_context(loop_factory=asyncio.new_event_loop):
    """A contextmanager that creates an event_loop, for test purposes.

    Handles the creation and cleanup of a test loop.
    """
    loop = setup_test_loop(loop_factory)
    yield loop
    teardown_test_loop(loop)


def setup_test_loop(loop_factory=asyncio.new_event_loop):
    """Create and return an asyncio.BaseEventLoop
    instance.

    The caller should also call teardown_test_loop,
    once they are done with the loop.
    """
    loop = loop_factory()
    asyncio.set_event_loop(None)
    return loop


def teardown_test_loop(loop):
    """Teardown and cleanup an event_loop created
    by setup_test_loop.

    """
    closed = loop.is_closed()
    if not closed:
        loop.call_soon(loop.stop)
        loop.run_forever()
        loop.close()
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
                        reader=sentinel,
                        writer=sentinel,
                        transport=sentinel,
                        payload=sentinel,
                        sslcontext=None,
                        secure_proxy_ssl_header=None,
                        client_max_size=1024**2):
    """Creates mocked web.Request testing purposes.

    Useful in unit tests, when spinning full web server is overkill or
    specific conditions and errors are hard to trigger.

    """

    if version < HttpVersion(1, 1):
        closing = True

    if headers:
        hdrs = CIMultiDict(headers)
        raw_hdrs = [
            (k.encode('utf-8'), v.encode('utf-8')) for k, v in headers.items()]
    else:
        hdrs = CIMultiDict()
        raw_hdrs = []

    message = RawRequestMessage(method, path, version, hdrs,
                                raw_hdrs, closing, False)
    if app is None:
        app = _create_app_mock()

    if reader is sentinel:
        reader = mock.Mock()

    if writer is sentinel:
        writer = mock.Mock()

    if transport is sentinel:
        transport = _create_transport(sslcontext)

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

    task = mock.Mock()

    req = Request(message, payload,
                  transport, reader, writer,
                  time_service, task,
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
