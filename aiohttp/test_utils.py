"""Utilities shared by tests."""

import asyncio
import contextlib
import functools
import gc
import socket
import sys
import unittest
from abc import ABC, abstractmethod
from unittest import mock

from multidict import CIMultiDict
from yarl import URL

import aiohttp
from aiohttp.client import _RequestContextManager, _WSRequestContextManager

from . import ClientSession, hdrs
from .helpers import sentinel
from .http import HttpVersion, RawRequestMessage
from .signals import Signal
from .web import (AppRunner, Request, Server, ServerRunner, TCPSite,
                  UrlMappingMatchInfo)


def unused_port():
    """Return a port that is unused on the current host."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class BaseTestServer(ABC):
    def __init__(self, *, scheme=sentinel, loop=None,
                 host='127.0.0.1', port=None, skip_url_asserts=False,
                 **kwargs):
        self._loop = loop
        self.runner = None
        self._root = None
        self.host = host
        self.port = port
        self._closed = False
        self.scheme = scheme
        self.skip_url_asserts = skip_url_asserts

    async def start_server(self, loop=None, **kwargs):
        if self.runner:
            return
        self._loop = loop
        self._ssl = kwargs.pop('ssl', None)
        self.runner = await self._make_runner(**kwargs)
        await self.runner.setup()
        if not self.port:
            self.port = unused_port()
        site = TCPSite(self.runner, host=self.host, port=self.port,
                       ssl_context=self._ssl)
        await site.start()
        if self.scheme is sentinel:
            if self._ssl:
                scheme = 'https'
            else:
                scheme = 'http'
            self.scheme = scheme
        self._root = URL('{}://{}:{}'.format(self.scheme,
                                             self.host,
                                             self.port))

    @abstractmethod  # pragma: no cover
    async def _make_runner(self, **kwargs):
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
        return self.runner is not None

    @property
    def closed(self):
        return self._closed

    @property
    def handler(self):
        # for backward compatibility
        # web.Server instance
        return self.runner.server

    async def close(self):
        """Close all fixtures created by the test client.

        After that point, the TestClient is no longer usable.

        This is an idempotent function: running close multiple times
        will not have any additional effects.

        close is also run when the object is garbage collected, and on
        exit when used as a context manager.

        """
        if self.started and not self.closed:
            await self.runner.cleanup()
            self._root = None
            self.port = None
            self._closed = True

    def __enter__(self):
        raise TypeError("Use async with instead")

    def __exit__(self, exc_type, exc_value, traceback):
        # __exit__ should exist in pair with __enter__ but never executed
        pass  # pragma: no cover

    async def __aenter__(self):
        await self.start_server(loop=self._loop)
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.close()


class TestServer(BaseTestServer):

    def __init__(self, app, *,
                 scheme=sentinel, host='127.0.0.1', port=None, **kwargs):
        self.app = app
        super().__init__(scheme=scheme, host=host, port=port, **kwargs)

    async def _make_runner(self, **kwargs):
        return AppRunner(self.app, **kwargs)


class RawTestServer(BaseTestServer):

    def __init__(self, handler, *,
                 scheme=sentinel, host='127.0.0.1', port=None, **kwargs):
        self._handler = handler
        super().__init__(scheme=scheme, host=host, port=port, **kwargs)

    async def _make_runner(self, debug=True, **kwargs):
        srv = Server(
            self._handler, loop=self._loop, debug=True, **kwargs)
        return ServerRunner(srv, debug=debug, **kwargs)


class TestClient:
    """
    A test client implementation.

    To write functional tests for aiohttp based servers.

    """

    def __init__(self, server, *, cookie_jar=None, loop=None, **kwargs):
        if not isinstance(server, BaseTestServer):
            raise TypeError("server must be TestServer "
                            "instance, found type: %r" % type(server))
        self._server = server
        self._loop = loop
        if cookie_jar is None:
            cookie_jar = aiohttp.CookieJar(unsafe=True, loop=loop)
        self._session = ClientSession(loop=loop,
                                      cookie_jar=cookie_jar,
                                      **kwargs)
        self._closed = False
        self._responses = []
        self._websockets = []

    async def start_server(self):
        await self._server.start_server(loop=self._loop)

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
    def app(self):
        return getattr(self._server, "app", None)

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

    async def request(self, method, path, *args, **kwargs):
        """Routes a request to tested http server.

        The interface is identical to asyncio.ClientSession.request,
        except the loop kwarg is overridden by the instance used by the
        test server.

        """
        resp = await self._session.request(
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

    def ws_connect(self, path, *args, **kwargs):
        """Initiate websocket connection.

        The api corresponds to aiohttp.ClientSession.ws_connect.

        """
        return _WSRequestContextManager(
            self._ws_connect(path, *args, **kwargs)
        )

    async def _ws_connect(self, path, *args, **kwargs):
        ws = await self._session.ws_connect(
            self.make_url(path), *args, **kwargs)
        self._websockets.append(ws)
        return ws

    async def close(self):
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
                await ws.close()
            await self._session.close()
            await self._server.close()
            self._closed = True

    def __enter__(self):
        raise TypeError("Use async with instead")

    def __exit__(self, exc_type, exc_value, traceback):
        # __exit__ should exist in pair with __enter__ but never executed
        pass  # pragma: no cover

    async def __aenter__(self):
        await self.start_server()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.close()


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

    async def get_application(self):
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
        raise RuntimeError("Did you forget to define get_application()?")

    def setUp(self):
        self.loop = setup_test_loop()

        self.app = self.loop.run_until_complete(self.get_application())
        self.server = self.loop.run_until_complete(self.get_server(self.app))
        self.client = self.loop.run_until_complete(
            self.get_client(self.server))

        self.loop.run_until_complete(self.client.start_server())

        self.loop.run_until_complete(self.setUpAsync())

    async def setUpAsync(self):
        pass

    def tearDown(self):
        self.loop.run_until_complete(self.tearDownAsync())
        self.loop.run_until_complete(self.client.close())
        teardown_test_loop(self.loop)

    async def tearDownAsync(self):
        pass

    async def get_server(self, app):
        """Return a TestServer instance."""
        return TestServer(app, loop=self.loop)

    async def get_client(self, server):
        """Return a TestClient instance."""
        return TestClient(server, loop=self.loop)


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
    asyncio.set_event_loop(loop)
    if sys.platform != "win32":
        policy = asyncio.get_event_loop_policy()
        watcher = asyncio.SafeChildWatcher()
        watcher.attach_loop(loop)
        with contextlib.suppress(NotImplementedError):
            policy.set_child_watcher(watcher)
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
    app.on_response_prepare.freeze()
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
                        match_info=sentinel,
                        version=HttpVersion(1, 1), closing=False,
                        app=None,
                        writer=sentinel,
                        protocol=sentinel,
                        transport=sentinel,
                        payload=sentinel,
                        sslcontext=None,
                        client_max_size=1024**2,
                        loop=...):
    """Creates mocked web.Request testing purposes.

    Useful in unit tests, when spinning full web server is overkill or
    specific conditions and errors are hard to trigger.

    """

    task = mock.Mock()
    if loop is ...:
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

    if transport is sentinel:
        transport = _create_transport(sslcontext)

    if protocol is sentinel:
        protocol = mock.Mock()
        protocol.transport = transport

    if writer is sentinel:
        writer = mock.Mock()
        writer.write_headers = make_mocked_coro(None)
        writer.write = make_mocked_coro(None)
        writer.write_eof = make_mocked_coro(None)
        writer.drain = make_mocked_coro(None)
        writer.transport = transport

    protocol.transport = transport
    protocol.writer = writer

    if payload is sentinel:
        payload = mock.Mock()

    req = Request(message, payload,
                  protocol, writer, task, loop,
                  client_max_size=client_max_size)

    match_info = UrlMappingMatchInfo(
        {} if match_info is sentinel else match_info, mock.Mock())
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
