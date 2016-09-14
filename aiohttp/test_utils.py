"""Utilities shared by tests."""

import asyncio
import contextlib
import functools
import gc
import socket
import sys
import unittest
from unittest import mock

from multidict import CIMultiDict

import aiohttp

from . import ClientSession, hdrs
from .helpers import sentinel
from .protocol import HttpVersion, RawRequestMessage
from .signals import Signal
from .web import Application, Request

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


class TestServer:
    def __init__(self, app, *, scheme="http", host='127.0.0.1'):
        self.app = app
        self._loop = app.loop
        self.port = None
        self.server = None
        self.handler = None
        self._root = None
        self.host = host
        self.scheme = scheme
        self._closed = False

    @asyncio.coroutine
    def start_server(self, **kwargs):
        if self.server:
            return
        self.port = unused_port()
        self._root = '{}://{}:{}'.format(self.scheme, self.host, self.port)
        self.handler = self.app.make_handler(**kwargs)
        self.server = yield from self._loop.create_server(self.handler,
                                                          self.host,
                                                          self.port)

    def make_url(self, path):
        return self._root + path

    @asyncio.coroutine
    def close(self):
        """Close all fixtures created by the test client.

        After that point, the TestClient is no longer usable.

        This is an idempotent function: running close multiple times
        will not have any additional effects.

        close is also run when the object is garbage collected, and on
        exit when used as a context manager.

        """
        if self.server is not None and not self._closed:
            self.server.close()
            yield from self.server.wait_closed()
            yield from self.app.shutdown()
            yield from self.handler.finish_connections()
            yield from self.app.cleanup()
            self._root = None
            self.port = None
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


class TestClient:
    """
    A test client implementation, for a aiohttp.web.Application.

    :param app: the aiohttp.web application passed to create_test_server

    :type app: aiohttp.web.Application

    :param protocol: http or https

    :type protocol: str

    TestClient can also be used as a contextmanager, returning
    the instance of itself instantiated.
    """

    def __init__(self, app_or_server, *, scheme=sentinel, host=sentinel):
        if isinstance(app_or_server, TestServer):
            if scheme is not sentinel or host is not sentinel:
                raise ValueError("scheme and host are mutable exclusive "
                                 "with TestServer parameter")
            self._server = app_or_server
        elif isinstance(app_or_server, Application):
            scheme = "http" if scheme is sentinel else scheme
            host = '127.0.0.1' if host is sentinel else host
            self._server = TestServer(app_or_server,
                                      scheme=scheme, host=host)
        else:
            raise TypeError("app_or_server should be either web.Application "
                            "or TestServer instance")
        self._loop = self._server.app.loop
        self._session = ClientSession(
            loop=self._loop,
            cookie_jar=aiohttp.CookieJar(unsafe=True,
                                         loop=self._loop))
        self._closed = False
        self._responses = []

    @asyncio.coroutine
    def start_server(self):
        yield from self._server.start_server()

    @property
    def app(self):
        return self._server.app

    @property
    def host(self):
        return self._server.host

    @property
    def port(self):
        return self._server.port

    @property
    def handler(self):
        return self._server.handler

    @property
    def server(self):
        return self._server.server

    @property
    def session(self):
        """A raw handler to the aiohttp.ClientSession.

        Unlike the methods on the TestClient, client session requests
        do not automatically include the host in the url queried, and
        will require an absolute path to the resource.

        """
        return self._session

    def make_url(self, path):
        return self._server.make_url(path)

    @asyncio.coroutine
    def request(self, method, path, *args, **kwargs):
        """Routes a request to the http server.

        The interface is identical to asyncio.ClientSession.request,
        except the loop kwarg is overridden by the instance used by the
        application.

        """
        resp = yield from self._session.request(
            method, self.make_url(path), *args, **kwargs
        )
        # save it to close later
        self._responses.append(resp)
        return resp

    def get(self, path, *args, **kwargs):
        """Perform an HTTP GET request."""
        return self.request(hdrs.METH_GET, path, *args, **kwargs)

    def post(self, path, *args, **kwargs):
        """Perform an HTTP POST request."""
        return self.request(hdrs.METH_POST, path, *args, **kwargs)

    def options(self, path, *args, **kwargs):
        """Perform an HTTP OPTIONS request."""
        return self.request(hdrs.METH_OPTIONS, path, *args, **kwargs)

    def head(self, path, *args, **kwargs):
        """Perform an HTTP HEAD request."""
        return self.request(hdrs.METH_HEAD, path, *args, **kwargs)

    def put(self, path, *args, **kwargs):
        """Perform an HTTP PUT request."""
        return self.request(hdrs.METH_PUT, path, *args, **kwargs)

    def patch(self, path, *args, **kwargs):
        """Perform an HTTP PATCH request."""
        return self.request(hdrs.METH_PATCH, path, *args, **kwargs)

    def delete(self, path, *args, **kwargs):
        """Perform an HTTP PATCH request."""
        return self.request(hdrs.METH_DELETE, path, *args, **kwargs)

    def ws_connect(self, path, *args, **kwargs):
        """Initiate websocket connection.

        The api is identical to aiohttp.ClientSession.ws_connect.

        """
        return self._session.ws_connect(
            self.make_url(path), *args, **kwargs
        )

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
        self.get_app()

    Note that the TestClient's methods are asynchronous: you have to
    execute function on the test client using asynchronous methods.
    """

    def get_app(self, loop):
        """
        This method should be overridden
        to return the aiohttp.web.Application
        object to test.

        :param loop: the event_loop to use
        :type loop: asyncio.BaseEventLoop
        """
        pass  # pragma: no cover

    def setUp(self):
        self.loop = setup_test_loop()
        self.app = self.get_app(self.loop)
        self.client = TestClient(self.app)
        self.loop.run_until_complete(self.client.start_server())

    def tearDown(self):
        self.loop.run_until_complete(self.client.close())
        teardown_test_loop(self.loop)


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

    :param loop: the loop to teardown
    :type loop: asyncio.BaseEventLoop
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
                        secure_proxy_ssl_header=None):
    """Creates mocked web.Request testing purposes.

    Useful in unit tests, when spinning full web server is overkill or
    specific conditions and errors are hard to trigger.

    :param method: str, that represents HTTP method, like; GET, POST.
    :type method: str

    :param path: str, The URL including *PATH INFO* without the host or scheme
    :type path: str

    :param headers: mapping containing the headers. Can be anything accepted
        by the multidict.CIMultiDict constructor.
    :type headers: dict, multidict.CIMultiDict, list of pairs

    :param version: namedtuple with encoded HTTP version
    :type version: aiohttp.protocol.HttpVersion

    :param closing: flag indicates that connection should be closed after
        response.
    :type closing: bool

    :param app: the aiohttp.web application attached for fake request
    :type app: aiohttp.web.Application

    :param reader: object for storing and managing incoming data
    :type reader: aiohttp.parsers.StreamParser

    :param writer: object for managing outcoming data
    :type wirter: aiohttp.parsers.StreamWriter

    :param transport: asyncio transport instance
    :type transport: asyncio.transports.Transport

    :param payload: raw payload reader object
    :type  payload: aiohttp.streams.FlowControlStreamReader

    :param sslcontext: ssl.SSLContext object, for HTTPS connection
    :type sslcontext: ssl.SSLContext

    :param secure_proxy_ssl_header: A tuple representing a HTTP header/value
        combination that signifies a request is secure.
    :type secure_proxy_ssl_header: tuple

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

    req = Request(app, message, payload,
                  transport, reader, writer,
                  secure_proxy_ssl_header=secure_proxy_ssl_header)

    return req


def make_mocked_coro(return_value=sentinel, raise_exception=sentinel):
    """Creates a coroutine mock."""
    @asyncio.coroutine
    def mock_coro(*args, **kwargs):
        if raise_exception is not sentinel:
            raise raise_exception
        return return_value

    return mock.Mock(wraps=mock_coro)
