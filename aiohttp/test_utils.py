"""Utilities shared by tests."""

import asyncio
import contextlib
import functools
import gc
import socket
import unittest
from unittest import mock

from multidict import CIMultiDict

import aiohttp

from . import ClientSession, hdrs
from .helpers import _sentinel
from .protocol import HttpVersion, RawRequestMessage
from .signals import Signal
from .web import Request


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
    _address = '127.0.0.1'

    def __init__(self, app, protocol="http"):
        self.app = app
        self._loop = loop = app.loop
        self.port = unused_port()
        self._handler = app.make_handler()
        self._server = None
        if not loop.is_running():
            loop.run_until_complete(self.start_server())
        self._session = ClientSession(
            loop=self._loop,
            cookie_jar=aiohttp.CookieJar(unsafe=True,
                                         loop=self._loop))
        self._root = '{}://{}:{}'.format(protocol, self._address, self.port)
        self._closed = False
        self._responses = []

    @asyncio.coroutine
    def start_server(self):
        self._server = yield from self._loop.create_server(
            self._handler, self._address, self.port
        )

    @property
    def session(self):
        """A raw handler to the aiohttp.ClientSession.

        Unlike the methods on the TestClient, client session requests
        do not automatically include the host in the url queried, and
        will require an absolute path to the resource.

        """
        return self._session

    def make_url(self, path):
        return self._root + path

    @asyncio.coroutine
    def request(self, method, path, *args, **kwargs):
        """Routes a request to the http server.

        The interface is identical to asyncio.ClientSession.request,
        except the loop kwarg is overriden by the instance used by the
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

    def close(self):
        """Close all fixtures created by the test client.

        After that point, the TestClient is no longer usable.

        This is an idempotent function: running close multiple times
        will not have any additional effects.

        close is also run when the object is garbage collected, and on
        exit when used as a context manager.

        """
        if not self._closed:
            loop = self._loop
            for resp in self._responses:
                resp.close()
            loop.run_until_complete(self._session.close())
            self._server.close()
            loop.run_until_complete(self._server.wait_closed())
            loop.run_until_complete(self.app.shutdown())
            loop.run_until_complete(self._handler.finish_connections())
            loop.run_until_complete(self.app.cleanup())
            self._closed = True

    def __del__(self):
        self.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


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
        This method should be overriden
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

    def tearDown(self):
        del self.client
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
def loop_context():
    """A contextmanager that creates an event_loop, for test purposes.

    Handles the creation and cleanup of a test loop.
    """
    loop = setup_test_loop()
    yield loop
    teardown_test_loop(loop)


def setup_test_loop():
    """Create and return an asyncio.BaseEventLoop
    instance.

    The caller should also call teardown_test_loop,
    once they are done with the loop.
    """
    loop = asyncio.new_event_loop()
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
                        reader=_sentinel,
                        writer=_sentinel,
                        transport=_sentinel,
                        payload=_sentinel,
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

    :param closing: flag idicates that connection should be closed after
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

    if reader is _sentinel:
        reader = mock.Mock()

    if writer is _sentinel:
        writer = mock.Mock()

    if transport is _sentinel:
        transport = _create_transport(sslcontext)

    if payload is _sentinel:
        payload = mock.Mock()

    req = Request(app, message, payload,
                  transport, reader, writer,
                  secure_proxy_ssl_header=secure_proxy_ssl_header)

    assert req.app is app
    assert req.content is payload
    assert req.transport is transport

    return req


def make_mocked_coro(return_value):
    """A coroutine mock.

    Behavees like a coroutine which returns return_value.

    But it is also a mock object, you might test it as usual Mock:

    mocked = mocke_mocked_coro(1)
    assert 1 == await mocked(1, 2)
    mocked.assert_called_with(1, 2)
    """
    @asyncio.coroutine
    def mock_coro(*args, **kwargs):
        return return_value

    return mock.Mock(wraps=mock_coro)
