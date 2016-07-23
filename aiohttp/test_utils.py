"""Utilities shared by tests."""

import cgi
import contextlib
import gc
import email.parser
import functools
import http.server
import json
import logging
import io
import os
import re
import socket
import ssl
import sys
import threading
import traceback
import urllib.parse
import unittest
from unittest import mock

import asyncio
import aiohttp
from multidict import CIMultiDict

from . import server
from . import helpers
from . import ClientSession
from . import hdrs
from .protocol import HttpVersion
from .protocol import RawRequestMessage
from .signals import Signal


def run_briefly(loop):
    @asyncio.coroutine
    def once():
        pass
    t = asyncio.Task(once(), loop=loop)
    loop.run_until_complete(t)


@contextlib.contextmanager
def run_server(loop, *, listen_addr=('127.0.0.1', 0),
               use_ssl=False, router=None):
    properties = {}
    transports = []

    class HttpRequestHandler:

        def __init__(self, addr):
            if isinstance(addr, tuple):
                host, port = addr
                self.host = host
                self.port = port
            else:
                self.host = host = 'localhost'
                self.port = port = 0
            self.address = addr
            self._url = '{}://{}:{}'.format(
                'https' if use_ssl else 'http', host, port)

        def __getitem__(self, key):
            return properties[key]

        def __setitem__(self, key, value):
            properties[key] = value

        def url(self, *suffix):
            return urllib.parse.urljoin(
                self._url, '/'.join(str(s) for s in suffix))

    class TestHttpServer(server.ServerHttpProtocol):

        def connection_made(self, transport):
            transports.append(transport)

            super().connection_made(transport)

        def handle_request(self, message, payload):
            if properties.get('close', False):
                return

            for hdr, val in message.headers.items():
                if (hdr == 'EXPECT') and (val == '100-continue'):
                    self.transport.write(b'HTTP/1.0 100 Continue\r\n\r\n')
                    break

            if router is not None:
                body = yield from payload.read()

                rob = router(
                    self, properties, self.transport, message, body)
                rob.dispatch()

            else:
                response = aiohttp.Response(self.writer, 200, message.version)

                text = b'Test message'
                response.add_header('Content-type', 'text/plain')
                response.add_header('Content-length', str(len(text)))
                response.send_headers()
                response.write(text)
                response.write_eof()

    if use_ssl:
        here = os.path.join(os.path.dirname(__file__), '..', 'tests')
        keyfile = os.path.join(here, 'sample.key')
        certfile = os.path.join(here, 'sample.crt')
        sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        sslcontext.load_cert_chain(certfile, keyfile)
    else:
        sslcontext = None

    def run(loop, fut):
        thread_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(thread_loop)

        if isinstance(listen_addr, tuple):
            host, port = listen_addr
            server_coroutine = thread_loop.create_server(
                lambda: TestHttpServer(keep_alive=0.5),
                host, port, ssl=sslcontext)
        else:
            try:
                os.unlink(listen_addr)
            except FileNotFoundError:
                pass
            server_coroutine = thread_loop.create_unix_server(
                lambda: TestHttpServer(keep_alive=0.5, timeout=15),
                listen_addr, ssl=sslcontext)
        server = thread_loop.run_until_complete(server_coroutine)

        waiter = helpers.create_future(thread_loop)
        loop.call_soon_threadsafe(
            fut.set_result, (thread_loop, waiter,
                             server.sockets[0].getsockname()))

        try:
            thread_loop.run_until_complete(waiter)
        finally:
            # call pending connection_made if present
            run_briefly(thread_loop)

            # close opened transports
            for tr in transports:
                tr.close()

            run_briefly(thread_loop)  # call close callbacks

            server.close()
            thread_loop.stop()
            thread_loop.close()
            gc.collect()

    fut = helpers.create_future(loop)
    server_thread = threading.Thread(target=run, args=(loop, fut))
    server_thread.start()

    thread_loop, waiter, addr = loop.run_until_complete(fut)
    try:
        yield HttpRequestHandler(addr)
    finally:
        thread_loop.call_soon_threadsafe(waiter.set_result, None)
        server_thread.join()


class Router:

    _response_version = "1.1"
    _responses = http.server.BaseHTTPRequestHandler.responses

    def __init__(self, srv, props, transport, message, payload):
        # headers
        self._headers = http.client.HTTPMessage()
        for hdr, val in message.headers.items():
            self._headers.add_header(hdr, val)

        self._srv = srv
        self._props = props
        self._transport = transport
        self._method = message.method
        self._uri = message.path
        self._version = message.version
        self._compression = message.compression
        self._body = payload

        url = urllib.parse.urlsplit(self._uri)
        self._path = url.path
        self._query = url.query

    @staticmethod
    def define(rmatch):
        def wrapper(fn):
            f_locals = sys._getframe(1).f_locals
            mapping = f_locals.setdefault('_mapping', [])
            mapping.append((re.compile(rmatch), fn.__name__))
            return fn

        return wrapper

    def dispatch(self):  # pragma: no cover
        for route, fn in self._mapping:
            match = route.match(self._path)
            if match is not None:
                try:
                    return getattr(self, fn)(match)
                except Exception:
                    out = io.StringIO()
                    traceback.print_exc(file=out)
                    self._response(500, out.getvalue())

                return

        return self._response(self._start_response(404))

    def _start_response(self, code):
        return aiohttp.Response(self._srv.writer, code)

    def _response(self, response, body=None,
                  headers=None, chunked=False, write_body=None):
        r_headers = {}
        for key, val in self._headers.items():
            key = '-'.join(p.capitalize() for p in key.split('-'))
            r_headers[key] = val

        encoding = self._headers.get('content-encoding', '').lower()
        if 'gzip' in encoding:  # pragma: no cover
            cmod = 'gzip'
        elif 'deflate' in encoding:
            cmod = 'deflate'
        else:
            cmod = ''

        resp = {
            'method': self._method,
            'version': '%s.%s' % self._version,
            'path': self._uri,
            'headers': r_headers,
            'origin': self._transport.get_extra_info('addr', ' ')[0],
            'query': self._query,
            'form': {},
            'compression': cmod,
            'multipart-data': []
        }
        if body:  # pragma: no cover
            resp['content'] = body
        else:
            resp['content'] = self._body.decode('utf-8', 'ignore')

        ct = self._headers.get('content-type', '').lower()

        # application/x-www-form-urlencoded
        if ct == 'application/x-www-form-urlencoded':
            resp['form'] = urllib.parse.parse_qs(self._body.decode('latin1'))

        # multipart/form-data
        elif ct.startswith('multipart/form-data'):  # pragma: no cover
            out = io.BytesIO()
            for key, val in self._headers.items():
                out.write(bytes('{}: {}\r\n'.format(key, val), 'latin1'))

            out.write(b'\r\n')
            out.write(self._body)
            out.write(b'\r\n')
            out.seek(0)

            message = email.parser.BytesParser().parse(out)
            if message.is_multipart():
                for msg in message.get_payload():
                    if msg.is_multipart():
                        logging.warning('multipart msg is not expected')
                    else:
                        key, params = cgi.parse_header(
                            msg.get('content-disposition', ''))
                        params['data'] = msg.get_payload()
                        params['content-type'] = msg.get_content_type()
                        cte = msg.get('content-transfer-encoding')
                        if cte is not None:
                            resp['content-transfer-encoding'] = cte
                        resp['multipart-data'].append(params)
        body = json.dumps(resp, indent=4, sort_keys=True)

        # default headers
        hdrs = [('Connection', 'close'),
                ('Content-Type', 'application/json')]
        if chunked:
            hdrs.append(('Transfer-Encoding', 'chunked'))
        else:
            hdrs.append(('Content-Length', str(len(body))))

        # extra headers
        if headers:
            hdrs.extend(headers.items())

        if chunked:
            response.enable_chunked_encoding()

        # headers
        response.add_headers(*hdrs)
        response.send_headers()

        # write payload
        if write_body:
            try:
                write_body(response, body)
            except:
                return
        else:
            response.write(helpers.str_to_bytes(body))

        response.write_eof()

        # keep-alive
        if response.keep_alive():
            self._srv.keep_alive(True)


def unused_port():
    """ return a port that is unused on the current host. """
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

    @asyncio.coroutine
    def start_server(self):
        self._server = yield from self._loop.create_server(
            self._handler, self._address, self.port
        )

    @property
    def session(self):
        """a raw handler to the aiohttp.ClientSession.  unlike the methods on
        the TestClient, client session requests do not automatically
        include the host in the url queried, and will require an
        absolute path to the resource.
        """
        return self._session

    def request(self, method, path, *args, **kwargs):
        """ routes a request to the http server.
        the interface is identical to asyncio.request,
        except the loop kwarg is overriden
        by the instance used by the application.
        """
        return self._session.request(
            method, self._root + path, *args, **kwargs
        )

    def get(self, path, *args, **kwargs):
        """Perform an HTTP GET request. """
        return self.request(hdrs.METH_GET, path, *args, **kwargs)

    def post(self, path, *args, **kwargs):
        """Perform an HTTP POST request. """
        return self.request(hdrs.METH_POST, path, *args, **kwargs)

    def options(self, path, *args, **kwargs):
        """Perform an HTTP OPTIONS request. """
        return self.request(hdrs.METH_OPTIONS, path, *args, **kwargs)

    def head(self, path, *args, **kwargs):
        """Perform an HTTP HEAD request. """
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
        """Initiate websocket connection. the api is identical to
        aiohttp.ClientSession.ws_connect.
        """
        return self._session.ws_connect(
            self._root + path, *args, **kwargs
        )

    def close(self):
        """ close all fixtures created by the test client.
        After that point, the TestClient is no longer
        usable.

        This is an idempotent function: running close
        multiple times will not have any additional effects.

        close is also run when the object is garbage collected,
        and on exit when used as a context manager.
        """
        if not self._closed:
            loop = self._loop
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

    provides the following:

    * self.client (aiohttp.test_utils.TestClient): an aiohttp test client.
    * self.loop (asyncio.BaseEventLoop): the event loop in which the
        application and server are running.
    * self.app (aiohttp.web.Application): the application returned by
        self.get_app()

    note that the TestClient's methods are asynchronous: you will have to
    execute function on the test client using asynchronous methods.
    """

    def get_app(self, loop):
        """
        this method should be overriden
        to return the aiohttp.web.Application
        object to test.

        :param loop: the event_loop to use
        :type loop: asyncio.BaseEventLoop
        """
        pass

    def setUp(self):
        self.loop = setup_test_loop()
        self.app = self.get_app(self.loop)
        self.client = TestClient(self.app)

    def tearDown(self):
        del self.client
        teardown_test_loop(self.loop)


def unittest_run_loop(func):
    """a decorator that should be used with asynchronous methods of an
    AioHTTPTestCase. Handles executing an asynchronous function, using
    the self.loop of the AioHTTPTestCase.
    """

    @functools.wraps(func)
    def new_func(self):
        return self.loop.run_until_complete(func(self))

    return new_func


@contextlib.contextmanager
def loop_context():
    """a contextmanager that creates an event_loop, for test purposes.
    handles the creation and cleanup of a test loop.
    """
    loop = setup_test_loop()
    yield loop
    teardown_test_loop(loop)


def setup_test_loop():
    """create and return an asyncio.BaseEventLoop
    instance. The caller should also call teardown_test_loop,
    once they are done with the loop.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(None)
    return loop


def teardown_test_loop(loop):
    """teardown and cleanup an event_loop created
    by setup_test_loop.

    :param loop: the loop to teardown
    :type loop: asyncio.BaseEventLoop
    """
    is_closed = getattr(loop, 'is_closed')
    if is_closed is not None:
        closed = is_closed()
    else:
        closed = loop._closed
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


_not_set = object()


def make_mocked_request(method, path, headers=CIMultiDict(), *,
                        version=HttpVersion(1, 1), closing=False,
                        app=None,
                        reader=_not_set,
                        writer=_not_set,
                        transport=_not_set,
                        payload=_not_set,
                        sslcontext=None,
                        secure_proxy_ssl_header=None):
    """Creates mocked web.Request testing purposes. Useful in unit tests,
    when spinning full web server is overkill or specific conditions and
    errors is hard to trigger.

    :param method: str, that represents HTTP method, like; GET, POST.
    :type method: str

    :param path: str, The URL including *PATH INFO* without the host or scheme
    :type path: multidict.CIMultiDict

    :param headers: str, The URL including *PATH INFO* without the host
        or scheme
    :type headers: str

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
    message = RawRequestMessage(method, path, version, headers,
                                [(k.encode('utf-8'), v.encode('utf-8'))
                                 for k, v in headers.items()],
                                closing, False)
    if app is None:
        app = _create_app_mock()

    if reader is _not_set:
        reader = mock.Mock()

    if writer is _not_set:
        writer = mock.Mock()

    if transport is _not_set:
        transport = _create_transport(sslcontext)

    if payload is _not_set:
        payload = mock.Mock()

    from .web import Request
    req = Request(app, message, payload,
                  transport, reader, writer,
                  secure_proxy_ssl_header=secure_proxy_ssl_header)

    assert req.app is app
    assert req.content is payload
    assert req.transport is transport

    return req
