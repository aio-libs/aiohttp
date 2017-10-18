"""HTTP client functional tests."""

import asyncio
import binascii
import cgi
import contextlib
import email.parser
import gc
import http.server
import io
import json
import logging
import os
import os.path
import re
import ssl
import sys
import threading
import traceback
import unittest
import urllib.parse
from unittest import mock

from multidict import MultiDict

import aiohttp
import aiohttp.http
from aiohttp import client, helpers, test_utils, web
from aiohttp.multipart import MultipartWriter
from aiohttp.test_utils import run_briefly, unused_port


@contextlib.contextmanager
def run_server(loop, *, listen_addr=('127.0.0.1', 0),
               use_ssl=False, router=None):
    properties = {}
    transports = []

    class HttpRequestHandler:

        def __init__(self, addr):
            host, port = addr
            self.host = host
            self.port = port
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

    @asyncio.coroutine
    def handler(request):
        if properties.get('close', False):
            return

        for hdr, val in request.message.headers.items():
            if (hdr.upper() == 'EXPECT') and (val == '100-continue'):
                request.writer.write(b'HTTP/1.0 100 Continue\r\n\r\n')
                break

        rob = router(properties, request)
        return (yield from rob.dispatch())

    class TestHttpServer(web.RequestHandler):

        def connection_made(self, transport):
            transports.append(transport)
            super().connection_made(transport)

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

        host, port = listen_addr
        server_coroutine = thread_loop.create_server(
            lambda: TestHttpServer(
                web.Server(handler, loop=thread_loop), keepalive_timeout=0.5),
            host, port, ssl=sslcontext)
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

    def __init__(self, props, request):
        # headers
        self._headers = http.client.HTTPMessage()
        for hdr, val in request.message.headers.items():
            self._headers.add_header(hdr, val)

        self._props = props
        self._request = request
        self._method = request.message.method
        self._uri = request.message.path
        self._version = request.message.version
        self._compression = request.message.compression
        self._body = request.content

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
                    return (yield from getattr(self, fn)(match))
                except Exception:
                    out = io.StringIO()
                    traceback.print_exc(file=out)
                    return (yield from self._response(500, out.getvalue()))

                return ()

        return (yield from self._response(self._start_response(404)))

    def _start_response(self, code):
        return web.Response(status=code)

    @asyncio.coroutine
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
            'origin': self._request.transport.get_extra_info('addr', ' ')[0],
            'query': self._query,
            'form': {},
            'compression': cmod,
            'multipart-data': []
        }
        if body:  # pragma: no cover
            resp['content'] = body
        else:
            resp['content'] = (
                yield from self._request.read()).decode('utf-8', 'ignore')

        ct = self._headers.get('content-type', '').lower()

        # application/x-www-form-urlencoded
        if ct == 'application/x-www-form-urlencoded':
            resp['form'] = urllib.parse.parse_qs(self._body.decode('latin1'))

        # multipart/form-data
        elif ct.startswith('multipart/form-data'):  # pragma: no cover
            out = io.BytesIO()
            for key, val in self._headers.items():
                out.write(bytes('{}: {}\r\n'.format(key, val), 'latin1'))

            b = yield from self._request.read()
            out.write(b'\r\n')
            out.write(b)
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

        # headers
        for key, val in hdrs:
            response.headers[key] = val

        if chunked:
            self._request.writer.enable_chunking()

        yield from response.prepare(self._request)

        # write payload
        if write_body:
            try:
                write_body(response, body)
            except:
                return
        else:
            response.write(body.encode('utf8'))

        return response


class Functional(Router):

    @Router.define('/method/([A-Za-z]+)$')
    def method(self, match):
        return self._response(self._start_response(200))

    @Router.define('/keepalive$')
    def keepalive(self, match):
        transport = self._request.transport

        transport._requests = getattr(transport, '_requests', 0) + 1
        resp = self._start_response(200)
        if 'close=' in self._query:
            return self._response(
                resp, 'requests={}'.format(transport._requests))
        else:
            return self._response(
                resp, 'requests={}'.format(transport._requests),
                headers={'CONNECTION': 'keep-alive'})

    @Router.define('/cookies$')
    def cookies(self, match):
        cookies = helpers.SimpleCookie()
        cookies['c1'] = 'cookie1'
        cookies['c2'] = 'cookie2'

        resp = self._start_response(200)
        for cookie in cookies.output(header='').split('\n'):
            resp.headers.extend({'Set-Cookie': cookie.strip()})

        resp.headers.extend(
            {'Set-Cookie':
             'ISAWPLB{A7F52349-3531-4DA9-8776-F74BC6F4F1BB}='
             '{925EC0B8-CB17-4BEB-8A35-1033813B0523}; HttpOnly; Path=/'})

        return self._response(resp)

    @Router.define('/cookies_partial$')
    def cookies_partial(self, match):
        cookies = helpers.SimpleCookie()
        cookies['c1'] = 'other_cookie1'

        resp = self._start_response(200)
        for cookie in cookies.output(header='').split('\n'):
            resp.add_header('Set-Cookie', cookie.strip())

        return self._response(resp)

    @Router.define('/broken$')
    def broken(self, match):
        resp = self._start_response(200)

        def write_body(resp, body):
            self._transport.close()
            raise ValueError()

        return self._response(
            resp,
            body=json.dumps({'t': (b'0' * 1024).decode('utf-8')}),
            write_body=write_body)


class TestHttpClientFunctional(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        # just in case if we have transport close callbacks
        test_utils.run_briefly(self.loop)

        self.loop.close()
        gc.collect()

    def test_POST_DATA_with_charset(self):
        with run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')

            form = aiohttp.FormData()
            form.add_field('name', 'текст',
                           content_type='text/plain; charset=koi8-r')

            session = client.ClientSession(loop=self.loop)
            r = self.loop.run_until_complete(
                session.request('post', url, data=form))
            content = self.loop.run_until_complete(r.json())

            self.assertEqual(1, len(content['multipart-data']))
            field = content['multipart-data'][0]
            self.assertEqual('name', field['name'])
            self.assertEqual('текст', field['data'])
            self.assertEqual(r.status, 200)
            r.close()
            session.close()

    def test_POST_DATA_with_charset_pub_request(self):
        with run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')

            form = aiohttp.FormData()
            form.add_field('name', 'текст',
                           content_type='text/plain; charset=koi8-r')

            r = self.loop.run_until_complete(
                aiohttp.request('post', url, data=form, loop=self.loop))
            content = self.loop.run_until_complete(r.json())

            self.assertEqual(1, len(content['multipart-data']))
            field = content['multipart-data'][0]
            self.assertEqual('name', field['name'])
            self.assertEqual('текст', field['data'])
            self.assertEqual(r.status, 200)
            r.close()

    def test_POST_DATA_with_content_transfer_encoding(self):
        with run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')

            form = aiohttp.FormData()
            form.add_field('name', b'123',
                           content_transfer_encoding='base64')

            session = client.ClientSession(loop=self.loop)
            r = self.loop.run_until_complete(
                session.request('post', url, data=form))
            content = self.loop.run_until_complete(r.json())

            self.assertEqual(1, len(content['multipart-data']))
            field = content['multipart-data'][0]
            self.assertEqual('name', field['name'])
            self.assertEqual(b'123', binascii.a2b_base64(field['data']))
            # self.assertEqual('base64', field['content-transfer-encoding'])
            self.assertEqual(r.status, 200)

            r.close()
            session.close()

    def test_POST_MULTIPART(self):
        with run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')

            with MultipartWriter('form-data') as writer:
                writer.append('foo')
                writer.append_json({'bar': 'баз'})
                writer.append_form([('тест', '4'), ('сетс', '2')])

            session = client.ClientSession(loop=self.loop)
            r = self.loop.run_until_complete(
                session.request('post', url, data=writer))

            content = self.loop.run_until_complete(r.json())

            self.assertEqual(3, len(content['multipart-data']))
            self.assertEqual({'content-type': 'text/plain', 'data': 'foo'},
                             content['multipart-data'][0])
            self.assertEqual({'content-type': 'application/json',
                              'data': '{"bar": "\\u0431\\u0430\\u0437"}'},
                             content['multipart-data'][1])
            self.assertEqual(
                {'content-type': 'application/x-www-form-urlencoded',
                 'data': '%D1%82%D0%B5%D1%81%D1%82=4&'
                         '%D1%81%D0%B5%D1%82%D1%81=2'},
                content['multipart-data'][2])
            self.assertEqual(r.status, 200)
            r.close()
            session.close()

    def test_POST_STREAM_DATA(self):
        with run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')

            here = os.path.dirname(__file__)
            fname = os.path.join(here, 'sample.key')

            with open(fname, 'rb') as f:
                data = f.read()

            fut = helpers.create_future(self.loop)

            @aiohttp.streamer
            def stream(writer):
                yield from fut
                writer.write(data)

            self.loop.call_later(0.01, fut.set_result, True)

            session = client.ClientSession(loop=self.loop)
            r = self.loop.run_until_complete(
                session.request(
                    'post', url, data=stream(),
                    headers={'Content-Length': str(len(data))}))
            content = self.loop.run_until_complete(r.json())
            r.close()
            session.close()

            self.assertEqual(str(len(data)),
                             content['headers']['Content-Length'])
            self.assertEqual('application/octet-stream',
                             content['headers']['Content-Type'])

    def test_POST_StreamReader(self):
        with run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')

            here = os.path.dirname(__file__)
            fname = os.path.join(here, 'sample.key')

            with open(fname, 'rb') as f:
                data = f.read()

            stream = aiohttp.StreamReader(loop=self.loop)
            stream.feed_data(data)
            stream.feed_eof()

            session = client.ClientSession(loop=self.loop)
            r = self.loop.run_until_complete(
                session.request(
                    'post', url, data=stream,
                    headers={'Content-Length': str(len(data))}))
            content = self.loop.run_until_complete(r.json())
            r.close()
            session.close()

            self.assertEqual(str(len(data)),
                             content['headers']['Content-Length'])

    def test_POST_DataQueue(self):
        with run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')

            here = os.path.dirname(__file__)
            fname = os.path.join(here, 'sample.key')

            with open(fname, 'rb') as f:
                data = f.read()

            stream = aiohttp.DataQueue(loop=self.loop)
            stream.feed_data(data[:100], 100)
            stream.feed_data(data[100:], len(data[100:]))
            stream.feed_eof()

            session = client.ClientSession(loop=self.loop)
            r = self.loop.run_until_complete(
                session.request(
                    'post', url, data=stream,
                    headers={'Content-Length': str(len(data))}))
            content = self.loop.run_until_complete(r.json())
            r.close()
            session.close()

            self.assertEqual(str(len(data)),
                             content['headers']['Content-Length'])

    def test_POST_ChunksQueue(self):
        with run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')

            here = os.path.dirname(__file__)
            fname = os.path.join(here, 'sample.key')

            with open(fname, 'rb') as f:
                data = f.read()

            stream = aiohttp.ChunksQueue(loop=self.loop)
            stream.feed_data(data[:100], 100)

            d = data[100:]
            stream.feed_data(d, len(d))
            stream.feed_eof()

            session = client.ClientSession(loop=self.loop)
            r = self.loop.run_until_complete(
                session.request(
                    'post', url, data=stream,
                    headers={'Content-Length': str(len(data))}))
            content = self.loop.run_until_complete(r.json())
            r.close()
            session.close()

            self.assertEqual(str(len(data)),
                             content['headers']['Content-Length'])

    def test_request_conn_closed(self):
        with run_server(self.loop, router=Functional) as httpd:
            httpd['close'] = True
            session = client.ClientSession(loop=self.loop)
            with self.assertRaises(aiohttp.ServerDisconnectedError):
                self.loop.run_until_complete(
                    session.request('get', httpd.url('method', 'get')))

            session.close()

    def test_session_close(self):
        conn = aiohttp.TCPConnector(loop=self.loop)
        session = client.ClientSession(loop=self.loop, connector=conn)

        with run_server(self.loop, router=Functional) as httpd:
            r = self.loop.run_until_complete(
                session.request(
                    'get', httpd.url('keepalive') + '?close=1'))
            self.assertEqual(r.status, 200)
            content = self.loop.run_until_complete(r.json())
            self.assertEqual(content['content'], 'requests=1')
            r.close()

            r = self.loop.run_until_complete(
                session.request('get', httpd.url('keepalive')))
            self.assertEqual(r.status, 200)
            content = self.loop.run_until_complete(r.json())
            self.assertEqual(content['content'], 'requests=1')
            r.close()

        session.close()
        conn.close()

    def test_multidict_headers(self):
        session = client.ClientSession(loop=self.loop)
        with run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')

            data = b'sample data'

            r = self.loop.run_until_complete(
                session.request(
                    'post', url, data=data,
                    headers=MultiDict(
                        {'Content-Length': str(len(data))})))
            content = self.loop.run_until_complete(r.json())
            r.close()

            self.assertEqual(str(len(data)),
                             content['headers']['Content-Length'])

        session.close()

    def test_dont_close_explicit_connector(self):

        @asyncio.coroutine
        def go(url):
            connector = aiohttp.TCPConnector(loop=self.loop)
            session = client.ClientSession(loop=self.loop, connector=connector)

            r = yield from session.request('GET', url)
            yield from r.read()
            self.assertEqual(1, len(connector._conns))
            connector.close()
            session.close()

        with run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('keepalive')
            self.loop.run_until_complete(go(url))

    def test_server_close_keepalive_connection(self):

        class Proto(asyncio.Protocol):

            def connection_made(self, transport):
                self.transp = transport
                self.data = b''

            def data_received(self, data):
                self.data += data
                if data.endswith(b'\r\n\r\n'):
                    self.transp.write(
                        b'HTTP/1.1 200 OK\r\n'
                        b'CONTENT-LENGTH: 2\r\n'
                        b'CONNECTION: close\r\n'
                        b'\r\n'
                        b'ok')
                    self.transp.close()

            def connection_lost(self, exc):
                self.transp = None

        @asyncio.coroutine
        def go():
            server = yield from self.loop.create_server(
                Proto, '127.0.0.1', unused_port())

            addr = server.sockets[0].getsockname()

            connector = aiohttp.TCPConnector(loop=self.loop, limit=1)
            session = client.ClientSession(loop=self.loop, connector=connector)

            url = 'http://{}:{}/'.format(*addr)
            for i in range(2):
                r = yield from session.request('GET', url)
                yield from r.read()
                self.assertEqual(0, len(connector._conns))
            session.close()
            connector.close()
            server.close()
            yield from server.wait_closed()

        self.loop.run_until_complete(go())

    def test_handle_keepalive_on_closed_connection(self):

        class Proto(asyncio.Protocol):

            def connection_made(self, transport):
                self.transp = transport
                self.data = b''

            def data_received(self, data):
                self.data += data
                if data.endswith(b'\r\n\r\n'):
                    self.transp.write(
                        b'HTTP/1.1 200 OK\r\n'
                        b'CONTENT-LENGTH: 2\r\n'
                        b'\r\n'
                        b'ok')
                    self.transp.close()

            def connection_lost(self, exc):
                self.transp = None

        @asyncio.coroutine
        def go():
            server = yield from self.loop.create_server(
                Proto, '127.0.0.1', unused_port())

            addr = server.sockets[0].getsockname()

            connector = aiohttp.TCPConnector(loop=self.loop, limit=1)
            session = client.ClientSession(loop=self.loop, connector=connector)

            url = 'http://{}:{}/'.format(*addr)

            r = yield from session.request('GET', url)
            yield from r.read()
            self.assertEqual(1, len(connector._conns))

            with self.assertRaises(aiohttp.ServerDisconnectedError):
                yield from session.request('GET', url)
            self.assertEqual(0, len(connector._conns))

            session.close()
            connector.close()
            server.close()
            yield from server.wait_closed()

        self.loop.run_until_complete(go())

    @mock.patch('aiohttp.client_reqrep.client_logger')
    def test_session_cookies(self, m_log):
        with run_server(self.loop, router=Functional) as httpd:
            session = client.ClientSession(loop=self.loop)

            resp = self.loop.run_until_complete(
                session.request('get', httpd.url('cookies')))
            self.assertEqual(resp.cookies['c1'].value, 'cookie1')
            self.assertEqual(resp.cookies['c2'].value, 'cookie2')
            resp.close()

            # Add the received cookies as shared for sending them to the test
            # server, which is only accessible via IP
            session.cookie_jar.update_cookies(resp.cookies)

            # Assert, that we send those cookies in next requests
            r = self.loop.run_until_complete(
                session.request('get', httpd.url('method', 'get')))
            self.assertEqual(r.status, 200)
            content = self.loop.run_until_complete(r.json())
            self.assertEqual(
                content['headers']['Cookie'], 'c1=cookie1; c2=cookie2')
            r.close()
            session.close()

    def test_session_headers(self):
        with run_server(self.loop, router=Functional) as httpd:
            session = client.ClientSession(
                loop=self.loop, headers={
                    "X-Real-IP": "192.168.0.1"
                })

            r = self.loop.run_until_complete(
                session.request('get', httpd.url('method', 'get')))
            self.assertEqual(r.status, 200)
            content = self.loop.run_until_complete(r.json())
            self.assertIn(
                "X-Real-Ip", content['headers'])
            self.assertEqual(
                content['headers']["X-Real-Ip"], "192.168.0.1")
            r.close()
            session.close()

    def test_session_headers_merge(self):
        with run_server(self.loop, router=Functional) as httpd:
            session = client.ClientSession(
                loop=self.loop, headers=[
                    ("X-Real-IP", "192.168.0.1"),
                    ("X-Sent-By", "requests")])

            r = self.loop.run_until_complete(
                session.request('get', httpd.url('method', 'get'),
                                headers={"X-Sent-By": "aiohttp"}))
            self.assertEqual(r.status, 200)
            content = self.loop.run_until_complete(r.json())
            self.assertIn(
                "X-Real-Ip", content['headers'])
            self.assertIn(
                "X-Sent-By", content['headers'])
            self.assertEqual(
                content['headers']["X-Real-Ip"], "192.168.0.1")
            self.assertEqual(
                content['headers']["X-Sent-By"], "aiohttp")
            r.close()
            session.close()

    def test_session_auth(self):
        with run_server(self.loop, router=Functional) as httpd:
            session = client.ClientSession(
                loop=self.loop, auth=helpers.BasicAuth("login", "pass"))

            r = self.loop.run_until_complete(
                session.request('get', httpd.url('method', 'get')))
            self.assertEqual(r.status, 200)
            content = self.loop.run_until_complete(r.json())
            self.assertIn(
                "Authorization", content['headers'])
            self.assertEqual(
                content['headers']["Authorization"], "Basic bG9naW46cGFzcw==")
            r.close()
            session.close()

    def test_session_auth_override(self):
        with run_server(self.loop, router=Functional) as httpd:
            session = client.ClientSession(
                loop=self.loop, auth=helpers.BasicAuth("login", "pass"))

            r = self.loop.run_until_complete(
                session.request('get', httpd.url('method', 'get'),
                                auth=helpers.BasicAuth("other_login", "pass")))
            self.assertEqual(r.status, 200)
            content = self.loop.run_until_complete(r.json())
            self.assertIn(
                "Authorization", content['headers'])
            self.assertEqual(
                content['headers']["Authorization"],
                "Basic b3RoZXJfbG9naW46cGFzcw==")
            r.close()
            session.close()

    def test_session_auth_header_conflict(self):
        with run_server(self.loop, router=Functional) as httpd:
            session = client.ClientSession(
                loop=self.loop, auth=helpers.BasicAuth("login", "pass"))

            headers = {'Authorization': "Basic b3RoZXJfbG9naW46cGFzcw=="}
            with self.assertRaises(ValueError):
                self.loop.run_until_complete(
                    session.request('get', httpd.url('method', 'get'),
                                    headers=headers))
            session.close()
