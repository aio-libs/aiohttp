"""Tests of http client with custom Connector"""

import asyncio
import http.cookies
import gc
import time
import socket
import unittest
import ssl
from unittest import mock

import aiohttp
from aiohttp import client
from aiohttp import test_utils
from aiohttp.client import ClientResponse, ClientRequest
from aiohttp.connector import Connection

from tests.test_client_functional import Functional


class HttpConnectionTests(unittest.TestCase):

    def setUp(self):
        self.key = object()
        self.connector = mock.Mock()
        self.request = mock.Mock()
        self.transport = mock.Mock()
        self.protocol = mock.Mock()
        self.loop = mock.Mock()

    def test_del(self):
        conn = Connection(
            self.connector, self.key, self.request,
            self.transport, self.protocol, self.loop)
        del conn
        self.assertTrue(self.transport.close.called)

    def test_close(self):
        conn = Connection(
            self.connector, self.key, self.request,
            self.transport, self.protocol, self.loop)
        conn.close()
        self.assertIsNone(conn._transport)
        self.connector._release.assert_called_with(
            self.key, self.request, self.transport, self.protocol,
            should_close=True)

    def test_release(self):
        conn = Connection(
            self.connector, self.key, self.request,
            self.transport, self.protocol, self.loop)
        conn.release()
        self.assertFalse(self.transport.close.called)
        self.assertIsNone(conn._transport)
        self.connector._release.assert_called_with(
            self.key, self.request, self.transport, self.protocol)

    def test_release_released(self):
        conn = Connection(
            self.connector, self.key, self.request,
            self.transport, self.protocol, self.loop)
        conn.release()
        self.connector._release.reset_mock()
        conn.release()
        self.assertFalse(self.transport.close.called)
        self.assertIsNone(conn._transport)
        self.assertFalse(self.connector._release.called)

    def test_no_share_cookies(self):
        connector = aiohttp.BaseConnector(share_cookies=False, loop=self.loop)

        conn = Connection(
            connector, self.key, self.request,
            self.transport, self.protocol, self.loop)
        self.assertEqual(connector.cookies, {})
        conn.share_cookies({'c1': 'cookie1'})
        self.assertEqual(connector.cookies, {})

    def test_share_cookies(self):
        connector = aiohttp.BaseConnector(share_cookies=True, loop=self.loop)

        conn = Connection(
            connector, self.key, self.request,
            self.transport, self.protocol, self.loop)
        self.assertEqual(connector.cookies, {})
        conn.share_cookies({'c1': 'cookie1'})
        self.assertEqual(connector.cookies,
                         http.cookies.SimpleCookie({'c1': 'cookie1'}))


class BaseConnectorTests(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

        self.transport = unittest.mock.Mock()
        self.stream = aiohttp.StreamParser()
        self.response = ClientResponse('get', 'http://python.org')

    def tearDown(self):
        self.loop.close()

    def test_del(self):
        conn = aiohttp.BaseConnector(loop=self.loop)
        transp = unittest.mock.Mock()
        conn._conns['a'] = [(transp, 'proto', 123)]

        conns_impl = conn._conns
        del conn
        self.assertFalse(conns_impl)
        transp.close.assert_called_with()

    def test_create_conn(self):
        conn = aiohttp.BaseConnector(loop=self.loop)
        self.assertRaises(
            NotImplementedError, conn._create_connection, object())

    @unittest.mock.patch('aiohttp.connector.asyncio')
    def test_ctor_loop(self, asyncio):
        session = aiohttp.BaseConnector()
        self.assertIs(session._loop, asyncio.get_event_loop.return_value)

    def test_close(self):
        tr = unittest.mock.Mock()

        conn = aiohttp.BaseConnector(loop=self.loop)
        conn._conns[1] = [(tr, object(), object())]
        conn.close()

        self.assertFalse(conn._conns)
        self.assertTrue(tr.close.called)

    def test_get(self):
        conn = aiohttp.BaseConnector(loop=self.loop)
        self.assertEqual(conn._get(1), (None, None))

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        conn._conns[1] = [(tr, proto, time.time())]
        self.assertEqual(conn._get(1), (tr, proto))

    def test_get_expired(self):
        conn = aiohttp.BaseConnector(loop=self.loop)
        self.assertEqual(conn._get(1), (None, None))

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        conn._conns[1] = [(tr, proto, time.time() - 1000)]
        self.assertEqual(conn._get(1), (None, None))
        self.assertEqual(conn._conns[1], [])

    @mock.patch('aiohttp.connector.time')
    def test_release(self, m_time):
        m_time.time.return_value = 10

        conn = aiohttp.BaseConnector(share_cookies=True, loop=self.loop)
        conn._start_cleanup_task = unittest.mock.Mock()
        req = unittest.mock.Mock()
        resp = req.response = unittest.mock.Mock()
        resp.message.should_close = False

        # cookies = resp.cookies = http.cookies.SimpleCookie()
        # cookies['c1'] = 'cookie1'
        # cookies['c2'] = 'cookie2'

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        conn._release(1, req, tr, proto)
        self.assertEqual(conn._conns[1][0], (tr, proto, 10))
        # self.assertEqual(conn.cookies, dict(cookies.items()))
        self.assertTrue(conn._start_cleanup_task.called)

    def test_release_close(self):
        conn = aiohttp.BaseConnector(share_cookies=True, loop=self.loop)
        req = unittest.mock.Mock()
        resp = unittest.mock.Mock()
        resp.message.should_close = True
        req.response = resp

        cookies = resp.cookies = http.cookies.SimpleCookie()
        cookies['c1'] = 'cookie1'
        cookies['c2'] = 'cookie2'

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        conn._release(1, req, tr, proto)
        self.assertFalse(conn._conns)
        self.assertTrue(tr.close.called)

    def test_release_pop_empty_conns(self):
        # see issue #253
        conn = aiohttp.BaseConnector(loop=self.loop)
        req = unittest.mock.Mock()
        resp = unittest.mock.Mock()
        resp.message.should_close = True
        req.response = resp

        key = ('127.0.0.1', 80, False)

        conn._conns[key] = []

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        conn._release(key, req, tr, proto)
        self.assertEqual({}, conn._conns)
        self.assertTrue(tr.close.called)

    def test_release_close_do_not_delete_existing_connections(self):
        key = ('127.0.0.1', 80, False)
        tr1, proto1 = unittest.mock.Mock(), unittest.mock.Mock()

        conn = aiohttp.BaseConnector(share_cookies=True, loop=self.loop)
        conn._conns[key] = [(tr1, proto1, 1)]
        req = unittest.mock.Mock()
        resp = unittest.mock.Mock()
        resp.message.should_close = True
        req.response = resp

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        conn._release(key, req, tr, proto)
        self.assertEqual(conn._conns[key], [(tr1, proto1, 1)])
        self.assertTrue(tr.close.called)

    @mock.patch('aiohttp.connector.time')
    def test_release_not_started(self, m_time):
        m_time.time.return_value = 10

        conn = aiohttp.BaseConnector(loop=self.loop)
        req = unittest.mock.Mock()
        req.response = None

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        conn._release(1, req, tr, proto)
        self.assertEqual(conn._conns, {1: [(tr, proto, 10)]})
        self.assertFalse(tr.close.called)

    def test_release_not_opened(self):
        conn = aiohttp.BaseConnector(loop=self.loop)
        req = unittest.mock.Mock()
        req.response = unittest.mock.Mock()
        req.response.message = None

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        conn._release(1, req, tr, proto)
        self.assertTrue(tr.close.called)

    def test_connect(self):
        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        proto.is_connected.return_value = True

        class Req:
            host = 'host'
            port = 80
            ssl = False

        conn = aiohttp.BaseConnector(loop=self.loop)
        key = ('host', 80, False)
        conn._conns[key] = [(tr, proto, time.time())]
        conn._create_connection = unittest.mock.Mock()
        conn._create_connection.return_value = asyncio.Future(loop=self.loop)
        conn._create_connection.return_value.set_result((tr, proto))

        connection = self.loop.run_until_complete(conn.connect(Req()))
        self.assertFalse(conn._create_connection.called)
        self.assertEqual(connection._transport, tr)
        self.assertEqual(connection._protocol, proto)
        self.assertIsInstance(connection, Connection)

    def test_connect_timeout(self):
        conn = aiohttp.BaseConnector(loop=self.loop)
        conn._create_connection = unittest.mock.Mock()
        conn._create_connection.return_value = asyncio.Future(loop=self.loop)
        conn._create_connection.return_value.set_exception(
            asyncio.TimeoutError())

        with self.assertRaises(aiohttp.ClientTimeoutError):
            req = unittest.mock.Mock()
            self.loop.run_until_complete(conn.connect(req))

    def test_connect_oserr(self):
        conn = aiohttp.BaseConnector(loop=self.loop)
        conn._create_connection = unittest.mock.Mock()
        conn._create_connection.return_value = asyncio.Future(loop=self.loop)
        conn._create_connection.return_value.set_exception(OSError())

        with self.assertRaises(aiohttp.ClientOSError):
            req = unittest.mock.Mock()
            self.loop.run_until_complete(conn.connect(req))

    def test_start_cleanup_task(self):
        loop = unittest.mock.Mock()
        conn = aiohttp.BaseConnector(loop=loop)
        self.assertIsNone(conn._cleanup_handle)

        conn._start_cleanup_task()
        self.assertIsNotNone(conn._cleanup_handle)
        loop.call_later.assert_called_with(
            conn._keepalive_timeout, conn._cleanup)

    @unittest.mock.patch('aiohttp.connector.time')
    def test_cleanup(self, time):
        time.time.return_value = 300

        testset = {
            1: [(unittest.mock.Mock(), unittest.mock.Mock(), 10),
                (unittest.mock.Mock(), unittest.mock.Mock(), 300),
                (None, unittest.mock.Mock(), 300)],
        }
        testset[1][0][1].is_connected.return_value = True
        testset[1][1][1].is_connected.return_value = False

        loop = unittest.mock.Mock()
        conn = aiohttp.BaseConnector(loop=loop)
        conn._conns = testset
        existing_handle = conn._cleanup_handle = unittest.mock.Mock()

        conn._cleanup()
        self.assertTrue(existing_handle.cancel.called)
        self.assertEqual(conn._conns, {})
        self.assertIsNone(conn._cleanup_handle)

        testset = {1: [(unittest.mock.Mock(), unittest.mock.Mock(), 300)]}
        testset[1][0][1].is_connected.return_value = True

        conn = aiohttp.BaseConnector(loop=loop)
        conn._conns = testset
        conn._cleanup()
        self.assertEqual(conn._conns, testset)

        self.assertIsNotNone(conn._cleanup_handle)

    def test_tcp_connector_ctor(self):
        conn = aiohttp.TCPConnector(loop=self.loop)
        self.assertTrue(conn.verify_ssl)
        self.assertFalse(conn.resolve)
        self.assertEqual(conn.family, socket.AF_INET)
        self.assertEqual(conn.resolved_hosts, {})

    def test_tcp_connector_clear_resolved_hosts(self):
        conn = aiohttp.TCPConnector(loop=self.loop)
        info = object()
        conn._resolved_hosts[('localhost', 123)] = info
        conn._resolved_hosts[('localhost', 124)] = info
        conn.clear_resolved_hosts('localhost', 123)
        self.assertEqual(
            conn.resolved_hosts, {('localhost', 124): info})
        conn.clear_resolved_hosts('localhost', 123)
        self.assertEqual(
            conn.resolved_hosts, {('localhost', 124): info})
        conn.clear_resolved_hosts()
        self.assertEqual(conn.resolved_hosts, {})

    def test_ambigous_verify_ssl_and_ssl_context(self):
        with self.assertRaises(ValueError):
            aiohttp.TCPConnector(
                verify_ssl=False,
                ssl_context=ssl.SSLContext(ssl.PROTOCOL_SSLv23))

    def test_dont_recreate_ssl_context(self):
        conn = aiohttp.TCPConnector(loop=self.loop)
        ctx = conn.ssl_context
        self.assertIs(ctx, conn.ssl_context)

    def test_respect_precreated_ssl_context(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        conn = aiohttp.TCPConnector(loop=self.loop, ssl_context=ctx)
        self.assertIs(ctx, conn.ssl_context)


class HttpClientConnectorTests(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        # just in case if we have transport close callbacks
        test_utils.run_briefly(self.loop)

        self.loop.close()
        gc.collect()

    def test_tcp_connector(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            r = self.loop.run_until_complete(
                client.request(
                    'get', httpd.url('method', 'get'),
                    connector=aiohttp.TCPConnector(loop=self.loop),
                    loop=self.loop))
            content = self.loop.run_until_complete(r.content.read())
            content = content.decode()
            self.assertEqual(r.status, 200)
            r.close()

    @unittest.skipUnless(hasattr(socket, 'AF_UNIX'), 'requires unix')
    def test_unix_connector(self):
        path = '/tmp/aiohttp_unix.sock'

        connector = aiohttp.UnixConnector(path, loop=self.loop)
        self.assertEqual(path, connector.path)

        with test_utils.run_server(
                self.loop, listen_addr=path, router=Functional) as httpd:
            r = self.loop.run_until_complete(
                client.request(
                    'get', httpd.url('method', 'get'),
                    connector=connector,
                    loop=self.loop))
            content = self.loop.run_until_complete(r.content.read())
            content = content.decode()
            self.assertEqual(r.status, 200)
            r.close()


class ProxyConnectorTests(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        # just in case if we have transport close callbacks
        test_utils.run_briefly(self.loop)

        self.loop.close()
        gc.collect()

    def _fake_coroutine(self, mock, return_value):

        def coro(*args, **kw):
            if isinstance(return_value, Exception):
                raise return_value
            return return_value
            yield  # pragma: no cover
        mock.side_effect = coro

    def test_ctor(self):
        with self.assertRaises(AssertionError):
            aiohttp.ProxyConnector('https://localhost:8118', loop=self.loop)

    def test_ctor2(self):
        connector = aiohttp.ProxyConnector('http://localhost:8118',
                                           loop=self.loop)

        self.assertEqual('http://localhost:8118', connector.proxy)

    @unittest.mock.patch('aiohttp.connector.ClientRequest')
    def test_connect(self, ClientRequestMock):
        req = ClientRequest('GET', 'http://www.python.org')
        self.assertEqual(req.path, '/')

        loop_mock = unittest.mock.Mock()
        connector = aiohttp.ProxyConnector('http://proxy.example.com',
                                           loop=loop_mock)
        self.assertIs(loop_mock, connector._loop)

        resolve_host = unittest.mock.Mock()
        self._fake_coroutine(resolve_host, [unittest.mock.MagicMock()])
        connector._resolve_host = resolve_host

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        self._fake_coroutine(loop_mock.create_connection, (tr, proto))
        conn = self.loop.run_until_complete(connector.connect(req))
        self.assertEqual(req.path, 'http://www.python.org/')
        self.assertIs(conn._transport, tr)
        self.assertIs(conn._protocol, proto)

        # resolve_host.assert_called_once_with('proxy.example.com', 80)
        self.assertEqual(tr.mock_calls, [])

        ClientRequestMock.assert_called_with(
            'GET', 'http://proxy.example.com',
            auth=None,
            headers={'Host': 'www.python.org'},
            loop=loop_mock)

    def test_proxy_auth(self):
        with self.assertRaises(AssertionError) as ctx:
            aiohttp.ProxyConnector('http://proxy.example.com',
                                   proxy_auth=('user', 'pass'),
                                   loop=unittest.mock.Mock())
        self.assertEqual(ctx.exception.args[0],
                         ("proxy_auth must be None or BasicAuth() tuple",
                          ('user', 'pass')))

    def test_proxy_connection_error(self):
        connector = aiohttp.ProxyConnector('http://proxy.example.com',
                                           loop=self.loop)
        connector._resolve_host = resolve_mock = unittest.mock.Mock()
        self._fake_coroutine(resolve_mock, OSError('dont take it serious'))

        req = ClientRequest('GET', 'http://www.python.org')
        expected_headers = dict(req.headers)
        with self.assertRaises(aiohttp.ProxyConnectionError):
            self.loop.run_until_complete(connector.connect(req))
        self.assertEqual(req.path, '/')
        self.assertEqual(dict(req.headers), expected_headers)

    @unittest.mock.patch('aiohttp.connector.ClientRequest')
    def test_auth(self, ClientRequestMock):
        proxy_req = ClientRequest('GET', 'http://proxy.example.com',
                                  auth=aiohttp.helpers.BasicAuth('user',
                                                                 'pass'))
        ClientRequestMock.return_value = proxy_req
        self.assertIn('AUTHORIZATION', proxy_req.headers)
        self.assertNotIn('PROXY-AUTHORIZATION', proxy_req.headers)

        loop_mock = unittest.mock.Mock()
        connector = aiohttp.ProxyConnector(
            'http://proxy.example.com', loop=loop_mock,
            proxy_auth=aiohttp.helpers.BasicAuth('user', 'pass'))
        connector._resolve_host = resolve_mock = unittest.mock.Mock()
        self._fake_coroutine(resolve_mock, [unittest.mock.MagicMock()])

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        self._fake_coroutine(loop_mock.create_connection, (tr, proto))

        req = ClientRequest('GET', 'http://www.python.org')
        self.assertNotIn('AUTHORIZATION', req.headers)
        self.assertNotIn('PROXY-AUTHORIZATION', req.headers)
        self.loop.run_until_complete(connector.connect(req))

        self.assertEqual(req.path, 'http://www.python.org/')
        self.assertNotIn('AUTHORIZATION', req.headers)
        self.assertIn('PROXY-AUTHORIZATION', req.headers)
        self.assertNotIn('AUTHORIZATION', proxy_req.headers)
        self.assertNotIn('PROXY-AUTHORIZATION', proxy_req.headers)

        ClientRequestMock.assert_called_with(
            'GET', 'http://proxy.example.com',
            auth=aiohttp.helpers.BasicAuth('user', 'pass'),
            loop=unittest.mock.ANY, headers=unittest.mock.ANY)

    def test_auth_utf8(self):
        proxy_req = ClientRequest(
            'GET', 'http://proxy.example.com',
            auth=aiohttp.helpers.BasicAuth('юзер', 'пасс', 'utf-8'))
        self.assertIn('AUTHORIZATION', proxy_req.headers)

    @unittest.mock.patch('aiohttp.connector.ClientRequest')
    def test_auth_from_url(self, ClientRequestMock):
        proxy_req = ClientRequest('GET', 'http://user:pass@proxy.example.com')
        ClientRequestMock.return_value = proxy_req
        self.assertIn('AUTHORIZATION', proxy_req.headers)
        self.assertNotIn('PROXY-AUTHORIZATION', proxy_req.headers)

        loop_mock = unittest.mock.Mock()
        connector = aiohttp.ProxyConnector(
            'http://user:pass@proxy.example.com', loop=loop_mock)
        connector._resolve_host = resolve_mock = unittest.mock.Mock()
        self._fake_coroutine(resolve_mock, [unittest.mock.MagicMock()])

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        self._fake_coroutine(loop_mock.create_connection, (tr, proto))

        req = ClientRequest('GET', 'http://www.python.org')
        self.assertNotIn('AUTHORIZATION', req.headers)
        self.assertNotIn('PROXY-AUTHORIZATION', req.headers)
        self.loop.run_until_complete(connector.connect(req))

        self.assertEqual(req.path, 'http://www.python.org/')
        self.assertNotIn('AUTHORIZATION', req.headers)
        self.assertIn('PROXY-AUTHORIZATION', req.headers)
        self.assertNotIn('AUTHORIZATION', proxy_req.headers)
        self.assertNotIn('PROXY-AUTHORIZATION', proxy_req.headers)

        ClientRequestMock.assert_called_with(
            'GET', 'http://user:pass@proxy.example.com',
            auth=None, loop=unittest.mock.ANY, headers=unittest.mock.ANY)

    @unittest.mock.patch('aiohttp.connector.ClientRequest')
    def test_auth__not_modifying_request(self, ClientRequestMock):
        proxy_req = ClientRequest('GET', 'http://user:pass@proxy.example.com')
        ClientRequestMock.return_value = proxy_req
        proxy_req_headers = dict(proxy_req.headers)

        loop_mock = unittest.mock.Mock()
        connector = aiohttp.ProxyConnector(
            'http://user:pass@proxy.example.com', loop=loop_mock)
        connector._resolve_host = resolve_mock = unittest.mock.Mock()
        self._fake_coroutine(resolve_mock, OSError('nothing personal'))

        req = ClientRequest('GET', 'http://www.python.org')
        req_headers = dict(req.headers)
        with self.assertRaises(aiohttp.ProxyConnectionError):
            self.loop.run_until_complete(connector.connect(req))
        self.assertEqual(req.headers, req_headers)
        self.assertEqual(req.path, '/')
        self.assertEqual(proxy_req.headers, proxy_req_headers)

    @unittest.mock.patch('aiohttp.connector.ClientRequest')
    def test_https_connect(self, ClientRequestMock):
        loop_mock = unittest.mock.Mock()
        proxy_req = ClientRequest('GET', 'http://proxy.example.com',
                                  loop=loop_mock)
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse('get', 'http://proxy.example.com')
        proxy_req.send = send_mock = unittest.mock.Mock()
        send_mock.return_value = proxy_resp
        proxy_resp.start = start_mock = unittest.mock.Mock()
        self._fake_coroutine(start_mock, unittest.mock.Mock(status=200))

        connector = aiohttp.ProxyConnector(
            'http://proxy.example.com', loop=loop_mock)

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        self._fake_coroutine(loop_mock.create_connection, (tr, proto))

        req = ClientRequest('GET', 'https://www.python.org')
        self.loop.run_until_complete(connector._create_connection(req))

        self.assertEqual(req.path, '/')
        self.assertEqual(proxy_req.method, 'CONNECT')
        self.assertEqual(proxy_req.path, 'www.python.org:443')
        tr.pause_reading.assert_called_once_with()
        tr.get_extra_info.assert_called_once_with('socket', default=None)

    @unittest.mock.patch('aiohttp.connector.ClientRequest')
    def test_https_connect_runtime_error(self, ClientRequestMock):
        loop_mock = unittest.mock.Mock()
        proxy_req = ClientRequest('GET', 'http://proxy.example.com',
                                  loop=loop_mock)
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse('get', 'http://proxy.example.com')
        proxy_req.send = send_mock = unittest.mock.Mock()
        send_mock.return_value = proxy_resp
        proxy_resp.start = start_mock = unittest.mock.Mock()
        self._fake_coroutine(start_mock, unittest.mock.Mock(status=200))

        connector = aiohttp.ProxyConnector(
            'http://proxy.example.com', loop=loop_mock)

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        tr.get_extra_info.return_value = None
        self._fake_coroutine(loop_mock.create_connection, (tr, proto))

        req = ClientRequest('GET', 'https://www.python.org')
        with self.assertRaisesRegex(
                RuntimeError, "Transport does not expose socket instance"):
            self.loop.run_until_complete(connector._create_connection(req))

    @unittest.mock.patch('aiohttp.connector.ClientRequest')
    def test_https_connect_http_proxy_error(self, ClientRequestMock):
        loop_mock = unittest.mock.Mock()
        proxy_req = ClientRequest('GET', 'http://proxy.example.com',
                                  loop=loop_mock)
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse('get', 'http://proxy.example.com')
        proxy_req.send = send_mock = unittest.mock.Mock()
        send_mock.return_value = proxy_resp
        proxy_resp.start = start_mock = unittest.mock.Mock()
        self._fake_coroutine(
            start_mock, unittest.mock.Mock(status=400, reason='bad request'))

        connector = aiohttp.ProxyConnector(
            'http://proxy.example.com', loop=loop_mock)

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        tr.get_extra_info.return_value = None
        self._fake_coroutine(loop_mock.create_connection, (tr, proto))

        req = ClientRequest('GET', 'https://www.python.org')
        with self.assertRaisesRegex(
                aiohttp.HttpProxyError, "400, message='bad request'"):
            self.loop.run_until_complete(connector._create_connection(req))

    @unittest.mock.patch('aiohttp.connector.ClientRequest')
    def test_https_connect_resp_start_error(self, ClientRequestMock):
        loop_mock = unittest.mock.Mock()
        proxy_req = ClientRequest('GET', 'http://proxy.example.com',
                                  loop=loop_mock)
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse('get', 'http://proxy.example.com')
        proxy_req.send = send_mock = unittest.mock.Mock()
        send_mock.return_value = proxy_resp
        proxy_resp.start = start_mock = unittest.mock.Mock()
        self._fake_coroutine(start_mock, OSError("error message"))

        connector = aiohttp.ProxyConnector(
            'http://proxy.example.com', loop=loop_mock)

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        tr.get_extra_info.return_value = None
        self._fake_coroutine(loop_mock.create_connection, (tr, proto))

        req = ClientRequest('GET', 'https://www.python.org')
        with self.assertRaisesRegex(OSError, "error message"):
            self.loop.run_until_complete(connector._create_connection(req))

    @unittest.mock.patch('aiohttp.connector.ClientRequest')
    def test_request_port(self, ClientRequestMock):
        proxy_req = ClientRequest('GET', 'http://proxy.example.com')
        ClientRequestMock.return_value = proxy_req

        loop_mock = unittest.mock.Mock()
        connector = aiohttp.ProxyConnector('http://proxy.example.com',
                                           loop=loop_mock)

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        tr.get_extra_info.return_value = None
        self._fake_coroutine(loop_mock.create_connection, (tr, proto))

        req = ClientRequest('GET', 'http://localhost:1234/path')
        self.loop.run_until_complete(connector._create_connection(req))
        self.assertEqual(req.path, 'http://localhost:1234/path')
