"""Tests of http client with custom Connector"""

import asyncio
import http.cookies
import gc
import time
import socket
import unittest
from unittest import mock

import aiohttp
from aiohttp import client
from aiohttp import test_utils
from aiohttp.client import HttpResponse, HttpRequest
from aiohttp.connector import Connection

from tests.test_client_functional import Functional


class HttpConnectionTests(unittest.TestCase):

    def setUp(self):
        self.key = object()
        self.connector = mock.Mock()
        self.request = mock.Mock()
        self.transport = mock.Mock()
        self.protocol = mock.Mock()

    def test_del(self):
        conn = Connection(
            self.connector, self.key, self.request,
            self.transport, self.protocol)
        del conn
        self.assertTrue(self.transport.close.called)

    def test_close(self):
        conn = Connection(
            self.connector, self.key, self.request,
            self.transport, self.protocol)
        conn.close()
        self.assertTrue(self.transport.close.called)
        self.assertIsNone(conn._transport)

    def test_release(self):
        conn = Connection(
            self.connector, self.key, self.request,
            self.transport, self.protocol)
        conn.release()
        self.assertFalse(self.transport.close.called)
        self.assertIsNone(conn._transport)
        self.connector._release.assert_called_with(
            self.key, self.request, self.transport, self.protocol)


class BaseConnectorTests(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

        self.transport = unittest.mock.Mock()
        self.stream = aiohttp.StreamParser()
        self.response = HttpResponse('get', 'http://python.org')

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
        conn._conns[1] = [(tr, proto, time.time()-1000)]
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

        cookies = resp.cookies = http.cookies.SimpleCookie()
        cookies['c1'] = 'cookie1'
        cookies['c2'] = 'cookie2'

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        conn._release(1, req, tr, proto)
        self.assertEqual(conn._conns[1][0], (tr, proto, 10))
        self.assertEqual(conn.cookies, dict(cookies.items()))
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

    def test_start_cleanup_task(self):
        loop = unittest.mock.Mock()
        conn = aiohttp.BaseConnector(loop=loop)
        self.assertIsNone(conn._cleanup_handle)

        conn._start_cleanup_task()
        self.assertIsNotNone(conn._cleanup_handle)
        loop.call_later.assert_called_with(
            conn._reuse_timeout, conn._cleanup)

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

        with test_utils.run_server(
                self.loop, listen_addr=path, router=Functional) as httpd:
            r = self.loop.run_until_complete(
                client.request(
                    'get', httpd.url('method', 'get'),
                    connector=aiohttp.UnixConnector(
                        path, loop=self.loop),
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

    def test_ctor(self):
        proxies = {
            'https': 'https://localhost:8118',
        }
        self.assertRaises(
            NotImplementedError,
            aiohttp.connector.ProxyConnector, loop=self.loop, proxies=proxies)

    def test_proxy_connector(self):
        proxies = {
            'http': 'http://localhost:8118',
        }
        proxy_connector = aiohttp.connector.ProxyConnector(
            loop=self.loop, proxies=proxies)
        req = HttpRequest('get', 'http://python.org/')

        @asyncio.coroutine
        def connect_coroutine(*args, **kwargs):
            return Connection(
                mock.Mock(), mock.Mock(), mock.Mock(), mock.Mock(), mock.Mock()
            )

        with mock.patch('aiohttp.connector.BaseConnector.connect') \
                as mocked_base_connect:

            mocked_base_connect.return_value = connect_coroutine()
            connection = self.loop.run_until_complete(
                proxy_connector.connect(req))
            self.assertEqual(connection._request.url, req.url)
            self.assertTrue(mocked_base_connect.called)
            self.assertEqual(
                mocked_base_connect.call_args[0][0].url, proxies[req.scheme])
