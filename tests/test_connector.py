"""Tests of http client with custom Connector"""

import asyncio
import http.cookies
import gc
import socket
import unittest
import ssl
import sys
from unittest import mock

import aiohttp
from aiohttp import client
from aiohttp import test_utils
from aiohttp.errors import FingerprintMismatch
from aiohttp.client import ClientResponse, ClientRequest
from aiohttp.connector import Connection

from tests.test_client_functional import Functional

PY_341 = sys.version_info >= (3, 4, 1)


class TestHttpConnection(unittest.TestCase):

    def setUp(self):
        self.key = object()
        self.connector = mock.Mock()
        self.request = mock.Mock()
        self.transport = mock.Mock()
        self.protocol = mock.Mock()
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    @unittest.skipUnless(PY_341, "Requires Python 3.4.1+")
    def test_del(self):
        conn = Connection(
            self.connector, self.key, self.request,
            self.transport, self.protocol, self.loop)
        exc_handler = unittest.mock.Mock()
        self.loop.set_exception_handler(exc_handler)

        with self.assertWarns(ResourceWarning):
            del conn
            gc.collect()

        self.connector._release.assert_called_with(self.key,
                                                   self.request,
                                                   self.transport,
                                                   self.protocol,
                                                   should_close=True)
        msg = {'client_connection': unittest.mock.ANY,  # conn was deleted
               'message': 'Unclosed connection'}
        if self.loop.get_debug():
            msg['source_traceback'] = unittest.mock.ANY
        exc_handler.assert_called_with(self.loop, msg)

    def test_close(self):
        conn = Connection(
            self.connector, self.key, self.request,
            self.transport, self.protocol, self.loop)
        self.assertFalse(conn.closed)
        conn.close()
        self.assertIsNone(conn._transport)
        self.connector._release.assert_called_with(
            self.key, self.request, self.transport, self.protocol,
            should_close=True)
        self.assertTrue(conn.closed)

    def test_release(self):
        conn = Connection(
            self.connector, self.key, self.request,
            self.transport, self.protocol, self.loop)
        self.assertFalse(conn.closed)
        conn.release()
        self.assertFalse(self.transport.close.called)
        self.assertIsNone(conn._transport)
        self.connector._release.assert_called_with(
            self.key, self.request, self.transport, self.protocol,
            should_close=False)
        self.assertTrue(conn.closed)

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

    def test_detach(self):
        conn = Connection(
            self.connector, self.key, self.request,
            self.transport, self.protocol, self.loop)
        self.assertFalse(conn.closed)
        conn.detach()
        self.assertIsNone(conn._transport)
        self.assertFalse(self.connector._release.called)
        self.assertTrue(conn.closed)


class TestBaseConnector(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

        self.transport = unittest.mock.Mock()
        self.stream = aiohttp.StreamParser()
        self.response = ClientResponse('get', 'http://python.org')
        self.response._loop = self.loop

    def tearDown(self):
        self.loop.close()
        gc.collect()

    @unittest.skipUnless(PY_341, "Requires Python 3.4.1+")
    def test_del(self):
        conn = aiohttp.BaseConnector(loop=self.loop)
        transp = unittest.mock.Mock()
        conn._conns['a'] = [(transp, 'proto', 123)]
        conns_impl = conn._conns

        exc_handler = unittest.mock.Mock()
        self.loop.set_exception_handler(exc_handler)

        with self.assertWarns(ResourceWarning):
            del conn
            gc.collect()

        self.assertFalse(conns_impl)
        transp.close.assert_called_with()
        msg = {'connector': unittest.mock.ANY,  # conn was deleted
               'message': 'Unclosed connector'}
        if self.loop.get_debug():
            msg['source_traceback'] = unittest.mock.ANY
        exc_handler.assert_called_with(self.loop, msg)

    @unittest.skipUnless(PY_341, "Requires Python 3.4.1+")
    def test_del_with_scheduled_cleanup(self):
        conn = aiohttp.BaseConnector(loop=self.loop, keepalive_timeout=0.01)
        transp = unittest.mock.Mock()
        conn._conns['a'] = [(transp, 'proto', 123)]

        conns_impl = conn._conns
        conn._start_cleanup_task()
        exc_handler = unittest.mock.Mock()
        self.loop.set_exception_handler(exc_handler)

        with self.assertWarns(ResourceWarning):
            del conn
            yield from asyncio.sleep(0.01)
            gc.collect()

        self.assertFalse(conns_impl)
        transp.close.assert_called_with()
        msg = {'connector': unittest.mock.ANY,  # conn was deleted
               'message': 'Unclosed connector'}
        if self.loop.get_debug():
            msg['source_traceback'] = unittest.mock.ANY
        exc_handler.assert_called_with(self.loop, msg)

    @unittest.skipUnless(PY_341, "Requires Python 3.4.1+")
    def test_del_with_closed_loop(self):
        conn = aiohttp.BaseConnector(loop=self.loop)
        transp = unittest.mock.Mock()
        conn._conns['a'] = [(transp, 'proto', 123)]

        conns_impl = conn._conns
        conn._start_cleanup_task()
        exc_handler = unittest.mock.Mock()
        self.loop.set_exception_handler(exc_handler)
        self.loop.close()

        with self.assertWarns(ResourceWarning):
            del conn
            gc.collect()

        self.assertFalse(conns_impl)
        self.assertFalse(transp.close.called)
        self.assertTrue(exc_handler.called)

    @unittest.skipUnless(PY_341, "Requires Python 3.4.1+")
    def test_del_empty_conector(self):
        conn = aiohttp.BaseConnector(loop=self.loop)

        exc_handler = unittest.mock.Mock()
        self.loop.set_exception_handler(exc_handler)

        del conn

        self.assertFalse(exc_handler.called)

    def test_create_conn(self):

        def go():
            conn = aiohttp.BaseConnector(loop=self.loop)
            with self.assertRaises(NotImplementedError):
                yield from conn._create_connection(object())

        self.loop.run_until_complete(go())

    @unittest.mock.patch('aiohttp.connector.asyncio')
    def test_ctor_loop(self, asyncio):
        session = aiohttp.BaseConnector()
        self.assertIs(session._loop, asyncio.get_event_loop.return_value)

    def test_close(self):
        tr = unittest.mock.Mock()

        conn = aiohttp.BaseConnector(loop=self.loop)
        self.assertFalse(conn.closed)
        conn._conns[1] = [(tr, object(), object())]
        conn.close()

        self.assertFalse(conn._conns)
        self.assertTrue(tr.close.called)
        self.assertTrue(conn.closed)

    def test_get(self):
        conn = aiohttp.BaseConnector(loop=self.loop)
        self.assertEqual(conn._get(1), (None, None))

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        conn._conns[1] = [(tr, proto, self.loop.time())]
        self.assertEqual(conn._get(1), (tr, proto))
        conn.close()

    def test_get_expired(self):
        conn = aiohttp.BaseConnector(loop=self.loop)
        self.assertEqual(conn._get(1), (None, None))

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        conn._conns[1] = [(tr, proto, self.loop.time() - 1000)]
        self.assertEqual(conn._get(1), (None, None))
        self.assertFalse(conn._conns)
        conn.close()

    def test_release(self):
        self.loop.time = mock.Mock(return_value=10)

        conn = aiohttp.BaseConnector(loop=self.loop)
        conn._start_cleanup_task = unittest.mock.Mock()
        req = unittest.mock.Mock()
        resp = req.response = unittest.mock.Mock()
        resp.message.should_close = False

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        key = 1
        conn._acquired[key].add(tr)
        conn._release(key, req, tr, proto)
        self.assertEqual(conn._conns[1][0], (tr, proto, 10))
        self.assertTrue(conn._start_cleanup_task.called)
        conn.close()

    def test_release_close(self):
        with self.assertWarns(DeprecationWarning):
            conn = aiohttp.BaseConnector(share_cookies=True, loop=self.loop)
        req = unittest.mock.Mock()
        resp = unittest.mock.Mock()
        resp.message.should_close = True
        req.response = resp

        cookies = resp.cookies = http.cookies.SimpleCookie()
        cookies['c1'] = 'cookie1'
        cookies['c2'] = 'cookie2'

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        key = 1
        conn._acquired[key].add(tr)
        conn._release(key, req, tr, proto)
        self.assertFalse(conn._conns)
        self.assertTrue(tr.close.called)

    def test_get_pop_empty_conns(self):
        # see issue #473
        conn = aiohttp.BaseConnector(loop=self.loop)
        key = ('127.0.0.1', 80, False)
        conn._conns[key] = []
        tr, proto = conn._get(key)
        self.assertEqual((None, None), (tr, proto))
        self.assertFalse(conn._conns)

    def test_release_close_do_not_add_to_pool(self):
        # see issue #473
        conn = aiohttp.BaseConnector(loop=self.loop)
        req = unittest.mock.Mock()
        resp = unittest.mock.Mock()
        resp.message.should_close = True
        req.response = resp

        key = ('127.0.0.1', 80, False)

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        conn._acquired[key].add(tr)
        conn._release(key, req, tr, proto)
        self.assertFalse(conn._conns)

    def test_release_close_do_not_delete_existing_connections(self):
        key = ('127.0.0.1', 80, False)
        tr1, proto1 = unittest.mock.Mock(), unittest.mock.Mock()

        with self.assertWarns(DeprecationWarning):
            conn = aiohttp.BaseConnector(share_cookies=True, loop=self.loop)
        conn._conns[key] = [(tr1, proto1, 1)]
        req = unittest.mock.Mock()
        resp = unittest.mock.Mock()
        resp.message.should_close = True
        req.response = resp

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        conn._acquired[key].add(tr1)
        conn._release(key, req, tr, proto)
        self.assertEqual(conn._conns[key], [(tr1, proto1, 1)])
        self.assertTrue(tr.close.called)
        conn.close()

    def test_release_not_started(self):
        self.loop.time = mock.Mock(return_value=10)

        conn = aiohttp.BaseConnector(loop=self.loop)
        req = unittest.mock.Mock()
        req.response = None

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        key = 1
        conn._acquired[key].add(tr)
        conn._release(key, req, tr, proto)
        self.assertEqual(conn._conns, {1: [(tr, proto, 10)]})
        self.assertFalse(tr.close.called)
        conn.close()

    def test_release_not_opened(self):
        conn = aiohttp.BaseConnector(loop=self.loop)
        req = unittest.mock.Mock()
        req.response = unittest.mock.Mock()
        req.response.message = None

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        key = 1
        conn._acquired[key].add(tr)
        conn._release(key, req, tr, proto)
        self.assertTrue(tr.close.called)

    def test_connect(self):
        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        proto.is_connected.return_value = True

        class Req:
            host = 'host'
            port = 80
            ssl = False
            response = unittest.mock.Mock()

        conn = aiohttp.BaseConnector(loop=self.loop)
        key = ('host', 80, False)
        conn._conns[key] = [(tr, proto, self.loop.time())]
        conn._create_connection = unittest.mock.Mock()
        conn._create_connection.return_value = asyncio.Future(loop=self.loop)
        conn._create_connection.return_value.set_result((tr, proto))

        connection = self.loop.run_until_complete(conn.connect(Req()))
        self.assertFalse(conn._create_connection.called)
        self.assertEqual(connection._transport, tr)
        self.assertEqual(connection._protocol, proto)
        self.assertIsInstance(connection, Connection)
        connection.close()

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
        loop.time.return_value = 1.5
        conn = aiohttp.BaseConnector(loop=loop, keepalive_timeout=10)
        self.assertIsNone(conn._cleanup_handle)

        conn._start_cleanup_task()
        self.assertIsNotNone(conn._cleanup_handle)
        loop.call_at.assert_called_with(
            12, conn._cleanup)

    def test_cleanup(self):
        testset = {
            1: [(unittest.mock.Mock(), unittest.mock.Mock(), 10),
                (unittest.mock.Mock(), unittest.mock.Mock(), 300),
                (None, unittest.mock.Mock(), 300)],
        }
        testset[1][0][1].is_connected.return_value = True
        testset[1][1][1].is_connected.return_value = False

        loop = unittest.mock.Mock()
        loop.time.return_value = 300
        conn = aiohttp.BaseConnector(loop=loop)
        conn._conns = testset
        existing_handle = conn._cleanup_handle = unittest.mock.Mock()

        conn._cleanup()
        self.assertTrue(existing_handle.cancel.called)
        self.assertEqual(conn._conns, {})
        self.assertIsNone(conn._cleanup_handle)

    def test_cleanup2(self):
        testset = {1: [(unittest.mock.Mock(), unittest.mock.Mock(), 300)]}
        testset[1][0][1].is_connected.return_value = True

        loop = unittest.mock.Mock()
        loop.time.return_value = 300.1

        conn = aiohttp.BaseConnector(loop=loop, keepalive_timeout=10)
        conn._conns = testset
        conn._cleanup()
        self.assertEqual(conn._conns, testset)

        self.assertIsNotNone(conn._cleanup_handle)
        loop.call_at.assert_called_with(
            310, conn._cleanup)
        conn.close()

    def test_cleanup3(self):
        testset = {1: [(unittest.mock.Mock(), unittest.mock.Mock(), 290.1),
                       (unittest.mock.Mock(), unittest.mock.Mock(), 305.1)]}
        testset[1][0][1].is_connected.return_value = True

        loop = unittest.mock.Mock()
        loop.time.return_value = 308.5

        conn = aiohttp.BaseConnector(loop=loop, keepalive_timeout=10)
        conn._conns = testset

        conn._cleanup()
        self.assertEqual(conn._conns, {1: [testset[1][1]]})

        self.assertIsNotNone(conn._cleanup_handle)
        loop.call_at.assert_called_with(
            316, conn._cleanup)
        conn.close()

    def test_tcp_connector_ctor(self):
        conn = aiohttp.TCPConnector(loop=self.loop)
        self.assertTrue(conn.verify_ssl)
        self.assertIs(conn.fingerprint, None)

        with self.assertWarns(DeprecationWarning):
            self.assertFalse(conn.resolve)
        self.assertFalse(conn.use_dns_cache)

        self.assertEqual(conn.family, socket.AF_INET)

        with self.assertWarns(DeprecationWarning):
            self.assertEqual(conn.resolved_hosts, {})
        self.assertEqual(conn.resolved_hosts, {})

    def test_tcp_connector_ctor_fingerprint_valid(self):
        valid = b'\xa2\x06G\xad\xaa\xf5\xd8\\J\x99^by;\x06='
        conn = aiohttp.TCPConnector(loop=self.loop, fingerprint=valid)
        self.assertEqual(conn.fingerprint, valid)

    def test_tcp_connector_fingerprint_invalid(self):
        invalid = b'\x00'
        with self.assertRaises(ValueError):
            aiohttp.TCPConnector(loop=self.loop, fingerprint=invalid)

    def test_tcp_connector_fingerprint(self):
        # The even-index fingerprints below are "expect success" cases
        # for ./sample.crt.der, the cert presented by test_utils.run_server.
        # The odd-index fingerprints are "expect fail" cases.
        testcases = (
            # md5
            b'\xa2\x06G\xad\xaa\xf5\xd8\\J\x99^by;\x06=',
            b'\x00' * 16,

            # sha1
            b's\x93\xfd:\xed\x08\x1do\xa9\xaeq9\x1a\xe3\xc5\x7f\x89\xe7l\xf9',
            b'\x00' * 20,

            # sha256
            b'0\x9a\xc9D\x83\xdc\x91\'\x88\x91\x11\xa1d\x97\xfd\xcb~7U\x14D@L'
            b'\x11\xab\x99\xa8\xae\xb7\x14\xee\x8b',
            b'\x00' * 32,
        )
        for i, fingerprint in enumerate(testcases):
            expect_fail = i % 2
            conn = aiohttp.TCPConnector(loop=self.loop, verify_ssl=False,
                                        fingerprint=fingerprint)
            with test_utils.run_server(self.loop, use_ssl=True) as httpd:
                coro = client.request('get', httpd.url('method', 'get'),
                                      connector=conn, loop=self.loop)
                if expect_fail:
                    with self.assertRaises(FingerprintMismatch) as cm:
                        self.loop.run_until_complete(coro)
                    exc = cm.exception
                    self.assertEqual(exc.expected, fingerprint)
                    # the previous test case should be what we actually got
                    self.assertEqual(exc.got, testcases[i-1])
                else:
                    # should not raise
                    resp = self.loop.run_until_complete(coro)
                    resp.close(force=True)

            conn.close()

    def test_tcp_connector_clear_resolved_hosts(self):
        conn = aiohttp.TCPConnector(loop=self.loop)
        info = object()
        conn._cached_hosts[('localhost', 123)] = info
        conn._cached_hosts[('localhost', 124)] = info
        conn.clear_resolved_hosts('localhost', 123)
        self.assertEqual(
            conn.resolved_hosts, {('localhost', 124): info})
        conn.clear_resolved_hosts('localhost', 123)
        self.assertEqual(
            conn.resolved_hosts, {('localhost', 124): info})
        with self.assertWarns(DeprecationWarning):
            conn.clear_resolved_hosts()
        self.assertEqual(conn.resolved_hosts, {})

    def test_tcp_connector_clear_dns_cache(self):
        conn = aiohttp.TCPConnector(loop=self.loop)
        info = object()
        conn._cached_hosts[('localhost', 123)] = info
        conn._cached_hosts[('localhost', 124)] = info
        conn.clear_dns_cache('localhost', 123)
        self.assertEqual(
            conn.cached_hosts, {('localhost', 124): info})
        conn.clear_dns_cache('localhost', 123)
        self.assertEqual(
            conn.cached_hosts, {('localhost', 124): info})
        conn.clear_dns_cache()
        self.assertEqual(conn.cached_hosts, {})

    def test_tcp_connector_clear_dns_cache_bad_args(self):
        conn = aiohttp.TCPConnector(loop=self.loop)
        with self.assertRaises(ValueError):
            conn.clear_dns_cache('localhost')

    def test_ambigous_verify_ssl_and_ssl_context(self):
        with self.assertRaises(ValueError):
            aiohttp.TCPConnector(
                verify_ssl=False,
                ssl_context=ssl.SSLContext(ssl.PROTOCOL_SSLv23),
                loop=self.loop)

    def test_dont_recreate_ssl_context(self):
        conn = aiohttp.TCPConnector(loop=self.loop)
        ctx = conn.ssl_context
        self.assertIs(ctx, conn.ssl_context)

    def test_respect_precreated_ssl_context(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        conn = aiohttp.TCPConnector(loop=self.loop, ssl_context=ctx)
        self.assertIs(ctx, conn.ssl_context)

    def test_close_twice(self):
        tr = unittest.mock.Mock()

        conn = aiohttp.BaseConnector(loop=self.loop)
        conn._conns[1] = [(tr, object(), object())]
        conn.close()

        self.assertFalse(conn._conns)
        self.assertTrue(tr.close.called)
        self.assertTrue(conn.closed)

        conn._conns = 'Invalid'  # fill with garbage
        conn.close()
        self.assertTrue(conn.closed)

    def test_close_cancels_cleanup_handle(self):
        conn = aiohttp.BaseConnector(loop=self.loop)
        conn._start_cleanup_task()

        self.assertIsNotNone(conn._cleanup_handle)
        conn.close()
        self.assertIsNone(conn._cleanup_handle)

    def test_ctor_with_default_loop(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self.addCleanup(loop.close)
        self.addCleanup(asyncio.set_event_loop, None)
        conn = aiohttp.BaseConnector()
        self.assertIs(loop, conn._loop)

    def test_connect_with_limit(self):

        @asyncio.coroutine
        def go():
            tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
            proto.is_connected.return_value = True

            class Req:
                host = 'host'
                port = 80
                ssl = False
                response = unittest.mock.Mock()

            conn = aiohttp.BaseConnector(loop=self.loop, limit=1)
            key = ('host', 80, False)
            conn._conns[key] = [(tr, proto, self.loop.time())]
            conn._create_connection = unittest.mock.Mock()
            conn._create_connection.return_value = asyncio.Future(
                loop=self.loop)
            conn._create_connection.return_value.set_result((tr, proto))

            connection1 = yield from conn.connect(Req())
            self.assertEqual(connection1._transport, tr)

            self.assertEqual(1, len(conn._acquired[key]))

            acquired = False

            @asyncio.coroutine
            def f():
                nonlocal acquired
                connection2 = yield from conn.connect(Req())
                acquired = True
                self.assertEqual(1, len(conn._acquired[key]))
                connection2.release()

            task = asyncio.async(f(), loop=self.loop)

            yield from asyncio.sleep(0.01, loop=self.loop)
            self.assertFalse(acquired)
            connection1.release()
            yield from asyncio.sleep(0, loop=self.loop)
            self.assertTrue(acquired)
            yield from task
            conn.close()

        self.loop.run_until_complete(go())

    def test_connect_with_limit_cancelled(self):

        @asyncio.coroutine
        def go():
            tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
            proto.is_connected.return_value = True

            class Req:
                host = 'host'
                port = 80
                ssl = False
                response = unittest.mock.Mock()

            conn = aiohttp.BaseConnector(loop=self.loop, limit=1)
            key = ('host', 80, False)
            conn._conns[key] = [(tr, proto, self.loop.time())]
            conn._create_connection = unittest.mock.Mock()
            conn._create_connection.return_value = asyncio.Future(
                loop=self.loop)
            conn._create_connection.return_value.set_result((tr, proto))

            connection = yield from conn.connect(Req())
            self.assertEqual(connection._transport, tr)

            self.assertEqual(1, len(conn._acquired[key]))

            with self.assertRaises(asyncio.TimeoutError):
                # limit exhausted
                yield from asyncio.wait_for(conn.connect(Req), 0.01,
                                            loop=self.loop)

            connection.close()

        self.loop.run_until_complete(go())

    def test_close_with_acquired_connection(self):

        @asyncio.coroutine
        def go():
            tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
            proto.is_connected.return_value = True

            class Req:
                host = 'host'
                port = 80
                ssl = False
                response = unittest.mock.Mock()

            conn = aiohttp.BaseConnector(loop=self.loop, limit=1)
            key = ('host', 80, False)
            conn._conns[key] = [(tr, proto, self.loop.time())]
            conn._create_connection = unittest.mock.Mock()
            conn._create_connection.return_value = asyncio.Future(
                loop=self.loop)
            conn._create_connection.return_value.set_result((tr, proto))

            connection = yield from conn.connect(Req())

            self.assertEqual(1, len(conn._acquired))
            conn.close()
            self.assertEqual(0, len(conn._acquired))
            self.assertTrue(conn.closed)
            tr.close.assert_called_with()

            self.assertFalse(connection.closed)
            connection.close()
            self.assertTrue(connection.closed)

        self.loop.run_until_complete(go())

    def test_default_force_close(self):
        connector = aiohttp.BaseConnector(loop=self.loop)
        self.assertFalse(connector.force_close)

    def test_limit_property(self):
        conn = aiohttp.BaseConnector(loop=self.loop, limit=15)
        self.assertEqual(15, conn.limit)
        conn.close()

    def test_limit_property_default(self):
        conn = aiohttp.BaseConnector(loop=self.loop)
        self.assertIsNone(conn.limit)
        conn.close()


class TestHttpClientConnector(unittest.TestCase):

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

    def test_connector_cookie_deprecation(self):
        with self.assertWarnsRegex(DeprecationWarning,
                                   "^Using `share_cookies` is deprecated"):
            conn = aiohttp.TCPConnector(share_cookies=True, loop=self.loop)
        conn.close()

    def test_ambiguous_ctor_params(self):
        with self.assertRaises(ValueError):
            aiohttp.TCPConnector(resolve=True, use_dns_cache=False,
                                 loop=self.loop)

    def test_both_resolve_and_use_dns_cache(self):
        conn = aiohttp.TCPConnector(resolve=True, use_dns_cache=True,
                                    loop=self.loop)
        self.assertTrue(conn.use_dns_cache)
        with self.assertWarns(DeprecationWarning):
            self.assertTrue(conn.resolve)

    def test_both_use_dns_cache_only(self):
        conn = aiohttp.TCPConnector(use_dns_cache=True,
                                    loop=self.loop)
        self.assertTrue(conn.use_dns_cache)
        with self.assertWarns(DeprecationWarning):
            self.assertTrue(conn.resolve)


class TestProxyConnector(unittest.TestCase):

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
        self.assertTrue(connector.force_close)

    @unittest.mock.patch('aiohttp.connector.ClientRequest')
    def test_connect(self, ClientRequestMock):
        req = ClientRequest('GET', 'http://www.python.org', loop=self.loop)
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
        tr.get_extra_info.assert_called_once_with('sslcontext')

        ClientRequestMock.assert_called_with(
            'GET', 'http://proxy.example.com',
            auth=None,
            headers={'HOST': 'www.python.org'},
            loop=loop_mock)
        conn.close()

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

        req = ClientRequest('GET', 'http://www.python.org', loop=self.loop)
        expected_headers = dict(req.headers)
        with self.assertRaises(aiohttp.ProxyConnectionError):
            self.loop.run_until_complete(connector.connect(req))
        self.assertEqual(req.path, '/')
        self.assertEqual(dict(req.headers), expected_headers)

    @unittest.mock.patch('aiohttp.connector.ClientRequest')
    def test_auth(self, ClientRequestMock):
        proxy_req = ClientRequest('GET', 'http://proxy.example.com',
                                  auth=aiohttp.helpers.BasicAuth('user',
                                                                 'pass'),
                                  loop=self.loop)
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

        req = ClientRequest('GET', 'http://www.python.org', loop=self.loop)
        self.assertNotIn('AUTHORIZATION', req.headers)
        self.assertNotIn('PROXY-AUTHORIZATION', req.headers)
        conn = self.loop.run_until_complete(connector.connect(req))

        self.assertEqual(req.path, 'http://www.python.org/')
        self.assertNotIn('AUTHORIZATION', req.headers)
        self.assertIn('PROXY-AUTHORIZATION', req.headers)
        self.assertNotIn('AUTHORIZATION', proxy_req.headers)
        self.assertNotIn('PROXY-AUTHORIZATION', proxy_req.headers)

        ClientRequestMock.assert_called_with(
            'GET', 'http://proxy.example.com',
            auth=aiohttp.helpers.BasicAuth('user', 'pass'),
            loop=unittest.mock.ANY, headers=unittest.mock.ANY)
        conn.close()

    def test_auth_utf8(self):
        proxy_req = ClientRequest(
            'GET', 'http://proxy.example.com',
            auth=aiohttp.helpers.BasicAuth('юзер', 'пасс', 'utf-8'),
            loop=self.loop)
        self.assertIn('AUTHORIZATION', proxy_req.headers)

    @unittest.mock.patch('aiohttp.connector.ClientRequest')
    def test_auth_from_url(self, ClientRequestMock):
        proxy_req = ClientRequest('GET', 'http://user:pass@proxy.example.com',
                                  loop=self.loop)
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

        req = ClientRequest('GET', 'http://www.python.org', loop=self.loop)
        self.assertNotIn('AUTHORIZATION', req.headers)
        self.assertNotIn('PROXY-AUTHORIZATION', req.headers)
        conn = self.loop.run_until_complete(connector.connect(req))

        self.assertEqual(req.path, 'http://www.python.org/')
        self.assertNotIn('AUTHORIZATION', req.headers)
        self.assertIn('PROXY-AUTHORIZATION', req.headers)
        self.assertNotIn('AUTHORIZATION', proxy_req.headers)
        self.assertNotIn('PROXY-AUTHORIZATION', proxy_req.headers)

        ClientRequestMock.assert_called_with(
            'GET', 'http://user:pass@proxy.example.com',
            auth=None, loop=unittest.mock.ANY, headers=unittest.mock.ANY)
        conn.close()

    @unittest.mock.patch('aiohttp.connector.ClientRequest')
    def test_auth__not_modifying_request(self, ClientRequestMock):
        proxy_req = ClientRequest('GET', 'http://user:pass@proxy.example.com',
                                  loop=self.loop)
        ClientRequestMock.return_value = proxy_req
        proxy_req_headers = dict(proxy_req.headers)

        loop_mock = unittest.mock.Mock()
        connector = aiohttp.ProxyConnector(
            'http://user:pass@proxy.example.com', loop=loop_mock)
        connector._resolve_host = resolve_mock = unittest.mock.Mock()
        self._fake_coroutine(resolve_mock, OSError('nothing personal'))

        req = ClientRequest('GET', 'http://www.python.org', loop=self.loop)
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
        proxy_resp._loop = loop_mock
        proxy_req.send = send_mock = unittest.mock.Mock()
        send_mock.return_value = proxy_resp
        proxy_resp.start = start_mock = unittest.mock.Mock()
        self._fake_coroutine(start_mock, unittest.mock.Mock(status=200))

        connector = aiohttp.ProxyConnector(
            'http://proxy.example.com', loop=loop_mock)

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        self._fake_coroutine(loop_mock.create_connection, (tr, proto))

        req = ClientRequest('GET', 'https://www.python.org', loop=self.loop)
        self.loop.run_until_complete(connector._create_connection(req))

        self.assertEqual(req.path, '/')
        self.assertEqual(proxy_req.method, 'CONNECT')
        self.assertEqual(proxy_req.path, 'www.python.org:443')
        tr.pause_reading.assert_called_once_with()
        tr.get_extra_info.assert_called_with('socket', default=None)

        proxy_req.close()
        proxy_resp.close()
        req.close()

    @unittest.mock.patch('aiohttp.connector.ClientRequest')
    def test_https_connect_runtime_error(self, ClientRequestMock):
        loop_mock = unittest.mock.Mock()
        proxy_req = ClientRequest('GET', 'http://proxy.example.com',
                                  loop=loop_mock)
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse('get', 'http://proxy.example.com')
        proxy_resp._loop = loop_mock
        proxy_req.send = send_mock = unittest.mock.Mock()
        send_mock.return_value = proxy_resp
        proxy_resp.start = start_mock = unittest.mock.Mock()
        self._fake_coroutine(start_mock, unittest.mock.Mock(status=200))

        connector = aiohttp.ProxyConnector(
            'http://proxy.example.com', loop=loop_mock)

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        tr.get_extra_info.return_value = None
        self._fake_coroutine(loop_mock.create_connection, (tr, proto))

        req = ClientRequest('GET', 'https://www.python.org', loop=self.loop)
        with self.assertRaisesRegex(
                RuntimeError, "Transport does not expose socket instance"):
            self.loop.run_until_complete(connector._create_connection(req))

        proxy_req.close()
        proxy_resp.close()
        req.close()

    @unittest.mock.patch('aiohttp.connector.ClientRequest')
    def test_https_connect_http_proxy_error(self, ClientRequestMock):
        loop_mock = unittest.mock.Mock()
        proxy_req = ClientRequest('GET', 'http://proxy.example.com',
                                  loop=loop_mock)
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse('get', 'http://proxy.example.com')
        proxy_resp._loop = loop_mock
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

        req = ClientRequest('GET', 'https://www.python.org', loop=self.loop)
        with self.assertRaisesRegex(
                aiohttp.HttpProxyError, "400, message='bad request'"):
            self.loop.run_until_complete(connector._create_connection(req))

        proxy_req.close()
        proxy_resp.close()
        req.close()

    @unittest.mock.patch('aiohttp.connector.ClientRequest')
    def test_https_connect_resp_start_error(self, ClientRequestMock):
        loop_mock = unittest.mock.Mock()
        proxy_req = ClientRequest('GET', 'http://proxy.example.com',
                                  loop=loop_mock)
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse('get', 'http://proxy.example.com')
        proxy_resp._loop = loop_mock
        proxy_req.send = send_mock = unittest.mock.Mock()
        send_mock.return_value = proxy_resp
        proxy_resp.start = start_mock = unittest.mock.Mock()
        self._fake_coroutine(start_mock, OSError("error message"))

        connector = aiohttp.ProxyConnector(
            'http://proxy.example.com', loop=loop_mock)

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        tr.get_extra_info.return_value = None
        self._fake_coroutine(loop_mock.create_connection, (tr, proto))

        req = ClientRequest('GET', 'https://www.python.org', loop=self.loop)
        with self.assertRaisesRegex(OSError, "error message"):
            self.loop.run_until_complete(connector._create_connection(req))

    @unittest.mock.patch('aiohttp.connector.ClientRequest')
    def test_request_port(self, ClientRequestMock):
        proxy_req = ClientRequest('GET', 'http://proxy.example.com',
                                  loop=self.loop)
        ClientRequestMock.return_value = proxy_req

        loop_mock = unittest.mock.Mock()
        connector = aiohttp.ProxyConnector('http://proxy.example.com',
                                           loop=loop_mock)

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        tr.get_extra_info.return_value = None
        self._fake_coroutine(loop_mock.create_connection, (tr, proto))

        req = ClientRequest('GET', 'http://localhost:1234/path',
                            loop=self.loop)
        self.loop.run_until_complete(connector._create_connection(req))
        self.assertEqual(req.path, 'http://localhost:1234/path')

    def test_proxy_auth_property(self):
        connector = aiohttp.ProxyConnector(
            'http://proxy.example.com',
            proxy_auth=aiohttp.helpers.BasicAuth('user', 'pass'),
            loop=self.loop)
        self.assertEqual(('user', 'pass', 'latin1'), connector.proxy_auth)
        connector.close()

    def test_proxy_auth_property_default(self):
        connector = aiohttp.ProxyConnector('http://proxy.example.com',
                                           loop=self.loop)
        self.assertIsNone(connector.proxy_auth)
        connector.close()

    @unittest.mock.patch('aiohttp.connector.ClientRequest')
    def test_https_connect_pass_ssl_context(self, ClientRequestMock):
        loop_mock = unittest.mock.Mock()
        proxy_req = ClientRequest('GET', 'http://proxy.example.com',
                                  loop=loop_mock)
        ClientRequestMock.return_value = proxy_req

        proxy_resp = ClientResponse('get', 'http://proxy.example.com')
        proxy_resp._loop = loop_mock
        proxy_req.send = send_mock = unittest.mock.Mock()
        send_mock.return_value = proxy_resp
        proxy_resp.start = start_mock = unittest.mock.Mock()
        self._fake_coroutine(start_mock, unittest.mock.Mock(status=200))

        connector = aiohttp.ProxyConnector(
            'http://proxy.example.com', loop=loop_mock)

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        self._fake_coroutine(loop_mock.create_connection, (tr, proto))

        req = ClientRequest('GET', 'https://www.python.org', loop=self.loop)
        self.loop.run_until_complete(connector._create_connection(req))

        loop_mock.create_connection.assert_called_with(
            mock.ANY,
            ssl=connector.ssl_context,
            sock=mock.ANY,
            server_hostname='www.python.org')

        self.assertEqual(req.path, '/')
        self.assertEqual(proxy_req.method, 'CONNECT')
        self.assertEqual(proxy_req.path, 'www.python.org:443')
        tr.pause_reading.assert_called_once_with()
        tr.get_extra_info.assert_called_with('socket', default=None)

        proxy_req.close()
        proxy_resp.close()
        req.close()
