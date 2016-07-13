"""Tests of http client with custom Connector"""

import asyncio
import gc
import socket
import unittest
import ssl
import tempfile
import shutil
import os.path
from unittest import mock

import aiohttp
from aiohttp import web
from aiohttp import client
from aiohttp import helpers
from aiohttp.client import ClientResponse
from aiohttp.connector import Connection


class TestBaseConnector(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

        self.transport = unittest.mock.Mock()
        self.stream = aiohttp.StreamParser()
        self.response = ClientResponse('get', 'http://base-conn.org')
        self.response._post_init(self.loop)

    def tearDown(self):
        self.response.close()
        self.loop.close()
        gc.collect()

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
               'connections': unittest.mock.ANY,
               'message': 'Unclosed connector'}
        if self.loop.get_debug():
            msg['source_traceback'] = unittest.mock.ANY
        exc_handler.assert_called_with(self.loop, msg)

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
        resp._should_close = False

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        key = 1
        conn._acquired[key].add(tr)
        conn._release(key, req, tr, proto)
        self.assertEqual(conn._conns[1][0], (tr, proto, 10))
        self.assertTrue(conn._start_cleanup_task.called)
        conn.close()

    def test_release_close(self):
        conn = aiohttp.BaseConnector(loop=self.loop)
        req = unittest.mock.Mock()
        resp = unittest.mock.Mock()
        resp.message.should_close = True
        req.response = resp

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

        conn = aiohttp.BaseConnector(loop=self.loop)
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
        conn._create_connection.return_value = helpers.create_future(self.loop)
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
        conn._create_connection.return_value = helpers.create_future(self.loop)
        conn._create_connection.return_value.set_exception(
            asyncio.TimeoutError())

        with self.assertRaises(aiohttp.ClientTimeoutError):
            req = unittest.mock.Mock()
            self.loop.run_until_complete(conn.connect(req))

    def test_connect_oserr(self):
        conn = aiohttp.BaseConnector(loop=self.loop)
        conn._create_connection = unittest.mock.Mock()
        conn._create_connection.return_value = helpers.create_future(self.loop)
        err = OSError(1, 'permission error')
        conn._create_connection.return_value.set_exception(err)

        with self.assertRaises(aiohttp.ClientOSError) as ctx:
            req = unittest.mock.Mock()
            self.loop.run_until_complete(conn.connect(req))
        self.assertEqual(1, ctx.exception.errno)
        self.assertTrue(ctx.exception.strerror.startswith('Cannot connect to'))
        self.assertTrue(ctx.exception.strerror.endswith('[permission error]'))

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

        self.assertEqual(conn.family, 0)

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
            conn._create_connection.return_value = helpers.create_future(
                self.loop)
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
            conn._create_connection.return_value = helpers.create_future(
                self.loop)
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

    def test_connect_with_limit_release_waiters(self):

        def check_with_exc(err):
            conn = aiohttp.BaseConnector(limit=1, loop=self.loop)
            conn._create_connection = unittest.mock.Mock()
            conn._create_connection.return_value = \
                helpers.create_future(self.loop)
            conn._create_connection.return_value.set_exception(err)

            with self.assertRaises(Exception):
                req = unittest.mock.Mock()
                self.loop.run_until_complete(conn.connect(req))
            key = (req.host, req.port, req.ssl)
            self.assertFalse(conn._waiters[key])

        check_with_exc(OSError(1, 'permission error'))
        check_with_exc(RuntimeError())
        check_with_exc(asyncio.TimeoutError())

    def test_connect_with_limit_concurrent(self):

        @asyncio.coroutine
        def go():
            proto = unittest.mock.Mock()
            proto.is_connected.return_value = True

            class Req:
                host = 'host'
                port = 80
                ssl = False
                response = unittest.mock.Mock(_should_close=False)

            max_connections = 2
            num_connections = 0

            conn = aiohttp.BaseConnector(limit=max_connections, loop=self.loop)

            # Use a real coroutine for _create_connection; a mock would mask
            # problems that only happen when the method yields.

            @asyncio.coroutine
            def create_connection(req):
                nonlocal num_connections
                num_connections += 1
                yield from asyncio.sleep(0, loop=self.loop)

                # Make a new transport mock each time because acquired
                # transports are stored in a set. Reusing the same object
                # messes with the count.
                tr = unittest.mock.Mock()

                return tr, proto

            conn._create_connection = create_connection

            # Simulate something like a crawler. It opens a connection, does
            # something with it, closes it, then creates tasks that make more
            # connections and waits for them to finish. The crawler is started
            # with multiple concurrent requests and stops when it hits a
            # predefined maximum number of requests.

            max_requests = 10
            num_requests = 0
            start_requests = max_connections + 1

            @asyncio.coroutine
            def f(start=True):
                nonlocal num_requests
                if num_requests == max_requests:
                    return
                num_requests += 1
                if not start:
                    connection = yield from conn.connect(Req())
                    yield from asyncio.sleep(0, loop=self.loop)
                    connection.release()
                tasks = [
                    asyncio.async(f(start=False), loop=self.loop)
                    for i in range(start_requests)
                ]
                yield from asyncio.wait(tasks, loop=self.loop)

            yield from f()
            conn.close()

            self.assertEqual(max_connections, num_connections)

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
            conn._create_connection.return_value = helpers.create_future(
                self.loop)
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

    def test_force_close_and_explicit_keep_alive(self):
        with self.assertRaises(ValueError):
            aiohttp.BaseConnector(loop=self.loop, keepalive_timeout=30,
                                  force_close=True)

        conn = aiohttp.BaseConnector(loop=self.loop, force_close=True,
                                     keepalive_timeout=None)
        assert conn

        conn = aiohttp.BaseConnector(loop=self.loop, force_close=True)

        assert conn


class TestHttpClientConnector(unittest.TestCase):

    def setUp(self):
        self.handler = None
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        if self.handler:
            self.loop.run_until_complete(self.handler.finish_connections())
        self.loop.stop()
        self.loop.run_forever()
        self.loop.close()
        gc.collect()

    def find_unused_port(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
        s.close()
        return port

    @asyncio.coroutine
    def create_server(self, method, path, handler):
        app = web.Application(loop=self.loop)
        app.router.add_route(method, path, handler)

        port = self.find_unused_port()
        self.handler = app.make_handler(keep_alive_on=False)
        srv = yield from self.loop.create_server(
            self.handler, '127.0.0.1', port)
        url = "http://127.0.0.1:{}".format(port) + path
        self.addCleanup(srv.close)
        return app, srv, url

    @asyncio.coroutine
    def create_unix_server(self, method, path, handler):
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir)
        app = web.Application(loop=self.loop)
        app.router.add_route(method, path, handler)

        self.handler = app.make_handler(keep_alive_on=False, access_log=None)
        sock_path = os.path.join(tmpdir, 'socket.sock')
        srv = yield from self.loop.create_unix_server(
            self.handler, sock_path)
        url = "http://127.0.0.1" + path
        self.addCleanup(srv.close)
        return app, srv, url, sock_path

    def test_tcp_connector(self):
        @asyncio.coroutine
        def handler(request):
            return web.HTTPOk()

        app, srv, url = self.loop.run_until_complete(
            self.create_server('get', '/', handler))
        conn = aiohttp.TCPConnector(loop=self.loop)
        r = self.loop.run_until_complete(
            aiohttp.request(
                'get', url,
                connector=conn,
                loop=self.loop))
        self.loop.run_until_complete(r.release())
        self.assertEqual(r.status, 200)
        r.close()
        conn.close()

    def test_tcp_connector_uses_provided_local_addr(self):
        @asyncio.coroutine
        def handler(request):
            return web.HTTPOk()

        app, srv, url = self.loop.run_until_complete(
            self.create_server('get', '/', handler)
        )

        port = self.find_unused_port()
        conn = aiohttp.TCPConnector(loop=self.loop,
                                    local_addr=('127.0.0.1', port))

        r = self.loop.run_until_complete(
            aiohttp.request(
                'get', url,
                connector=conn
            ))

        self.loop.run_until_complete(r.release())
        first_conn = next(iter(conn._conns.values()))[0][0]
        self.assertEqual(first_conn._sock.getsockname(), ('127.0.0.1', port))
        r.close()

        conn.close()

    @unittest.skipUnless(hasattr(socket, 'AF_UNIX'), 'requires unix')
    def test_unix_connector(self):
        @asyncio.coroutine
        def handler(request):
            return web.HTTPOk()

        app, srv, url, sock_path = self.loop.run_until_complete(
            self.create_unix_server('get', '/', handler))

        connector = aiohttp.UnixConnector(sock_path, loop=self.loop)
        self.assertEqual(sock_path, connector.path)

        r = self.loop.run_until_complete(
            client.request(
                'get', url,
                connector=connector,
                loop=self.loop))
        self.assertEqual(r.status, 200)
        r.close()

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

    def test_resolver_not_called_with_address_is_ip(self):
        resolver = unittest.mock.MagicMock()
        connector = aiohttp.TCPConnector(resolver=resolver, loop=self.loop)

        class Req:
            host = '127.0.0.1'
            port = 80
            ssl = False
            response = unittest.mock.Mock()

        with self.assertRaises(OSError):
            self.loop.run_until_complete(connector.connect(Req()))

        resolver.resolve.assert_not_called()

    def test_ip_addresses(self):
        ip_addresses = [
            '0.0.0.0',
            '127.0.0.1',
            '255.255.255.255',
            '0:0:0:0:0:0:0:0',
            'FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF',
            '00AB:0002:3008:8CFD:00AB:0002:3008:8CFD',
            '00ab:0002:3008:8cfd:00ab:0002:3008:8cfd',
            'AB:02:3008:8CFD:AB:02:3008:8CFD',
            'AB:02:3008:8CFD::02:3008:8CFD',
            '::',
            '1::1',
        ]
        for address in ip_addresses:
            assert helpers.is_ip_address(address) is True

    def test_host_addresses(self):
        hosts = [
            'www.four.part.host'
            'www.python.org',
            'foo.bar',
            'localhost',
        ]
        for host in hosts:
            assert helpers.is_ip_address(host) is False
