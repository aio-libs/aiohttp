"""Tests for aiohttp/session.py"""

import asyncio
import http.cookies
import time
import unittest
import unittest.mock

import aiohttp
from aiohttp.client import HttpResponse
from aiohttp.session import Session, TransportWrapper


class HttpSessionTests(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

        self.transport = unittest.mock.Mock()
        self.stream = aiohttp.StreamParser()
        self.response = HttpResponse('get', 'http://python.org')

    def tearDown(self):
        self.loop.close()

    def test_del(self):
        session = Session(loop=self.loop)
        close = session.close = unittest.mock.Mock()

        del session
        self.assertTrue(close.called)

    @unittest.mock.patch('aiohttp.session.asyncio')
    def test_ctor_loop(self, asyncio):
        session = Session()
        self.assertIs(session._loop, asyncio.get_event_loop.return_value)

    def test_close(self):
        tr = unittest.mock.Mock()

        session = Session(loop=self.loop)
        session._conns[1] = [(tr, object(), object())]
        session.close()

        self.assertFalse(session._conns)
        self.assertTrue(tr.close.called)

    def test_get(self):
        session = Session(loop=self.loop)
        self.assertEqual(session._get(1), (None, None, None))

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        session._conns[1] = [(tr, proto)]
        self.assertEqual(session._get(1), (tr, proto))

    def test_release(self):
        session = Session(loop=self.loop)
        session._start_cleanup_task = unittest.mock.Mock()
        req = unittest.mock.Mock()
        resp = req.response = unittest.mock.Mock()
        resp.message.should_close = False

        cookies = resp.cookies = http.cookies.SimpleCookie()
        cookies['c1'] = 'cookie1'
        cookies['c2'] = 'cookie2'

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        session._release(req, 1, (tr, proto, 0))
        self.assertEqual(session._conns[1][0], (tr, proto, 0))
        self.assertEqual(session.cookies, dict(cookies.items()))
        self.assertTrue(session._start_cleanup_task.called)

    def test_release_close(self):
        session = Session(loop=self.loop)
        req = unittest.mock.Mock()
        resp = unittest.mock.Mock()
        resp.message.should_close = True
        req.response = resp

        cookies = resp.cookies = http.cookies.SimpleCookie()
        cookies['c1'] = 'cookie1'
        cookies['c2'] = 'cookie2'

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        session._release(req, 1, (tr, proto, 0))
        self.assertFalse(session._conns)
        self.assertTrue(tr.close.called)

    def test_release_not_started(self):
        session = Session(loop=self.loop)
        req = unittest.mock.Mock()
        req.response = None

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        session._release(req, 1, (tr, proto, 0))
        self.assertEqual(session._conns, {1: [(tr, proto, 0)]})
        self.assertFalse(tr.close.called)

    def test_release_not_opened(self):
        session = Session(loop=self.loop)
        req = unittest.mock.Mock()
        req.response = unittest.mock.Mock()
        req.response.message = None

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        session._release(req, 1, (tr, proto, 0))
        self.assertTrue(tr.close.called)

    def test_transport_wrapper_force_close(self):
        m = unittest.mock.Mock()
        release = unittest.mock.Mock()
        transp = unittest.mock.Mock()

        wrp = TransportWrapper(release, m, transp, m, m)
        wrp.close()
        self.assertTrue(release.called)

        release.reset_mock()
        wrp.close(True)
        self.assertFalse(release.called)
        self.assertTrue(transp.close.called)

    def test_start_existing_closed(self):
        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        proto.is_connected.return_value = False
        new_connection = False

        class Req:
            host = 'host'
            port = 80
            ssl = False

        class Loop:
            @asyncio.coroutine
            def create_connection(self, *args, **kw):
                nonlocal new_connection
                new_connection = True
                return tr, proto

        session = Session(loop=self.loop)
        key = ('host', 80, False)
        session._conns[key] = [(unittest.mock.Mock(), proto, 10)]

        self.loop.run_until_complete(session.start(Req(), Loop()))
        self.assertTrue(new_connection)

    def test_start_existing_timedout(self):
        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        proto.is_connected.return_value = True
        new_connection = False

        class Req:
            host = 'host'
            port = 80
            ssl = False

        class Loop:
            @asyncio.coroutine
            def create_connection(self, *args, **kw):
                nonlocal new_connection
                new_connection = True
                return tr, proto

        session = Session(loop=self.loop)
        key = ('host', 80, False)
        transport = unittest.mock.Mock()
        session._conns[key] = [(transport, proto, time.time()-40)]

        self.loop.run_until_complete(session.start(Req(), Loop()))
        self.assertTrue(new_connection)
        self.assertTrue(transport.close.called)

    def test_start_existing(self):
        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        proto.is_connected.return_value = True

        class Req:
            host = 'host'
            port = 80
            ssl = False

        session = Session(loop=self.loop)
        key = ('host', 80, False)
        session._conns[key] = [(tr, proto, time.time())]

        loop = unittest.mock.Mock()

        tr1, proto1, tw = self.loop.run_until_complete(
            session.start(Req(), loop))
        self.assertFalse(loop.create_connection.called)
        self.assertEqual((tr1, proto1), (tr, proto))
        self.assertIsInstance(tw, TransportWrapper)

    def test_start_cleanup_task(self):
        loop = unittest.mock.Mock()
        session = Session(loop=loop)
        self.assertIsNone(session._cleanup_handle)

        session._start_cleanup_task()
        self.assertIsNotNone(session._cleanup_handle)
        loop.call_later.assert_called_with(
            session._reuse_timeout, session._cleanup)

    @unittest.mock.patch('aiohttp.session.time')
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
        session = Session(loop=loop)
        session._conns = testset
        existing_handle = session._cleanup_handle = unittest.mock.Mock()

        session._cleanup()
        self.assertTrue(existing_handle.cancel.called)
        self.assertEqual(session._conns, {})
        self.assertIsNone(session._cleanup_handle)

        testset = {1: [(unittest.mock.Mock(), unittest.mock.Mock(), 300)]}
        testset[1][0][1].is_connected.return_value = True

        session = Session(loop=loop)
        session._conns = testset
        session._cleanup()
        self.assertEqual(session._conns, testset)

        self.assertIsNotNone(session._cleanup_handle)
        