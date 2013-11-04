"""Tests for aiohttp/session.py"""

import http.cookies
import asyncio
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
        session = Session()
        close = session.close = unittest.mock.Mock()

        del session
        self.assertTrue(close.called)

    def test_close(self):
        tr = unittest.mock.Mock()

        session = Session()
        session._conns[1] = [(tr, object())]
        session.close()

        self.assertFalse(session._conns)
        self.assertTrue(tr.close.called)

    def test_get(self):
        session = Session()
        self.assertEqual(session._get(1), (None, None))

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        session._conns[1] = [(tr, proto)]
        self.assertEqual(session._get(1), (tr, proto))

    def test_release(self):
        session = Session()
        req = unittest.mock.Mock()
        resp = req.response = unittest.mock.Mock()
        resp.message.should_close = False

        cookies = resp.cookies = http.cookies.SimpleCookie()
        cookies['c1'] = 'cookie1'
        cookies['c2'] = 'cookie2'

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        session._release(req, 1, (tr, proto))
        self.assertEqual(session._conns[1][0], (tr, proto))
        self.assertEqual(session.cookies, dict(cookies.items()))

    def test_release_close(self):
        session = Session()
        req = unittest.mock.Mock()
        resp = unittest.mock.Mock()
        resp.message.should_close = True
        req.response = resp

        cookies = resp.cookies = http.cookies.SimpleCookie()
        cookies['c1'] = 'cookie1'
        cookies['c2'] = 'cookie2'

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        session._release(req, 1, (tr, proto))
        self.assertFalse(session._conns)
        self.assertTrue(tr.close.called)

    def test_release_not_started(self):
        session = Session()
        req = unittest.mock.Mock()
        req.response = None

        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        session._release(req, 1, (tr, proto))
        self.assertEqual(session._conns, {1: [(tr, proto)]})
        self.assertFalse(tr.close.called)

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

        session = Session()
        key = ('host', 80, False)
        session._conns[key] = [(unittest.mock.Mock(), proto)]

        self.loop.run_until_complete(session.start(Req(), Loop()))
        self.assertTrue(new_connection)

    def test_start_existing(self):
        tr, proto = unittest.mock.Mock(), unittest.mock.Mock()
        proto.is_connected.return_value = True

        class Req:
            host = 'host'
            port = 80
            ssl = False

        session = Session()
        key = ('host', 80, False)
        session._conns[key] = [(tr, proto)]

        loop = unittest.mock.Mock()

        tr1, proto1, tw = self.loop.run_until_complete(
            session.start(Req(), loop))
        self.assertFalse(loop.create_connection.called)
        self.assertEqual((tr1, proto1), (tr, proto))
        self.assertIsInstance(tw, TransportWrapper)
