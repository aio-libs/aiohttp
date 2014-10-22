import asyncio
import collections
import unittest
from unittest import mock
from aiohttp.multidict import MultiDict
from aiohttp.web import Request
from aiohttp.protocol import RawRequestMessage, HttpVersion11

from aiohttp import web


class TestHTTPExceptions(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

        self.writer = mock.Mock()
        self.writer.drain.return_value = ()
        self.buf = b''

        self.writer.write.side_effect = self.append

    def tearDown(self):
        self.loop.close()

    def append(self, data):
        self.buf += data

    def make_request(self, method='GET', path='/', headers=MultiDict()):
        self.app = mock.Mock()
        message = RawRequestMessage(method, path, HttpVersion11, headers,
                                    False, False)
        self.payload = mock.Mock()
        req = Request(self.app, message, self.payload, self.writer)
        return req

    def test_all_http_exceptions_exported(self):
        self.assertIn('HTTPException', web.__all__)
        for name in dir(web):
            if name.startswith('_'):
                continue
            obj = getattr(web, name)
            if isinstance(obj, type) and issubclass(obj, web.HTTPException):
                self.assertIn(name, web.__all__)

    def test_HTTPOk(self):
        req = self.make_request()
        resp = web.HTTPOk(req)
        self.loop.run_until_complete(resp.write_eof())
        txt = self.buf.decode('utf8')
        self.assertRegex(txt, ('HTTP/1.1 200 OK\r\n'
                               'CONTENT-LENGTH: 0\r\n'
                               'CONNECTION: keep-alive\r\n'
                               'DATE: .+\r\n'
                               'SERVER: .+\r\n\r\n'))

    def test_terminal_classes_has_status_code(self):
        terminals = set()
        for name in dir(web):
            obj = getattr(web, name)
            if isinstance(obj, type) and issubclass(obj, web.HTTPException):
                terminals.add(obj)

        dup = frozenset(terminals)
        for cls1 in dup:
            for cls2 in dup:
                if cls1 in cls2.__bases__:
                    terminals.discard(cls1)

        for cls in terminals:
            self.assertIsNotNone(cls.status_code, cls)
        codes = collections.Counter(cls.status_code for cls in terminals)
        self.assertNotIn(None, codes)
        self.assertEqual(1, codes.most_common(1)[0][1])

    def test_HTTPFound(self):
        req = self.make_request()
        resp = web.HTTPFound(req, location='/redirect')
        self.assertEqual('/redirect', resp.location)
        self.assertEqual('/redirect', resp.headers['location'])
        self.loop.run_until_complete(resp.write_eof())
        txt = self.buf.decode('utf8')
        self.assertRegex(txt, ('HTTP/1.1 302 Found\r\n'
                               'CONTENT-LENGTH: 0\r\n'
                               'LOCATION: /redirect\r\n'
                               'CONNECTION: keep-alive\r\n'
                               'DATE: .+\r\n'
                               'SERVER: .+\r\n\r\n'))

    def test_HTTPFound_empty_location(self):
        req = self.make_request()

        with self.assertRaises(ValueError):
            web.HTTPFound(req, location='')

        with self.assertRaises(ValueError):
            web.HTTPFound(req, location=None)

    def test_HTTPMethodNotAllowed(self):
        req = self.make_request()
        resp = web.HTTPMethodNotAllowed(req, 'get', ['POST', 'PUT'])
        self.assertEqual('GET', resp.method)
        self.assertEqual(['POST', 'PUT'], resp.allowed_methods)
        self.assertEqual('POST,PUT', resp.headers['allow'])
        self.loop.run_until_complete(resp.write_eof())
        txt = self.buf.decode('utf8')
        self.assertRegex(txt, ('HTTP/1.1 405 Method Not Allowed\r\n'
                               'CONTENT-LENGTH: 0\r\n'
                               'ALLOW: POST,PUT\r\n'
                               'CONNECTION: keep-alive\r\n'
                               'DATE: .+\r\n'
                               'SERVER: .+\r\n\r\n'))
