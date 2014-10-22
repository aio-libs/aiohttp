import asyncio
import unittest
from unittest import mock
from aiohttp.multidict import MultiDict
from aiohttp.web import Request
from aiohttp.protocol import RawRequestMessage, HttpVersion11

from aiohttp.web import (HTTPException, HTTPOk, HTTPCreated)
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
            if isinstance(obj, type) and issubclass(obj, HTTPException):
                self.assertIn(name, web.__all__)

    def test_HTTPOk(self):
        req = self.make_request()
        resp = HTTPOk(req)
        self.loop.run_until_complete(resp.write_eof())
        txt = self.buf.decode('utf8')
        self.assertRegex(txt, ('HTTP/1.1 200 OK\r\n'
                               'CONTENT-LENGTH: 11\r\n'
                               'CONTENT-TYPE: text/plain\r\n'
                               'CONNECTION: keep-alive\r\n'
                               'DATE: .+\r\n'
                               'SERVER: .+\r\n\r\n'
                               '200 OK\n\n\n\n'))

    def test_HTTPOk_html(self):
        req = self.make_request(headers=MultiDict(ACCEPT='text/html'))
        resp = HTTPOk(req)
        self.loop.run_until_complete(resp.write_eof())
        txt = self.buf.decode('utf8')
        self.assertRegex(txt, ('HTTP/1.1 200 OK\r\n'
                               'CONTENT-LENGTH: 104\r\n'
                               'CONTENT-TYPE: text/html\r\n'
                               'CONNECTION: keep-alive\r\n'
                               'DATE: .+\r\n'
                               'SERVER: .+\r\n\r\n'
                               '<html>\n'
                               ' <head>\n'
                               '  <title>200 OK</title>\n'
                               ' </head>\n'
                               ' <body>\n'
                               '  <h1>200 OK</h1>\n'
                               '  <br/><br/>'
                               '\n'
                               '\n'
                               ' </body>\n'
                               '</html>'))

    def test_HTTPCreated(self):
        req = self.make_request()
        resp = HTTPCreated(req)
        self.loop.run_until_complete(resp.write_eof())
        txt = resp.body.decode('utf8')
        self.assertEqual('201 Created\n\n\n\n\n', txt)
