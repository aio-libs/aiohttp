import unittest
from unittest import mock
from aiohttp.web import Request
from aiohttp.multidict import MultiDict
from aiohttp.protocol import HttpVersion
from aiohttp.protocol import Request as RequestImpl


class TestWebRequest(unittest.TestCase):

    def make_request(self, method, path, headers=()):
        self.app = mock.Mock()
        self.transport = mock.Mock()
        message = RequestImpl(self.transport, method, path)
        message.headers.extend(headers)
        self.payload = mock.Mock()
        self.protocol = mock.Mock()
        req = Request(self.app, message, self.payload, self.protocol)
        return req

    def test_ctor(self):
        req = self.make_request('GeT', '/path/to?a=1&b=2')

        self.assertIs(self.app, req.app)
        self.assertEqual('GET', req.method)
        self.assertEqual(HttpVersion(1, 1), req.version)
        self.assertEqual(None, req.host)
        self.assertEqual('/path/to?a=1&b=2', req.path_qs)
        self.assertEqual('/path/to', req.path)
        self.assertEqual('a=1&b=2', req.query_string)
        self.assertEqual(MultiDict([('a', '1'), ('b', '2')]), req.GET)
        self.assertIs(self.payload, req.payload)

    def test_content_type_not_specified(self):
        req = self.make_request('Get', '/')
        self.assertEqual('application/octet-stream', req.content_type)

    def test_content_type_from_spec(self):
        req = self.make_request('Get', '/',
                                {'content-type': 'application/json'})
        self.assertEqual('application/json', req.content_type)

    def test_content_type_from_spec_with_charset(self):
        req = self.make_request('Get', '/',
                                {'content-type': 'text/html; charset=UTF-8'})
        self.assertEqual('text/html', req.content_type)
        self.assertEqual('UTF-8', req.charset)

    def test_calc_content_type_on_getting_charset(self):
        req = self.make_request('Get', '/',
                                {'content-type': 'text/html; charset=UTF-8'})
        self.assertEqual('UTF-8', req.charset)
        self.assertEqual('text/html', req.content_type)
