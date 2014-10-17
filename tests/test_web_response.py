import unittest
from unittest import mock
from aiohttp.web import Request, StreamResponse
from aiohttp.protocol import Request as RequestImpl, HttpVersion


class TestStreamResponse(unittest.TestCase):

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
        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        self.assertEqual(req, resp._request)
        self.assertIsNone(req._response)
        self.assertEqual(200, resp.status_code)
        self.assertTrue(resp.keep_alive)
        self.assertEqual(HttpVersion(1, 1), resp.version)

    def test_status_code_cannot_assign_nonint(self):
        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        with self.assertRaises(TypeError):
            resp.status_code = 'abc'
        self.assertEqual(200, resp.status_code)

    def test_status_code_setter(self):
        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        resp.status_code = 300
        self.assertEqual(300, resp.status_code)

    def test_status_code_cannot_assing_after_sending_headers(self):
        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        resp.send_headers()
        with self.assertRaises(RuntimeError):
            resp.status_code = 300
        self.assertEqual(200, resp.status_code)

    def test_change_version(self):
        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        resp.version = HttpVersion(1, 0)
        self.assertEqual(HttpVersion(1, 0), resp.version)

    def test_change_version_bad_type(self):
        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        with self.assertRaises(TypeError):
            resp.version = 123
        self.assertEqual(HttpVersion(1, 1), resp.version)

    def test_cannot_change_version_after_sending_headers(self):
        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        resp.send_headers()
        with self.assertRaises(RuntimeError):
            resp.version = HttpVersion(1, 0)
        self.assertEqual(HttpVersion(1, 1), resp.version)

    def test_content_length(self):
        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        self.assertIsNone(resp.content_length)

    def test_content_length_setter(self):
        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        resp.content_length = 234
        self.assertEqual(234, resp.content_length)

    def test_cannot_change_content_length_after_sending_headers(self):
        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        resp.send_headers()
        with self.assertRaises(RuntimeError):
            resp.content_length = 123
        self.assertIsNone(resp.content_length)

    def test_setting_content_type(self):

        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        resp.content_type = 'text/html'
        self.assertEqual('text/html', resp.headers['content-type'])

    def test_cannot_change_content_type_after_sending_headers(self):
        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        resp.content_type = 'text/plain'
        resp.send_headers()
        with self.assertRaises(RuntimeError):
            resp.content_type = 'text/html'
        self.assertEqual('text/plain', resp.content_type)

    def test_setting_charset(self):
        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        resp.content_type = 'text/html'
        resp.charset = 'koi8-r'
        self.assertEqual('text/html; charset=koi8-r',
                         resp.headers['content-type'])

    def test_default_charset(self):
        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        self.assertIsNone(resp.charset)

    def test_reset_charset(self):
        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        resp.content_type = 'text/html'
        resp.charset = None
        self.assertIsNone(resp.charset)

    def test_reset_charset_after_setting(self):
        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        resp.content_type = 'text/html'
        resp.charset = 'koi8-r'
        resp.charset = None
        self.assertIsNone(resp.charset)

    def test_charset_without_content_type(self):
        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        with self.assertRaises(RuntimeError):
            resp.charset = 'koi8-r'

    def test_cannot_send_headers_twice(self):
        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        resp.send_headers()
        with self.assertRaises(RuntimeError):
            resp.send_headers()
