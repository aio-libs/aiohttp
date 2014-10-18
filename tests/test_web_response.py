import asyncio
import unittest
from unittest import mock
from aiohttp.multidict import MultiDict, CaseInsensitiveMultiDict
from aiohttp.web import Request, StreamResponse, Response
from aiohttp.protocol import RawRequestMessage, HttpVersion11


class TestStreamResponse(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def make_request(self, method, path, headers=MultiDict()):
        self.app = mock.Mock()
        message = RawRequestMessage(method, path, HttpVersion11, headers,
                                    False, False)
        self.payload = mock.Mock()
        self.writer = mock.Mock()
        req = Request(self.app, message, self.payload, self.writer)
        return req

    def test_ctor(self):
        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        self.assertEqual(req, resp._request)
        self.assertIsNone(req._response)
        self.assertEqual(200, resp.status)
        self.assertTrue(resp.keep_alive)

    def test_status_cannot_assign_nonint(self):
        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        with self.assertRaises(TypeError):
            resp.status = 'abc'
        self.assertEqual(200, resp.status)

    def test_status_setter(self):
        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        resp.status = 300
        self.assertEqual(300, resp.status)

    def test_status_cannot_assing_after_sending_headers(self):
        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        resp.send_headers()
        with self.assertRaises(RuntimeError):
            resp.status = 300
        self.assertEqual(200, resp.status)

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

    def test_drop_content_length_header_on_setting_len_to_None(self):
        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        resp.content_length = 1
        self.assertEqual("1", resp.headers['Content-Length'])
        resp.content_length = None
        self.assertNotIn('Content-Length', resp.headers)

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

    def test_cannot_send_headers_after_eof(self):
        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        resp.send_headers()
        resp.write_eof()
        with self.assertRaises(RuntimeError):
            resp.send_headers()

    def test_write_non_byteish(self):
        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        with self.assertRaises(TypeError):
            resp.write(123)

    def test_write_before_sending_headers(self):
        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        resp.write(b'data')
        self.assertTrue(self.writer.write.called)

    def test_cannot_write_after_eof(self):
        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        resp.write(b'data')
        self.writer.drain.return_value = ()
        self.loop.run_until_complete(resp.write_eof())
        self.writer.write.reset_mock()

        with self.assertRaises(RuntimeError):
            resp.write(b'next data')
        self.assertFalse(self.writer.write.called)

    def test_cannot_write_eof_before_headers(self):
        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        with self.assertRaises(RuntimeError):
            self.loop.run_until_complete(resp.write_eof())

    def test_cannot_write_eof_twice(self):
        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        resp.write(b'data')
        self.writer.drain.return_value = ()
        self.loop.run_until_complete(resp.write_eof())
        self.assertTrue(self.writer.write.called)

        self.writer.write.reset_mock()
        self.loop.run_until_complete(resp.write_eof())
        self.assertFalse(self.writer.write.called)

    def test_force_close(self):
        req = self.make_request('GET', '/')
        resp = StreamResponse(req)

        self.assertTrue(resp.keep_alive)
        resp.force_close()
        self.assertFalse(resp.keep_alive)


class TestResponse(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def make_request(self, method, path, headers=MultiDict()):
        self.app = mock.Mock()
        message = RawRequestMessage(method, path, HttpVersion11, headers,
                                    False, False)
        self.payload = mock.Mock()
        self.writer = mock.Mock()
        req = Request(self.app, message, self.payload, self.writer)
        return req

    def test_ctor(self):
        req = self.make_request('GET', '/')
        resp = Response(req)

        self.assertEqual(200, resp.status)
        self.assertIsNone(resp.body)
        self.assertEqual(0, resp.content_length)
        self.assertEqual(CaseInsensitiveMultiDict([('CONTENT-LENGTH', '0')]),
                         resp.headers)

    def test_ctor_with_headers_and_status(self):
        req = self.make_request('GET', '/')
        resp = Response(req, b'body', status=201, headers={'Age': '12'})

        self.assertEqual(201, resp.status)
        self.assertEqual(b'body', resp.body)
        self.assertEqual(4, resp.content_length)
        self.assertEqual(CaseInsensitiveMultiDict([('CONTENT-LENGTH', '4'),
                                                   ('AGE', '12')]),
                         resp.headers)

    def test_assign_nonbyteish_body(self):
        req = self.make_request('GET', '/')
        resp = Response(req, b'data')

        with self.assertRaises(TypeError):
            resp.body = 123
        self.assertEqual(b'data', resp.body)
        self.assertEqual(4, resp.content_length)

    def test_send_headers_for_empty_body(self):
        req = self.make_request('GET', '/')
        resp = Response(req)

        self.writer.drain.return_value = ()
        buf = b''

        def append(data):
            nonlocal buf
            buf += data

        self.writer.write.side_effect = append

        self.loop.run_until_complete(resp.render())
        txt = buf.decode('utf8')
        self.assertRegex(txt, 'HTTP/1.1 200 OK\r\nCONTENT-LENGTH: 0\r\n'
                         'CONNECTION: keep-alive\r\n'
                         'DATE: .+\r\nSERVER: .+\r\n\r\n')

    def test_render_with_body(self):
        req = self.make_request('GET', '/')
        resp = Response(req, b'data')

        self.writer.drain.return_value = ()
        buf = b''

        def append(data):
            nonlocal buf
            buf += data

        self.writer.write.side_effect = append

        self.loop.run_until_complete(resp.render())
        txt = buf.decode('utf8')
        self.assertRegex(txt, 'HTTP/1.1 200 OK\r\nCONTENT-LENGTH: 4\r\n'
                         'CONNECTION: keep-alive\r\n'
                         'DATE: .+\r\nSERVER: .+\r\n\r\ndata')
