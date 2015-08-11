import asyncio
import datetime
import unittest
from unittest import mock
from aiohttp import hdrs
from aiohttp.multidict import CIMultiDict
from aiohttp.web import ContentCoding, Request, StreamResponse, Response
from aiohttp.protocol import HttpVersion, HttpVersion11, HttpVersion10
from aiohttp.protocol import RawRequestMessage


class TestStreamResponse(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def make_request(self, method, path, headers=CIMultiDict()):
        message = RawRequestMessage(method, path, HttpVersion11, headers,
                                    False, False)
        return self.request_from_message(message)

    def request_from_message(self, message):
        self.app = mock.Mock()
        self.payload = mock.Mock()
        self.transport = mock.Mock()
        self.reader = mock.Mock()
        self.writer = mock.Mock()
        req = Request(self.app, message, self.payload,
                      self.transport, self.reader, self.writer)
        return req

    def test_ctor(self):
        resp = StreamResponse()
        self.assertEqual(200, resp.status)
        self.assertIsNone(resp.keep_alive)

    def test_content_length(self):
        resp = StreamResponse()
        self.assertIsNone(resp.content_length)

    def test_content_length_setter(self):
        resp = StreamResponse()

        resp.content_length = 234
        self.assertEqual(234, resp.content_length)

    def test_drop_content_length_header_on_setting_len_to_None(self):
        resp = StreamResponse()

        resp.content_length = 1
        self.assertEqual("1", resp.headers['Content-Length'])
        resp.content_length = None
        self.assertNotIn('Content-Length', resp.headers)

    def test_set_content_length_to_None_on_non_set(self):
        resp = StreamResponse()

        resp.content_length = None
        self.assertNotIn('Content-Length', resp.headers)
        resp.content_length = None
        self.assertNotIn('Content-Length', resp.headers)

    def test_setting_content_type(self):
        resp = StreamResponse()

        resp.content_type = 'text/html'
        self.assertEqual('text/html', resp.headers['content-type'])

    def test_setting_charset(self):
        resp = StreamResponse()

        resp.content_type = 'text/html'
        resp.charset = 'koi8-r'
        self.assertEqual('text/html; charset=koi8-r',
                         resp.headers['content-type'])

    def test_default_charset(self):
        resp = StreamResponse()

        self.assertIsNone(resp.charset)

    def test_reset_charset(self):
        resp = StreamResponse()

        resp.content_type = 'text/html'
        resp.charset = None
        self.assertIsNone(resp.charset)

    def test_reset_charset_after_setting(self):
        resp = StreamResponse()

        resp.content_type = 'text/html'
        resp.charset = 'koi8-r'
        resp.charset = None
        self.assertIsNone(resp.charset)

    def test_charset_without_content_type(self):
        resp = StreamResponse()

        with self.assertRaises(RuntimeError):
            resp.charset = 'koi8-r'

    def test_last_modified_initial(self):
        resp = StreamResponse()
        self.assertIsNone(resp.last_modified)

    def test_last_modified_string(self):
        resp = StreamResponse()

        dt = datetime.datetime(1990, 1, 2, 3, 4, 5, 0, datetime.timezone.utc)
        resp.last_modified = 'Mon, 2 Jan 1990 03:04:05 GMT'
        self.assertEqual(resp.last_modified, dt)

    def test_last_modified_timestamp(self):
        resp = StreamResponse()

        dt = datetime.datetime(1970, 1, 1, 0, 0, 0, 0, datetime.timezone.utc)

        resp.last_modified = 0
        self.assertEqual(resp.last_modified, dt)

        resp.last_modified = 0.0
        self.assertEqual(resp.last_modified, dt)

    def test_last_modified_datetime(self):
        resp = StreamResponse()

        dt = datetime.datetime(2001, 2, 3, 4, 5, 6, 0, datetime.timezone.utc)
        resp.last_modified = dt
        self.assertEqual(resp.last_modified, dt)

    def test_last_modified_reset(self):
        resp = StreamResponse()

        resp.last_modified = 0
        resp.last_modified = None
        self.assertEqual(resp.last_modified, None)

    @mock.patch('aiohttp.web_reqrep.ResponseImpl')
    def test_start(self, ResponseImpl):
        req = self.make_request('GET', '/')
        resp = StreamResponse()
        self.assertIsNone(resp.keep_alive)

        msg = resp.start(req)

        self.assertTrue(msg.send_headers.called)
        self.assertIs(msg, resp.start(req))

        self.assertTrue(resp.keep_alive)

        req2 = self.make_request('GET', '/')
        with self.assertRaises(RuntimeError):
            resp.start(req2)

    @mock.patch('aiohttp.web_reqrep.ResponseImpl')
    def test_chunked_encoding(self, ResponseImpl):
        req = self.make_request('GET', '/')
        resp = StreamResponse()
        self.assertFalse(resp.chunked)

        resp.enable_chunked_encoding()
        self.assertTrue(resp.chunked)

        msg = resp.start(req)
        self.assertTrue(msg.chunked)

    @mock.patch('aiohttp.web_reqrep.ResponseImpl')
    def test_chunk_size(self, ResponseImpl):
        req = self.make_request('GET', '/')
        resp = StreamResponse()
        self.assertFalse(resp.chunked)

        resp.enable_chunked_encoding(chunk_size=8192)
        self.assertTrue(resp.chunked)

        msg = resp.start(req)
        self.assertTrue(msg.chunked)
        msg.add_chunking_filter.assert_called_with(8192)
        self.assertIsNotNone(msg.filter)

    @mock.patch('aiohttp.web_reqrep.ResponseImpl')
    def test_compression_no_accept(self, ResponseImpl):
        req = self.make_request('GET', '/')
        resp = StreamResponse()
        self.assertFalse(resp.chunked)

        self.assertFalse(resp.compression)
        resp.enable_compression()
        self.assertTrue(resp.compression)

        msg = resp.start(req)
        self.assertFalse(msg.add_compression_filter.called)

    @mock.patch('aiohttp.web_reqrep.ResponseImpl')
    def test_force_compression_no_accept_backwards_compat(self, ResponseImpl):
        req = self.make_request('GET', '/')
        resp = StreamResponse()
        self.assertFalse(resp.chunked)

        self.assertFalse(resp.compression)
        resp.enable_compression(force=True)
        self.assertTrue(resp.compression)

        msg = resp.start(req)
        self.assertTrue(msg.add_compression_filter.called)
        self.assertIsNotNone(msg.filter)

    @mock.patch('aiohttp.web_reqrep.ResponseImpl')
    def test_force_compression_false_backwards_compat(self, ResponseImpl):
        req = self.make_request('GET', '/')
        resp = StreamResponse()

        self.assertFalse(resp.compression)
        resp.enable_compression(force=False)
        self.assertTrue(resp.compression)

        msg = resp.start(req)
        self.assertFalse(msg.add_compression_filter.called)

    @mock.patch('aiohttp.web_reqrep.ResponseImpl')
    def test_compression_default_coding(self, ResponseImpl):
        req = self.make_request(
            'GET', '/',
            headers=CIMultiDict({hdrs.ACCEPT_ENCODING: 'gzip, deflate'}))
        resp = StreamResponse()
        self.assertFalse(resp.chunked)

        self.assertFalse(resp.compression)
        resp.enable_compression()
        self.assertTrue(resp.compression)

        msg = resp.start(req)
        msg.add_compression_filter.assert_called_with('deflate')
        self.assertEqual('deflate', resp.headers.get(hdrs.CONTENT_ENCODING))
        self.assertIsNotNone(msg.filter)

    @mock.patch('aiohttp.web_reqrep.ResponseImpl')
    def test_force_compression_deflate(self, ResponseImpl):
        req = self.make_request(
            'GET', '/',
            headers=CIMultiDict({hdrs.ACCEPT_ENCODING: 'gzip, deflate'}))
        resp = StreamResponse()

        resp.enable_compression(ContentCoding.deflate)
        self.assertTrue(resp.compression)

        msg = resp.start(req)
        msg.add_compression_filter.assert_called_with('deflate')
        self.assertEqual('deflate', resp.headers.get(hdrs.CONTENT_ENCODING))

    @mock.patch('aiohttp.web_reqrep.ResponseImpl')
    def test_force_compression_no_accept_deflate(self, ResponseImpl):
        req = self.make_request('GET', '/')
        resp = StreamResponse()

        resp.enable_compression(ContentCoding.deflate)
        self.assertTrue(resp.compression)

        msg = resp.start(req)
        msg.add_compression_filter.assert_called_with('deflate')
        self.assertEqual('deflate', resp.headers.get(hdrs.CONTENT_ENCODING))

    @mock.patch('aiohttp.web_reqrep.ResponseImpl')
    def test_force_compression_gzip(self, ResponseImpl):
        req = self.make_request(
            'GET', '/',
            headers=CIMultiDict({hdrs.ACCEPT_ENCODING: 'gzip, deflate'}))
        resp = StreamResponse()

        resp.enable_compression(ContentCoding.gzip)
        self.assertTrue(resp.compression)

        msg = resp.start(req)
        msg.add_compression_filter.assert_called_with('gzip')
        self.assertEqual('gzip', resp.headers.get(hdrs.CONTENT_ENCODING))

    @mock.patch('aiohttp.web_reqrep.ResponseImpl')
    def test_force_compression_no_accept_gzip(self, ResponseImpl):
        req = self.make_request('GET', '/')
        resp = StreamResponse()

        resp.enable_compression(ContentCoding.gzip)
        self.assertTrue(resp.compression)

        msg = resp.start(req)
        msg.add_compression_filter.assert_called_with('gzip')
        self.assertEqual('gzip', resp.headers.get(hdrs.CONTENT_ENCODING))

    @mock.patch('aiohttp.web_reqrep.ResponseImpl')
    def test_delete_content_length_if_compression_enabled(self, ResponseImpl):
        req = self.make_request('GET', '/')
        resp = Response(body=b'answer')
        self.assertEqual(6, resp.content_length)

        resp.enable_compression(ContentCoding.gzip)

        resp.start(req)
        self.assertIsNone(resp.content_length)

    def test_write_non_byteish(self):
        resp = StreamResponse()
        resp.start(self.make_request('GET', '/'))

        with self.assertRaises(AssertionError):
            resp.write(123)

    def test_write_before_start(self):
        resp = StreamResponse()

        with self.assertRaises(RuntimeError):
            resp.write(b'data')

    def test_cannot_write_after_eof(self):
        resp = StreamResponse()
        resp.start(self.make_request('GET', '/'))

        resp.write(b'data')
        self.writer.drain.return_value = ()
        self.loop.run_until_complete(resp.write_eof())
        self.writer.write.reset_mock()

        with self.assertRaises(RuntimeError):
            resp.write(b'next data')
        self.assertFalse(self.writer.write.called)

    def test_cannot_write_eof_before_headers(self):
        resp = StreamResponse()

        with self.assertRaises(RuntimeError):
            self.loop.run_until_complete(resp.write_eof())

    def test_cannot_write_eof_twice(self):
        resp = StreamResponse()
        resp.start(self.make_request('GET', '/'))

        resp.write(b'data')
        self.writer.drain.return_value = ()
        self.loop.run_until_complete(resp.write_eof())
        self.assertTrue(self.writer.write.called)

        self.writer.write.reset_mock()
        self.loop.run_until_complete(resp.write_eof())
        self.assertFalse(self.writer.write.called)

    def test_write_returns_drain(self):
        resp = StreamResponse()
        resp.start(self.make_request('GET', '/'))

        self.assertEqual((), resp.write(b'data'))

    def test_write_returns_empty_tuple_on_empty_data(self):
        resp = StreamResponse()
        resp.start(self.make_request('GET', '/'))

        self.assertEqual((), resp.write(b''))

    def test_force_close(self):
        resp = StreamResponse()

        self.assertIsNone(resp.keep_alive)
        resp.force_close()
        self.assertFalse(resp.keep_alive)

    def test_response_cookies(self):
        resp = StreamResponse()

        self.assertEqual(resp.cookies, {})
        self.assertEqual(str(resp.cookies), '')

        resp.set_cookie('name', 'value')
        self.assertEqual(str(resp.cookies), 'Set-Cookie: name=value; Path=/')
        resp.set_cookie('name', 'other_value')
        self.assertEqual(str(resp.cookies),
                         'Set-Cookie: name=other_value; Path=/')

        resp.cookies['name'] = 'another_other_value'
        resp.cookies['name']['max-age'] = 10
        self.assertEqual(
            str(resp.cookies),
            'Set-Cookie: name=another_other_value; Max-Age=10; Path=/')

        resp.del_cookie('name')
        self.assertEqual(
            str(resp.cookies),
            'Set-Cookie: name=; Max-Age=0; Path=/')

        resp.set_cookie('name', 'value', domain='local.host', path=None)
        self.assertEqual(str(resp.cookies),
                         'Set-Cookie: name=value; Domain=local.host')

    def test_response_cookie_path(self):
        resp = StreamResponse()

        self.assertEqual(resp.cookies, {})

        resp.set_cookie('name', 'value', path='/some/path')
        self.assertEqual(str(resp.cookies),
                         'Set-Cookie: name=value; Path=/some/path')
        resp.set_cookie('name', 'value', expires='123')
        self.assertEqual(str(resp.cookies),
                         'Set-Cookie: name=value; expires=123;'
                         ' Path=/')
        resp.set_cookie('name', 'value', domain='example.com',
                        path='/home', expires='123', max_age='10',
                        secure=True, httponly=True, version='2.0')
        self.assertEqual(str(resp.cookies).lower(),
                         'set-cookie: name=value; '
                         'domain=example.com; '
                         'expires=123; '
                         'httponly; '
                         'max-age=10; '
                         'path=/home; '
                         'secure; '
                         'version=2.0')

    def test_response_cookie__issue_del_cookie(self):
        resp = StreamResponse()

        self.assertEqual(resp.cookies, {})
        self.assertEqual(str(resp.cookies), '')

        resp.del_cookie('name')
        self.assertEqual(str(resp.cookies),
                         'Set-Cookie: name=; Max-Age=0; Path=/')

    def test_cookie_set_after_del(self):
        resp = StreamResponse()

        resp.del_cookie('name')
        resp.set_cookie('name', 'val')
        # check for Max-Age dropped
        self.assertEqual(str(resp.cookies),
                         'Set-Cookie: name=val; Path=/')

    def test_set_status_with_reason(self):
        resp = StreamResponse()

        resp.set_status(200, "Everithing is fine!")
        self.assertEqual(200, resp.status)
        self.assertEqual("Everithing is fine!", resp.reason)

    def test_start_force_close(self):
        req = self.make_request('GET', '/')
        resp = StreamResponse()
        resp.force_close()
        self.assertFalse(resp.keep_alive)

        msg = resp.start(req)
        self.assertFalse(resp.keep_alive)
        self.assertTrue(msg.closing)

    def test___repr__(self):
        req = self.make_request('GET', '/path/to')
        resp = StreamResponse(reason=301)
        resp.start(req)
        self.assertEqual("<StreamResponse 301 GET /path/to >", repr(resp))

    def test___repr__not_started(self):
        resp = StreamResponse(reason=301)
        self.assertEqual("<StreamResponse 301 not started>", repr(resp))

    def test_keep_alive_http10(self):
        message = RawRequestMessage('GET', '/', HttpVersion10, CIMultiDict(),
                                    True, False)
        req = self.request_from_message(message)
        resp = StreamResponse()
        resp.start(req)
        self.assertFalse(resp.keep_alive)

        headers = CIMultiDict(Connection='keep-alive')
        message = RawRequestMessage('GET', '/', HttpVersion10, headers,
                                    False, False)
        req = self.request_from_message(message)
        resp = StreamResponse()
        resp.start(req)
        self.assertEqual(resp.keep_alive, True)

    def test_keep_alive_http09(self):
        headers = CIMultiDict(Connection='keep-alive')
        message = RawRequestMessage('GET', '/', HttpVersion(0, 9), headers,
                                    False, False)
        req = self.request_from_message(message)
        resp = StreamResponse()
        resp.start(req)
        self.assertFalse(resp.keep_alive)


class TestResponse(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def make_request(self, method, path, headers=CIMultiDict()):
        self.app = mock.Mock()
        message = RawRequestMessage(method, path, HttpVersion11, headers,
                                    False, False)
        self.payload = mock.Mock()
        self.transport = mock.Mock()
        self.reader = mock.Mock()
        self.writer = mock.Mock()
        req = Request(self.app, message, self.payload,
                      self.transport, self.reader, self.writer)
        return req

    def test_ctor(self):
        resp = Response()

        self.assertEqual(200, resp.status)
        self.assertEqual('OK', resp.reason)
        self.assertIsNone(resp.body)
        self.assertEqual(0, resp.content_length)
        self.assertEqual(CIMultiDict([('CONTENT-LENGTH', '0')]),
                         resp.headers)

    def test_ctor_with_headers_and_status(self):
        resp = Response(body=b'body', status=201, headers={'Age': '12'})

        self.assertEqual(201, resp.status)
        self.assertEqual(b'body', resp.body)
        self.assertEqual(4, resp.content_length)
        self.assertEqual(CIMultiDict(
            [('AGE', '12'),
             ('CONTENT-LENGTH', '4')]), resp.headers)

    def test_ctor_content_type(self):
        resp = Response(content_type='application/json')

        self.assertEqual(200, resp.status)
        self.assertEqual('OK', resp.reason)
        self.assertEqual(
            CIMultiDict(
                [('CONTENT-TYPE', 'application/json'),
                 ('CONTENT-LENGTH', '0')]),
            resp.headers)

    def test_ctor_text_body_combined(self):
        with self.assertRaises(ValueError):
            Response(body=b'123', text='test text')

    def test_ctor_text(self):
        resp = Response(text='test text')

        self.assertEqual(200, resp.status)
        self.assertEqual('OK', resp.reason)
        self.assertEqual(
            CIMultiDict(
                [('CONTENT-TYPE', 'text/plain; charset=utf-8'),
                 ('CONTENT-LENGTH', '9')]),
            resp.headers)

        self.assertEqual(resp.body, b'test text')
        self.assertEqual(resp.text, 'test text')

    def test_assign_nonbyteish_body(self):
        resp = Response(body=b'data')

        with self.assertRaises(TypeError):
            resp.body = 123
        self.assertEqual(b'data', resp.body)
        self.assertEqual(4, resp.content_length)

    def test_assign_nonstr_text(self):
        resp = Response(text='test')

        with self.assertRaises(TypeError):
            resp.text = b'123'
        self.assertEqual(b'test', resp.body)
        self.assertEqual(4, resp.content_length)

    def test_send_headers_for_empty_body(self):
        req = self.make_request('GET', '/')
        resp = Response()

        self.writer.drain.return_value = ()
        buf = b''

        def append(data):
            nonlocal buf
            buf += data

        self.writer.write.side_effect = append

        resp.start(req)
        self.loop.run_until_complete(resp.write_eof())
        txt = buf.decode('utf8')
        self.assertRegex(txt, 'HTTP/1.1 200 OK\r\nCONTENT-LENGTH: 0\r\n'
                         'CONNECTION: keep-alive\r\n'
                         'DATE: .+\r\nSERVER: .+\r\n\r\n')

    def test_render_with_body(self):
        req = self.make_request('GET', '/')
        resp = Response(body=b'data')

        self.writer.drain.return_value = ()
        buf = b''

        def append(data):
            nonlocal buf
            buf += data

        self.writer.write.side_effect = append

        resp.start(req)
        self.loop.run_until_complete(resp.write_eof())
        txt = buf.decode('utf8')
        self.assertRegex(txt, 'HTTP/1.1 200 OK\r\nCONTENT-LENGTH: 4\r\n'
                         'CONNECTION: keep-alive\r\n'
                         'DATE: .+\r\nSERVER: .+\r\n\r\ndata')

    def test_send_set_cookie_header(self):
        resp = Response()
        resp.cookies['name'] = 'value'

        req = self.make_request('GET', '/')
        self.writer.drain.return_value = ()
        buf = b''

        def append(data):
            nonlocal buf
            buf += data

        self.writer.write.side_effect = append

        resp.start(req)
        self.loop.run_until_complete(resp.write_eof())
        txt = buf.decode('utf8')
        self.assertRegex(txt, 'HTTP/1.1 200 OK\r\nCONTENT-LENGTH: 0\r\n'
                         'SET-COOKIE: name=value\r\n'
                         'CONNECTION: keep-alive\r\n'
                         'DATE: .+\r\nSERVER: .+\r\n\r\n')

    def test_set_text_with_content_type(self):
        resp = Response()
        resp.content_type = "text/html"
        resp.text = "text"

        self.assertEqual("text", resp.text)
        self.assertEqual(b"text", resp.body)
        self.assertEqual("text/html", resp.content_type)

    def test_set_text_with_charset(self):
        resp = Response()
        resp.content_type = 'text/plain'
        resp.charset = "KOI8-R"
        resp.text = "текст"

        self.assertEqual("текст", resp.text)
        self.assertEqual("текст".encode('koi8-r'), resp.body)
        self.assertEqual("koi8-r", resp.charset)

    def test_started_when_not_started(self):
        resp = StreamResponse()
        self.assertFalse(resp.started)

    def test_started_when_started(self):
        resp = StreamResponse()
        resp.start(self.make_request('GET', '/'))
        self.assertTrue(resp.started)

    def test_drain_before_start(self):

        @asyncio.coroutine
        def go():
            resp = StreamResponse()
            with self.assertRaises(RuntimeError):
                yield from resp.drain()

        self.loop.run_until_complete(go())

    def test_nonstr_text_in_ctor(self):
        with self.assertRaises(TypeError):
            Response(text=b'data')

    def test_text_in_ctor_with_content_type(self):
        resp = Response(text='data', content_type='text/html')
        self.assertEqual('data', resp.text)
        self.assertEqual('text/html', resp.content_type)

    def test_text_in_ctor_with_content_type_header(self):
        resp = Response(text='текст',
                        headers={'Content-Type': 'text/html; charset=koi8-r'})
        self.assertEqual('текст'.encode('koi8-r'), resp.body)
        self.assertEqual('text/html', resp.content_type)
        self.assertEqual('koi8-r', resp.charset)

    def test_text_with_empty_payload(self):
        resp = Response(status=200)
        self.assertEqual(resp.body, None)
        self.assertEqual(resp.text, None)
