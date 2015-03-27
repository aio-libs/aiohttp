# -*- coding: utf-8 -*-
"""Tests for aiohttp/client.py"""

import asyncio
import inspect
import io
import unittest
import unittest.mock
import urllib.parse

import aiohttp
from aiohttp.client import ClientRequest, ClientResponse

try:
    import chardet
except ImportError:  # pragma: no cover
    chardet = None


class ClientResponseTests(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

        self.connection = unittest.mock.Mock()
        self.stream = aiohttp.StreamParser(loop=self.loop)
        self.response = ClientResponse('get', 'http://python.org')

    def tearDown(self):
        self.loop.close()

    def test_del(self):
        response = ClientResponse('get', 'http://python.org')

        connection = unittest.mock.Mock()
        response._setup_connection(connection)
        with self.assertWarns(ResourceWarning):
            del response

        connection.close.assert_called_with()

    def test_close(self):
        self.response.connection = self.connection
        self.response.close()
        self.assertIsNone(self.response.connection)
        self.assertTrue(self.connection.release.called)
        self.response.close()
        self.response.close()

    def test_wait_for_100(self):
        response = ClientResponse(
            'get', 'http://python.org', continue100=object())
        self.assertTrue(response.waiting_for_continue())
        response = ClientResponse(
            'get', 'http://python.org')
        self.assertFalse(response.waiting_for_continue())

    def test_repr(self):
        self.response.status = 200
        self.response.reason = 'Ok'
        self.assertIn(
            '<ClientResponse(http://python.org) [200 Ok]>',
            repr(self.response))

    def test_read_and_release_connection(self):
        def side_effect(*args, **kwargs):
            fut = asyncio.Future(loop=self.loop)
            fut.set_result(b'payload')
            return fut
        content = self.response.content = unittest.mock.Mock()
        content.read.side_effect = side_effect
        self.response.close = unittest.mock.Mock()

        res = self.loop.run_until_complete(self.response.read())
        self.assertEqual(res, b'payload')
        self.assertTrue(self.response.close.called)

    def test_read_and_release_connection_with_error(self):
        content = self.response.content = unittest.mock.Mock()
        content.read.return_value = asyncio.Future(loop=self.loop)
        content.read.return_value.set_exception(ValueError)
        self.response.close = unittest.mock.Mock()

        self.assertRaises(
            ValueError,
            self.loop.run_until_complete, self.response.read())
        self.response.close.assert_called_with(True)

    def test_release(self):
        fut = asyncio.Future(loop=self.loop)
        fut.set_result(b'')
        content = self.response.content = unittest.mock.Mock()
        content.readany.return_value = fut
        self.response.close = unittest.mock.Mock()

        self.loop.run_until_complete(self.response.release())
        self.assertTrue(self.response.close.called)

    def test_read_and_close(self):
        self.response.read = unittest.mock.Mock()
        self.response.read.return_value = asyncio.Future(loop=self.loop)
        self.response.read.return_value.set_result(b'data')

        with self.assertWarns(DeprecationWarning):
            res = self.loop.run_until_complete(self.response.read_and_close())
        self.assertEqual(res, b'data')
        self.assertTrue(self.response.read.called)

    def test_read_decode_deprecated(self):
        self.response._content = b'data'
        self.response.json = unittest.mock.Mock()
        self.response.json.return_value = asyncio.Future(loop=self.loop)
        self.response.json.return_value.set_result('json')

        with self.assertWarns(DeprecationWarning):
            res = self.loop.run_until_complete(self.response.read(decode=True))
        self.assertEqual(res, 'json')
        self.assertTrue(self.response.json.called)

    def test_text(self):
        def side_effect(*args, **kwargs):
            fut = asyncio.Future(loop=self.loop)
            fut.set_result('{"тест": "пройден"}'.encode('cp1251'))
            return fut
        self.response.headers = {
            'CONTENT-TYPE': 'application/json;charset=cp1251'}
        content = self.response.content = unittest.mock.Mock()
        content.read.side_effect = side_effect
        self.response.close = unittest.mock.Mock()

        res = self.loop.run_until_complete(self.response.text())
        self.assertEqual(res, '{"тест": "пройден"}')
        self.assertTrue(self.response.close.called)

    def test_text_custom_encoding(self):
        def side_effect(*args, **kwargs):
            fut = asyncio.Future(loop=self.loop)
            fut.set_result('{"тест": "пройден"}'.encode('cp1251'))
            return fut
        self.response.headers = {
            'CONTENT-TYPE': 'application/json'}
        content = self.response.content = unittest.mock.Mock()
        content.read.side_effect = side_effect
        self.response.close = unittest.mock.Mock()

        res = self.loop.run_until_complete(
            self.response.text(encoding='cp1251'))
        self.assertEqual(res, '{"тест": "пройден"}')
        self.assertTrue(self.response.close.called)

    @unittest.skipIf(chardet is None, "no chardet")
    def test_text_detect_encoding(self):
        def side_effect(*args, **kwargs):
            fut = asyncio.Future(loop=self.loop)
            fut.set_result('{"тест": "пройден"}'.encode('cp1251'))
            return fut
        self.response.headers = {'CONTENT-TYPE': 'application/json'}
        content = self.response.content = unittest.mock.Mock()
        content.read.side_effect = side_effect
        self.response.close = unittest.mock.Mock()

        res = self.loop.run_until_complete(self.response.text())
        self.assertEqual(res, '{"тест": "пройден"}')
        self.assertTrue(self.response.close.called)

    def test_text_detect_encoding_without_chardet(self):
        def side_effect(*args, **kwargs):
            fut = asyncio.Future(loop=self.loop)
            fut.set_result('{"тест": "пройден"}'.encode('cp1251'))
            return fut
        self.response.headers = {'CONTENT-TYPE': 'application/json'}
        content = self.response.content = unittest.mock.Mock()
        content.read.side_effect = side_effect
        self.response.close = unittest.mock.Mock()

        with unittest.mock.patch('aiohttp.client.chardet', None):
            self.assertRaises(UnicodeDecodeError,
                              self.loop.run_until_complete,
                              self.response.text())

    def test_json(self):
        def side_effect(*args, **kwargs):
            fut = asyncio.Future(loop=self.loop)
            fut.set_result('{"тест": "пройден"}'.encode('cp1251'))
            return fut
        self.response.headers = {
            'CONTENT-TYPE': 'application/json;charset=cp1251'}
        content = self.response.content = unittest.mock.Mock()
        content.read.side_effect = side_effect
        self.response.close = unittest.mock.Mock()

        res = self.loop.run_until_complete(self.response.json())
        self.assertEqual(res, {'тест': 'пройден'})
        self.assertTrue(self.response.close.called)

    def test_json_custom_loader(self):
        self.response.headers = {
            'CONTENT-TYPE': 'application/json;charset=cp1251'}
        self.response._content = b'data'

        def custom(content):
            return content + '-custom'

        res = self.loop.run_until_complete(self.response.json(loads=custom))
        self.assertEqual(res, 'data-custom')

    @unittest.mock.patch('aiohttp.client.client_logger')
    def test_json_no_content(self, m_log):
        self.response.headers = {
            'CONTENT-TYPE': 'data/octet-stream'}
        self.response._content = b''
        self.response.close = unittest.mock.Mock()

        res = self.loop.run_until_complete(self.response.json())
        self.assertIsNone(res)
        m_log.warning.assert_called_with(
            'Attempt to decode JSON with unexpected mimetype: %s',
            'data/octet-stream')

    def test_json_override_encoding(self):
        def side_effect(*args, **kwargs):
            fut = asyncio.Future(loop=self.loop)
            fut.set_result('{"тест": "пройден"}'.encode('cp1251'))
            return fut
        self.response.headers = {
            'CONTENT-TYPE': 'application/json;charset=utf8'}
        content = self.response.content = unittest.mock.Mock()
        content.read.side_effect = side_effect
        self.response.close = unittest.mock.Mock()

        res = self.loop.run_until_complete(
            self.response.json(encoding='cp1251'))
        self.assertEqual(res, {'тест': 'пройден'})
        self.assertTrue(self.response.close.called)

    @unittest.skipIf(chardet is None, "no chardet")
    def test_json_detect_encoding(self):
        def side_effect(*args, **kwargs):
            fut = asyncio.Future(loop=self.loop)
            fut.set_result('{"тест": "пройден"}'.encode('cp1251'))
            return fut
        self.response.headers = {'CONTENT-TYPE': 'application/json'}
        content = self.response.content = unittest.mock.Mock()
        content.read.side_effect = side_effect
        self.response.close = unittest.mock.Mock()

        res = self.loop.run_until_complete(self.response.json())
        self.assertEqual(res, {'тест': 'пройден'})
        self.assertTrue(self.response.close.called)

    def test_json_detect_encoding_without_chardet(self):
        def side_effect(*args, **kwargs):
            fut = asyncio.Future(loop=self.loop)
            fut.set_result('{"тест": "пройден"}'.encode('cp1251'))
            return fut
        self.response.headers = {'CONTENT-TYPE': 'application/json'}
        content = self.response.content = unittest.mock.Mock()
        content.read.side_effect = side_effect
        self.response.close = unittest.mock.Mock()

        with unittest.mock.patch('aiohttp.client.chardet', None):
            self.assertRaises(UnicodeDecodeError,
                              self.loop.run_until_complete,
                              self.response.json())

    def test_override_flow_control(self):
        class MyResponse(ClientResponse):
            flow_control_class = aiohttp.FlowControlDataQueue
        response = MyResponse('get', 'http://python.org')
        response._setup_connection(self.connection)
        self.assertIsInstance(response.content, aiohttp.FlowControlDataQueue)
        with self.assertWarns(ResourceWarning):
            del response


class ClientRequestTests(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

        self.transport = unittest.mock.Mock()
        self.connection = unittest.mock.Mock()
        self.protocol = unittest.mock.Mock()
        self.protocol.writer.drain.return_value = ()
        self.stream = aiohttp.StreamParser(loop=self.loop)

    def tearDown(self):
        self.loop.close()

    def test_method(self):
        req = ClientRequest('get', 'http://python.org/')
        self.assertEqual(req.method, 'GET')

        req = ClientRequest('head', 'http://python.org/')
        self.assertEqual(req.method, 'HEAD')

        req = ClientRequest('HEAD', 'http://python.org/')
        self.assertEqual(req.method, 'HEAD')

    def test_version(self):
        req = ClientRequest('get', 'http://python.org/', version='1.0')
        self.assertEqual(req.version, (1, 0))

    def test_version_err(self):
        self.assertRaises(
            ValueError,
            ClientRequest, 'get', 'http://python.org/', version='1.c')

    def test_host_port(self):
        req = ClientRequest('get', 'http://python.org/')
        self.assertEqual(req.host, 'python.org')
        self.assertEqual(req.port, 80)
        self.assertFalse(req.ssl)

        req = ClientRequest('get', 'https://python.org/')
        self.assertEqual(req.host, 'python.org')
        self.assertEqual(req.port, 443)
        self.assertTrue(req.ssl)

        req = ClientRequest('get', 'https://python.org:960/')
        self.assertEqual(req.host, 'python.org')
        self.assertEqual(req.port, 960)
        self.assertTrue(req.ssl)

    def test_host_port_err(self):
        self.assertRaises(
            ValueError, ClientRequest, 'get', 'http://python.org:123e/')

    def test_host_header(self):
        req = ClientRequest('get', 'http://python.org/')
        self.assertEqual(req.headers['HOST'], 'python.org')

        req = ClientRequest('get', 'http://python.org:80/')
        self.assertEqual(req.headers['HOST'], 'python.org:80')

        req = ClientRequest('get', 'http://python.org:99/')
        self.assertEqual(req.headers['HOST'], 'python.org:99')

        req = ClientRequest('get', 'http://python.org/',
                            headers={'host': 'example.com'})
        self.assertEqual(req.headers['HOST'], 'example.com')

        req = ClientRequest('get', 'http://python.org/',
                            headers={'host': 'example.com:99'})
        self.assertEqual(req.headers['HOST'], 'example.com:99')

    def test_headers(self):
        req = ClientRequest('get', 'http://python.org/',
                            headers={'Content-Type': 'text/plain'})
        self.assertIn('CONTENT-TYPE', req.headers)
        self.assertEqual(req.headers['CONTENT-TYPE'], 'text/plain')
        self.assertEqual(req.headers['ACCEPT-ENCODING'], 'gzip, deflate')

    def test_headers_list(self):
        req = ClientRequest('get', 'http://python.org/',
                            headers=[('Content-Type', 'text/plain')])
        self.assertIn('CONTENT-TYPE', req.headers)
        self.assertEqual(req.headers['CONTENT-TYPE'], 'text/plain')

    def test_headers_default(self):
        req = ClientRequest('get', 'http://python.org/',
                            headers={'ACCEPT-ENCODING': 'deflate'})
        self.assertEqual(req.headers['ACCEPT-ENCODING'], 'deflate')

    def test_invalid_url(self):
        self.assertRaises(
            ValueError, ClientRequest, 'get', 'hiwpefhipowhefopw')

    def test_invalid_idna(self):
        self.assertRaises(
            ValueError, ClientRequest, 'get', 'http://\u2061owhefopw.com')

    def test_no_path(self):
        req = ClientRequest('get', 'http://python.org')
        self.assertEqual('/', req.path)

    def test_basic_auth(self):
        req = ClientRequest('get', 'http://python.org',
                            auth=aiohttp.helpers.BasicAuth('nkim', '1234'))
        self.assertIn('AUTHORIZATION', req.headers)
        self.assertEqual('Basic bmtpbToxMjM0', req.headers['AUTHORIZATION'])

    def test_basic_auth_utf8(self):
        req = ClientRequest('get', 'http://python.org',
                            auth=aiohttp.helpers.BasicAuth('nkim', 'секрет',
                                                           'utf-8'))
        self.assertIn('AUTHORIZATION', req.headers)
        self.assertEqual('Basic bmtpbTrRgdC10LrRgNC10YI=',
                         req.headers['AUTHORIZATION'])

    def test_basic_auth_tuple_deprecated(self):
        with self.assertWarns(DeprecationWarning):
            req = ClientRequest('get', 'http://python.org',
                                auth=('nkim', '1234'))
        self.assertIn('AUTHORIZATION', req.headers)
        self.assertEqual('Basic bmtpbToxMjM0', req.headers['AUTHORIZATION'])

    def test_basic_auth_from_url(self):
        req = ClientRequest('get', 'http://nkim:1234@python.org')
        self.assertIn('AUTHORIZATION', req.headers)
        self.assertEqual('Basic bmtpbToxMjM0', req.headers['AUTHORIZATION'])

        req = ClientRequest(
            'get', 'http://nkim@python.org',
            auth=aiohttp.helpers.BasicAuth('nkim', '1234'))
        self.assertIn('AUTHORIZATION', req.headers)
        self.assertEqual('Basic bmtpbToxMjM0', req.headers['AUTHORIZATION'])

    def test_no_content_length(self):
        req = ClientRequest('get', 'http://python.org', loop=self.loop)
        req.send(self.transport, self.protocol)
        self.assertEqual('0', req.headers.get('CONTENT-LENGTH'))

        req = ClientRequest('head', 'http://python.org', loop=self.loop)
        req.send(self.transport, self.protocol)
        self.assertEqual('0', req.headers.get('CONTENT-LENGTH'))

    def test_path_is_not_double_encoded(self):
        req = ClientRequest('get', "http://0.0.0.0/get/test case")
        self.assertEqual(req.path, "/get/test%20case")

        req = ClientRequest('get', "http://0.0.0.0/get/test%2fcase")
        self.assertEqual(req.path, "/get/test%2fcase")

        req = ClientRequest('get', "http://0.0.0.0/get/test%20case")
        self.assertEqual(req.path, "/get/test%20case")

    def test_params_are_added_before_fragment(self):
        req = ClientRequest(
            'GET', "http://example.com/path#fragment", params={"a": "b"})
        self.assertEqual(
            req.path, "/path?a=b#fragment")

        req = ClientRequest(
            'GET',
            "http://example.com/path?key=value#fragment", params={"a": "b"})
        self.assertEqual(
            req.path, "/path?key=value&a=b#fragment")

    def test_cookies(self):
        req = ClientRequest(
            'get', 'http://test.com/path', cookies={'cookie1': 'val1'})
        self.assertIn('COOKIE', req.headers)
        self.assertEqual('cookie1=val1', req.headers['COOKIE'])

        req = ClientRequest(
            'get', 'http://test.com/path',
            headers={'cookie': 'cookie1=val1'},
            cookies={'cookie2': 'val2'})
        self.assertEqual('cookie1=val1; cookie2=val2', req.headers['COOKIE'])

    def test_unicode_get(self):
        def join(*suffix):
            return urllib.parse.urljoin('http://python.org/', '/'.join(suffix))

        url = 'http://python.org'
        req = ClientRequest('get', url, params={'foo': 'f\xf8\xf8'})
        self.assertEqual('/?foo=f%C3%B8%C3%B8', req.path)
        req = ClientRequest('', url, params={'f\xf8\xf8': 'f\xf8\xf8'})
        self.assertEqual('/?f%C3%B8%C3%B8=f%C3%B8%C3%B8', req.path)
        req = ClientRequest('', url, params={'foo': 'foo'})
        self.assertEqual('/?foo=foo', req.path)
        req = ClientRequest('', join('\xf8'), params={'foo': 'foo'})
        self.assertEqual('/%C3%B8?foo=foo', req.path)

    def test_query_multivalued_param(self):
        for meth in ClientRequest.ALL_METHODS:
            req = ClientRequest(
                meth, 'http://python.org',
                params=(('test', 'foo'), ('test', 'baz')))
            self.assertEqual(req.path, '/?test=foo&test=baz')

    def test_post_data(self):
        for meth in ClientRequest.POST_METHODS:
            req = ClientRequest(
                meth, 'http://python.org/',
                data={'life': '42'}, loop=self.loop)
            req.send(self.transport, self.protocol)
            self.assertEqual('/', req.path)
            self.assertEqual(b'life=42', req.body)
            self.assertEqual('application/x-www-form-urlencoded',
                             req.headers['CONTENT-TYPE'])

    @unittest.mock.patch('aiohttp.client.ClientRequest.update_body_from_data')
    def test_pass_falsy_data(self, _):
        req = ClientRequest(
            'post', 'http://python.org/',
            data={}, loop=self.loop)
        req.update_body_from_data.assert_called_once_with({})

    def test_get_with_data(self):
        for meth in ClientRequest.GET_METHODS:
            req = ClientRequest(
                meth, 'http://python.org/', data={'life': '42'})
            self.assertEqual('/', req.path)
            self.assertEqual(b'life=42', req.body)

    def test_bytes_data(self):
        for meth in ClientRequest.POST_METHODS:
            req = ClientRequest(
                meth, 'http://python.org/',
                data=b'binary data', loop=self.loop)
            req.send(self.transport, self.protocol)
            self.assertEqual('/', req.path)
            self.assertEqual(b'binary data', req.body)
            self.assertEqual('application/octet-stream',
                             req.headers['CONTENT-TYPE'])

    def test_files_and_bytes_data(self):
        with self.assertRaises(ValueError):
            with self.assertWarns(DeprecationWarning):
                ClientRequest(
                    'POST', 'http://python.org/',
                    data=b'binary data', files={'file': b'file data'})

    @unittest.mock.patch('aiohttp.client.aiohttp')
    def test_content_encoding(self, m_http):
        req = ClientRequest('get', 'http://python.org/',
                            compress='deflate', loop=self.loop)
        req.send(self.transport, self.protocol)
        self.assertEqual(req.headers['TRANSFER-ENCODING'], 'chunked')
        self.assertEqual(req.headers['CONTENT-ENCODING'], 'deflate')
        m_http.Request.return_value\
            .add_compression_filter.assert_called_with('deflate')

    @unittest.mock.patch('aiohttp.client.aiohttp')
    def test_content_encoding_header(self, m_http):
        req = ClientRequest(
            'get', 'http://python.org/',
            headers={'Content-Encoding': 'deflate'}, loop=self.loop)
        req.send(self.transport, self.protocol)
        self.assertEqual(req.headers['TRANSFER-ENCODING'], 'chunked')
        self.assertEqual(req.headers['CONTENT-ENCODING'], 'deflate')

        m_http.Request.return_value\
            .add_compression_filter.assert_called_with('deflate')
        m_http.Request.return_value\
            .add_chunking_filter.assert_called_with(8192)

    def test_chunked(self):
        req = ClientRequest(
            'get', 'http://python.org/',
            headers={'TRANSFER-ENCODING': 'gzip'}, loop=self.loop)
        req.send(self.transport, self.protocol)
        self.assertEqual('gzip', req.headers['TRANSFER-ENCODING'])

        req = ClientRequest(
            'get', 'http://python.org/',
            headers={'Transfer-encoding': 'chunked'}, loop=self.loop)
        req.send(self.transport, self.protocol)
        self.assertEqual('chunked', req.headers['TRANSFER-ENCODING'])

    @unittest.mock.patch('aiohttp.client.aiohttp')
    def test_chunked_explicit(self, m_http):
        req = ClientRequest(
            'get', 'http://python.org/', chunked=True, loop=self.loop)
        req.send(self.transport, self.protocol)

        self.assertEqual('chunked', req.headers['TRANSFER-ENCODING'])
        m_http.Request.return_value\
                      .add_chunking_filter.assert_called_with(8192)

    @unittest.mock.patch('aiohttp.client.aiohttp')
    def test_chunked_explicit_size(self, m_http):
        req = ClientRequest(
            'get', 'http://python.org/', chunked=1024, loop=self.loop)
        req.send(self.transport, self.protocol)
        self.assertEqual('chunked', req.headers['TRANSFER-ENCODING'])
        m_http.Request.return_value\
                      .add_chunking_filter.assert_called_with(1024)

    def test_chunked_length(self):
        req = ClientRequest(
            'get', 'http://python.org/',
            headers={'CONTENT-LENGTH': '1000'}, chunked=1024, loop=self.loop)
        req.send(self.transport, self.protocol)
        self.assertEqual(req.headers['TRANSFER-ENCODING'], 'chunked')
        self.assertNotIn('CONTENT-LENGTH', req.headers)

    def test_expect100(self):
        req = ClientRequest('get', 'http://python.org/',
                            expect100=True, loop=self.loop)
        req.send(self.transport, self.protocol)
        self.assertEqual('100-continue', req.headers['EXPECT'])
        self.assertIsNotNone(req._continue)

        req = ClientRequest('get', 'http://python.org/',
                            headers={'expect': '100-continue'}, loop=self.loop)
        req.send(self.transport, self.protocol)
        self.assertEqual('100-continue', req.headers['EXPECT'])
        self.assertIsNotNone(req._continue)

    def test_data_stream(self):
        def gen():
            yield b'binary data'
            return b' result'

        req = ClientRequest(
            'POST', 'http://python.org/', data=gen(), loop=self.loop)
        self.assertTrue(req.chunked)
        self.assertTrue(inspect.isgenerator(req.body))
        self.assertEqual(req.headers['TRANSFER-ENCODING'], 'chunked')

        resp = req.send(self.transport, self.protocol)
        self.assertIsInstance(req._writer, asyncio.Future)
        self.loop.run_until_complete(resp.wait_for_close())
        self.assertIsNone(req._writer)
        self.assertEqual(
            self.transport.write.mock_calls[-3:],
            [unittest.mock.call(b'binary data result'),
             unittest.mock.call(b'\r\n'),
             unittest.mock.call(b'0\r\n\r\n')])

    def test_data_file(self):
        req = ClientRequest(
            'POST', 'http://python.org/', data=io.BytesIO(b'*' * 2),
            loop=self.loop)
        self.assertTrue(req.chunked)
        self.assertTrue(isinstance(req.body, io.IOBase))
        self.assertEqual(req.headers['TRANSFER-ENCODING'], 'chunked')

        resp = req.send(self.transport, self.protocol)
        self.assertIsInstance(req._writer, asyncio.Future)
        self.loop.run_until_complete(resp.wait_for_close())
        self.assertIsNone(req._writer)
        self.assertEqual(
            self.transport.write.mock_calls[-3:],
            [unittest.mock.call(b'*' * 2),
             unittest.mock.call(b'\r\n'),
             unittest.mock.call(b'0\r\n\r\n')])

    def test_data_stream_exc(self):
        fut = asyncio.Future(loop=self.loop)

        def gen():
            yield b'binary data'
            yield from fut

        req = ClientRequest(
            'POST', 'http://python.org/', data=gen(), loop=self.loop)
        self.assertTrue(req.chunked)
        self.assertTrue(inspect.isgenerator(req.body))
        self.assertEqual(req.headers['TRANSFER-ENCODING'], 'chunked')

        @asyncio.coroutine
        def exc():
            yield from asyncio.sleep(0.01, loop=self.loop)
            fut.set_exception(ValueError)

        asyncio.async(exc(), loop=self.loop)

        resp = req.send(self.transport, self.protocol)
        resp.connection = self.connection
        self.loop.run_until_complete(req._writer)
        self.assertTrue(self.connection.close.called)
        self.assertTrue(self.protocol.set_exception.called)

    def test_data_stream_not_bytes(self):
        @asyncio.coroutine
        def gen():
            yield object()

        req = ClientRequest(
            'POST', 'http://python.org/', data=gen(), loop=self.loop)
        req.send(self.transport, self.protocol)
        self.loop.run_until_complete(req._writer)
        self.assertTrue(self.protocol.set_exception.called)

    def test_data_stream_exc_chain(self):
        fut = asyncio.Future(loop=self.loop)

        def gen():
            yield from fut

        req = ClientRequest(
            'POST', 'http://python.org/', data=gen(), loop=self.loop)

        inner_exc = ValueError()

        @asyncio.coroutine
        def exc():
            yield from asyncio.sleep(0.01, loop=self.loop)
            fut.set_exception(inner_exc)

        asyncio.async(exc(), loop=self.loop)

        resp = req.send(self.transport, self.protocol)
        resp.connection = self.connection
        self.loop.run_until_complete(req._writer)
        self.assertTrue(self.connection.close.called)
        self.assertTrue(self.protocol.set_exception.called)
        outer_exc = self.protocol.set_exception.call_args[0][0]
        self.assertIsInstance(outer_exc, aiohttp.ClientRequestError)
        self.assertIs(inner_exc, outer_exc.__context__)
        self.assertIs(inner_exc, outer_exc.__cause__)

    def test_data_stream_continue(self):
        def gen():
            yield b'binary data'
            return b' result'

        req = ClientRequest(
            'POST', 'http://python.org/', data=gen(),
            expect100=True, loop=self.loop)
        self.assertTrue(req.chunked)
        self.assertTrue(inspect.isgenerator(req.body))

        def coro():
            yield from asyncio.sleep(0.0001, loop=self.loop)
            req._continue.set_result(1)

        asyncio.async(coro(), loop=self.loop)

        req.send(self.transport, self.protocol)
        self.loop.run_until_complete(req._writer)
        self.assertEqual(
            self.transport.write.mock_calls[-3:],
            [unittest.mock.call(b'binary data result'),
             unittest.mock.call(b'\r\n'),
             unittest.mock.call(b'0\r\n\r\n')])

    def test_data_continue(self):
        req = ClientRequest(
            'POST', 'http://python.org/', data=b'data',
            expect100=True, loop=self.loop)

        def coro():
            yield from asyncio.sleep(0.0001, loop=self.loop)
            req._continue.set_result(1)

        asyncio.async(coro(), loop=self.loop)

        req.send(self.transport, self.protocol)
        self.assertEqual(1, len(self.transport.write.mock_calls))

        self.loop.run_until_complete(req._writer)
        self.assertEqual(
            self.transport.write.mock_calls[-1],
            unittest.mock.call(b'data'))

    def test_close(self):
        @asyncio.coroutine
        def gen():
            yield from asyncio.sleep(0.00001, loop=self.loop)
            return b'result'

        req = ClientRequest(
            'POST', 'http://python.org/', data=gen(), loop=self.loop)
        req.send(self.transport, self.protocol)
        self.loop.run_until_complete(req.close())
        self.assertEqual(
            self.transport.write.mock_calls[-3:],
            [unittest.mock.call(b'result'),
             unittest.mock.call(b'\r\n'),
             unittest.mock.call(b'0\r\n\r\n')])

    def test_custom_response_class(self):
        class CustomResponse(ClientResponse):
            def read(self, decode=False):
                return 'customized!'

        req = ClientRequest(
            'GET', 'http://python.org/', response_class=CustomResponse,
            loop=self.loop)
        resp = req.send(self.transport, self.protocol)
        self.assertEqual('customized!', resp.read())
