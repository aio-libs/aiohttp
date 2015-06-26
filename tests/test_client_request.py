import asyncio
import unittest
import unittest.mock
import sys

import inspect
import io
import urllib.parse
import os.path

import aiohttp
from aiohttp.client_reqrep import ClientRequest, ClientResponse

PY_341 = sys.version_info >= (3, 4, 1)


class TestClientRequest(unittest.TestCase):

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
        req = ClientRequest('get', 'http://python.org/', loop=self.loop)
        self.assertEqual(req.method, 'GET')
        self.loop.run_until_complete(req.close())

        req = ClientRequest('head', 'http://python.org/', loop=self.loop)
        self.assertEqual(req.method, 'HEAD')
        self.loop.run_until_complete(req.close())

        req = ClientRequest('HEAD', 'http://python.org/', loop=self.loop)
        self.assertEqual(req.method, 'HEAD')
        self.loop.run_until_complete(req.close())

    def test_version(self):
        req = ClientRequest('get', 'http://python.org/', version='1.0',
                            loop=self.loop)
        self.assertEqual(req.version, (1, 0))
        self.loop.run_until_complete(req.close())

    def test_version_err(self):
        self.assertRaises(
            ValueError,
            ClientRequest, 'get', 'http://python.org/', version='1.c',
            loop=self.loop)

    def test_host_port(self):
        req = ClientRequest('get', 'http://python.org/', loop=self.loop)
        self.assertEqual(req.host, 'python.org')
        self.assertEqual(req.port, 80)
        self.assertFalse(req.ssl)
        self.loop.run_until_complete(req.close())

        req = ClientRequest('get', 'https://python.org/', loop=self.loop)
        self.assertEqual(req.host, 'python.org')
        self.assertEqual(req.port, 443)
        self.assertTrue(req.ssl)
        self.loop.run_until_complete(req.close())

        req = ClientRequest('get', 'https://python.org:960/', loop=self.loop)
        self.assertEqual(req.host, 'python.org')
        self.assertEqual(req.port, 960)
        self.assertTrue(req.ssl)
        self.loop.run_until_complete(req.close())

    def test_host_port_err(self):
        self.assertRaises(
            ValueError, ClientRequest, 'get', 'http://python.org:123e/',
            loop=self.loop)

    def test_host_header(self):
        req = ClientRequest('get', 'http://python.org/', loop=self.loop)
        self.assertEqual(req.headers['HOST'], 'python.org')
        self.loop.run_until_complete(req.close())

        req = ClientRequest('get', 'http://python.org:80/', loop=self.loop)
        self.assertEqual(req.headers['HOST'], 'python.org:80')
        self.loop.run_until_complete(req.close())

        req = ClientRequest('get', 'http://python.org:99/', loop=self.loop)
        self.assertEqual(req.headers['HOST'], 'python.org:99')
        self.loop.run_until_complete(req.close())

        req = ClientRequest('get', 'http://python.org/',
                            headers={'host': 'example.com'}, loop=self.loop)
        self.assertEqual(req.headers['HOST'], 'example.com')
        self.loop.run_until_complete(req.close())

        req = ClientRequest('get', 'http://python.org/',
                            headers={'host': 'example.com:99'}, loop=self.loop)
        self.assertEqual(req.headers['HOST'], 'example.com:99')
        self.loop.run_until_complete(req.close())

    def test_headers(self):
        req = ClientRequest('get', 'http://python.org/',
                            headers={'Content-Type': 'text/plain'},
                            loop=self.loop)
        self.assertIn('CONTENT-TYPE', req.headers)
        self.assertEqual(req.headers['CONTENT-TYPE'], 'text/plain')
        self.assertEqual(req.headers['ACCEPT-ENCODING'], 'gzip, deflate')
        self.loop.run_until_complete(req.close())

    def test_headers_list(self):
        req = ClientRequest('get', 'http://python.org/',
                            headers=[('Content-Type', 'text/plain')],
                            loop=self.loop)
        self.assertIn('CONTENT-TYPE', req.headers)
        self.assertEqual(req.headers['CONTENT-TYPE'], 'text/plain')
        self.loop.run_until_complete(req.close())

    def test_headers_default(self):
        req = ClientRequest('get', 'http://python.org/',
                            headers={'ACCEPT-ENCODING': 'deflate'},
                            loop=self.loop)
        self.assertEqual(req.headers['ACCEPT-ENCODING'], 'deflate')
        self.loop.run_until_complete(req.close())

    def test_invalid_url(self):
        self.assertRaises(
            ValueError, ClientRequest, 'get', 'hiwpefhipowhefopw',
            loop=self.loop)

    def test_invalid_idna(self):
        self.assertRaises(
            ValueError, ClientRequest, 'get', 'http://\u2061owhefopw.com',
            loop=self.loop)

    def test_ipv6_host_port(self):
        req = ClientRequest('get', 'http://[2001:db8::1]/', loop=self.loop)
        self.assertEqual(req.host, '2001:db8::1')
        self.assertEqual(req.port, 80)
        self.assertFalse(req.ssl)
        self.loop.run_until_complete(req.close())

        req = ClientRequest('get', 'https://[2001:db8::1]', loop=self.loop)
        self.assertEqual(req.host, '2001:db8::1')
        self.assertEqual(req.port, 443)
        self.assertTrue(req.ssl)
        self.loop.run_until_complete(req.close())

        req = ClientRequest('get', 'https://[2001:db8::1]:960', loop=self.loop)
        self.assertEqual(req.host, '2001:db8::1')
        self.assertEqual(req.port, 960)
        self.assertTrue(req.ssl)
        self.loop.run_until_complete(req.close())

    def test_no_path(self):
        req = ClientRequest('get', 'http://python.org', loop=self.loop)
        self.assertEqual('/', req.path)
        self.loop.run_until_complete(req.close())

    def test_basic_auth(self):
        req = ClientRequest('get', 'http://python.org',
                            auth=aiohttp.helpers.BasicAuth('nkim', '1234'),
                            loop=self.loop)
        self.assertIn('AUTHORIZATION', req.headers)
        self.assertEqual('Basic bmtpbToxMjM0', req.headers['AUTHORIZATION'])
        self.loop.run_until_complete(req.close())

    def test_basic_auth_utf8(self):
        req = ClientRequest('get', 'http://python.org',
                            auth=aiohttp.helpers.BasicAuth('nkim', 'секрет',
                                                           'utf-8'),
                            loop=self.loop)
        self.assertIn('AUTHORIZATION', req.headers)
        self.assertEqual('Basic bmtpbTrRgdC10LrRgNC10YI=',
                         req.headers['AUTHORIZATION'])
        self.loop.run_until_complete(req.close())

    def test_basic_auth_tuple_deprecated(self):
        with self.assertWarns(DeprecationWarning):
            req = ClientRequest('get', 'http://python.org',
                                auth=('nkim', '1234'),
                                loop=self.loop)
        self.assertIn('AUTHORIZATION', req.headers)
        self.assertEqual('Basic bmtpbToxMjM0', req.headers['AUTHORIZATION'])
        self.loop.run_until_complete(req.close())

    def test_basic_auth_from_url(self):
        req = ClientRequest('get', 'http://nkim:1234@python.org',
                            loop=self.loop)
        self.assertIn('AUTHORIZATION', req.headers)
        self.assertEqual('Basic bmtpbToxMjM0', req.headers['AUTHORIZATION'])
        self.assertEqual('python.org', req.netloc)
        self.loop.run_until_complete(req.close())

        req = ClientRequest(
            'get', 'http://nkim@python.org',
            auth=aiohttp.helpers.BasicAuth('nkim', '1234'),
            loop=self.loop)
        self.assertIn('AUTHORIZATION', req.headers)
        self.assertEqual('Basic bmtpbToxMjM0', req.headers['AUTHORIZATION'])
        self.assertEqual('python.org', req.netloc)
        self.loop.run_until_complete(req.close())

    def test_no_content_length(self):
        req = ClientRequest('get', 'http://python.org', loop=self.loop)
        req.send(self.transport, self.protocol)
        self.assertEqual('0', req.headers.get('CONTENT-LENGTH'))
        self.loop.run_until_complete(req.close())

        req = ClientRequest('head', 'http://python.org', loop=self.loop)
        req.send(self.transport, self.protocol)
        self.assertEqual('0', req.headers.get('CONTENT-LENGTH'))
        self.loop.run_until_complete(req.close())

    def test_path_is_not_double_encoded(self):
        req = ClientRequest('get', "http://0.0.0.0/get/test case",
                            loop=self.loop)
        self.assertEqual(req.path, "/get/test%20case")
        self.loop.run_until_complete(req.close())

        req = ClientRequest('get', "http://0.0.0.0/get/test%2fcase",
                            loop=self.loop)
        self.assertEqual(req.path, "/get/test%2fcase")
        self.loop.run_until_complete(req.close())

        req = ClientRequest('get', "http://0.0.0.0/get/test%20case",
                            loop=self.loop)
        self.assertEqual(req.path, "/get/test%20case")
        self.loop.run_until_complete(req.close())

    def test_params_are_added_before_fragment(self):
        req = ClientRequest(
            'GET', "http://example.com/path#fragment", params={"a": "b"},
            loop=self.loop)
        self.assertEqual(
            req.path, "/path?a=b#fragment")
        self.loop.run_until_complete(req.close())

        req = ClientRequest(
            'GET',
            "http://example.com/path?key=value#fragment", params={"a": "b"},
            loop=self.loop)
        self.assertEqual(
            req.path, "/path?key=value&a=b#fragment")
        self.loop.run_until_complete(req.close())

    def test_cookies(self):
        req = ClientRequest(
            'get', 'http://test.com/path', cookies={'cookie1': 'val1'},
            loop=self.loop)
        self.assertIn('COOKIE', req.headers)
        self.assertEqual('cookie1=val1', req.headers['COOKIE'])
        self.loop.run_until_complete(req.close())

        req = ClientRequest(
            'get', 'http://test.com/path',
            headers={'cookie': 'cookie1=val1'},
            cookies={'cookie2': 'val2'},
            loop=self.loop)
        self.assertEqual('cookie1=val1; cookie2=val2', req.headers['COOKIE'])
        self.loop.run_until_complete(req.close())

    def test_unicode_get(self):
        def join(*suffix):
            return urllib.parse.urljoin('http://python.org/', '/'.join(suffix))

        url = 'http://python.org'
        req = ClientRequest('get', url, params={'foo': 'f\xf8\xf8'},
                            loop=self.loop)
        self.assertEqual('/?foo=f%C3%B8%C3%B8', req.path)
        self.loop.run_until_complete(req.close())

        req = ClientRequest('', url, params={'f\xf8\xf8': 'f\xf8\xf8'},
                            loop=self.loop)
        self.assertEqual('/?f%C3%B8%C3%B8=f%C3%B8%C3%B8', req.path)
        self.loop.run_until_complete(req.close())

        req = ClientRequest('', url, params={'foo': 'foo'},
                            loop=self.loop)
        self.assertEqual('/?foo=foo', req.path)
        self.loop.run_until_complete(req.close())

        req = ClientRequest('', join('\xf8'), params={'foo': 'foo'},
                            loop=self.loop)
        self.assertEqual('/%C3%B8?foo=foo', req.path)
        self.loop.run_until_complete(req.close())

    def test_query_multivalued_param(self):
        for meth in ClientRequest.ALL_METHODS:
            req = ClientRequest(
                meth, 'http://python.org',
                params=(('test', 'foo'), ('test', 'baz')),
                loop=self.loop)
            self.assertEqual(req.path, '/?test=foo&test=baz')
            self.loop.run_until_complete(req.close())

    def test_params_update_path_and_url(self):
        req = ClientRequest(
            'get', 'http://python.org',
            params=(('test', 'foo'), ('test', 'baz')),
            loop=self.loop)
        self.assertEqual(req.path, '/?test=foo&test=baz')
        self.assertEqual(req.url, 'http://python.org/?test=foo&test=baz')
        self.loop.run_until_complete(req.close())

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
            self.loop.run_until_complete(req.close())

    @unittest.mock.patch(
        'aiohttp.client_reqrep.ClientRequest.update_body_from_data')
    def test_pass_falsy_data(self, _):
        req = ClientRequest(
            'post', 'http://python.org/',
            data={}, loop=self.loop)
        req.update_body_from_data.assert_called_once_with({})
        self.loop.run_until_complete(req.close())

    def test_get_with_data(self):
        for meth in ClientRequest.GET_METHODS:
            req = ClientRequest(
                meth, 'http://python.org/', data={'life': '42'},
                loop=self.loop)
            self.assertEqual('/', req.path)
            self.assertEqual(b'life=42', req.body)
            self.loop.run_until_complete(req.close())

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
            self.loop.run_until_complete(req.close())

    def test_files_and_bytes_data(self):
        with self.assertRaises(ValueError):
            with self.assertWarns(DeprecationWarning):
                ClientRequest(
                    'POST', 'http://python.org/',
                    data=b'binary data', files={'file': b'file data'},
                    loop=self.loop)

    @unittest.mock.patch('aiohttp.client_reqrep.aiohttp')
    def test_content_encoding(self, m_http):
        req = ClientRequest('get', 'http://python.org/',
                            compress='deflate', loop=self.loop)
        req.send(self.transport, self.protocol)
        self.assertEqual(req.headers['TRANSFER-ENCODING'], 'chunked')
        self.assertEqual(req.headers['CONTENT-ENCODING'], 'deflate')
        m_http.Request.return_value\
            .add_compression_filter.assert_called_with('deflate')
        self.loop.run_until_complete(req.close())

    @unittest.mock.patch('aiohttp.client_reqrep.aiohttp')
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
        self.loop.run_until_complete(req.close())

    def test_chunked(self):
        req = ClientRequest(
            'get', 'http://python.org/',
            headers={'TRANSFER-ENCODING': 'gzip'}, loop=self.loop)
        req.send(self.transport, self.protocol)
        self.assertEqual('gzip', req.headers['TRANSFER-ENCODING'])
        self.loop.run_until_complete(req.close())

        req = ClientRequest(
            'get', 'http://python.org/',
            headers={'Transfer-encoding': 'chunked'}, loop=self.loop)
        req.send(self.transport, self.protocol)
        self.assertEqual('chunked', req.headers['TRANSFER-ENCODING'])
        self.loop.run_until_complete(req.close())

    @unittest.mock.patch('aiohttp.client_reqrep.aiohttp')
    def test_chunked_explicit(self, m_http):
        req = ClientRequest(
            'get', 'http://python.org/', chunked=True, loop=self.loop)
        req.send(self.transport, self.protocol)

        self.assertEqual('chunked', req.headers['TRANSFER-ENCODING'])
        m_http.Request.return_value\
                      .add_chunking_filter.assert_called_with(8192)
        self.loop.run_until_complete(req.close())

    @unittest.mock.patch('aiohttp.client_reqrep.aiohttp')
    def test_chunked_explicit_size(self, m_http):
        req = ClientRequest(
            'get', 'http://python.org/', chunked=1024, loop=self.loop)
        req.send(self.transport, self.protocol)
        self.assertEqual('chunked', req.headers['TRANSFER-ENCODING'])
        m_http.Request.return_value\
                      .add_chunking_filter.assert_called_with(1024)
        self.loop.run_until_complete(req.close())

    def test_chunked_length(self):
        req = ClientRequest(
            'get', 'http://python.org/',
            headers={'CONTENT-LENGTH': '1000'}, chunked=1024, loop=self.loop)
        req.send(self.transport, self.protocol)
        self.assertEqual(req.headers['TRANSFER-ENCODING'], 'chunked')
        self.assertNotIn('CONTENT-LENGTH', req.headers)
        self.loop.run_until_complete(req.close())

    def test_file_upload_not_chunked(self):
        here = os.path.dirname(__file__)
        fname = os.path.join(here, 'sample.key')
        with open(fname, 'rb') as f:
            req = ClientRequest(
                'post', 'http://python.org/',
                data=f,
                loop=self.loop)
            self.assertFalse(req.chunked)
            self.assertEqual(req.headers['CONTENT-LENGTH'],
                             str(os.path.getsize(fname)))
            self.loop.run_until_complete(req.close())

    def test_file_upload_not_chunked_seek(self):
        here = os.path.dirname(__file__)
        fname = os.path.join(here, 'sample.key')
        with open(fname, 'rb') as f:
            f.seek(100)
            req = ClientRequest(
                'post', 'http://python.org/',
                data=f,
                loop=self.loop)
            self.assertEqual(req.headers['CONTENT-LENGTH'],
                             str(os.path.getsize(fname) - 100))
            self.loop.run_until_complete(req.close())

    def test_file_upload_force_chunked(self):
        here = os.path.dirname(__file__)
        fname = os.path.join(here, 'sample.key')
        with open(fname, 'rb') as f:
            req = ClientRequest(
                'post', 'http://python.org/',
                data=f,
                chunked=True,
                loop=self.loop)
            self.assertTrue(req.chunked)
            self.assertNotIn('CONTENT-LENGTH', req.headers)
            self.loop.run_until_complete(req.close())

    def test_expect100(self):
        req = ClientRequest('get', 'http://python.org/',
                            expect100=True, loop=self.loop)
        resp = req.send(self.transport, self.protocol)
        self.assertEqual('100-continue', req.headers['EXPECT'])
        self.assertIsNotNone(req._continue)
        req.terminate()
        resp.close()

    def test_expect_100_continue_header(self):
        req = ClientRequest('get', 'http://python.org/',
                            headers={'expect': '100-continue'}, loop=self.loop)
        resp = req.send(self.transport, self.protocol)
        self.assertEqual('100-continue', req.headers['EXPECT'])
        self.assertIsNotNone(req._continue)
        req.terminate()
        resp.close()

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
        self.loop.run_until_complete(req.close())

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
        self.loop.run_until_complete(req.close())

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
        resp._connection = self.connection
        self.loop.run_until_complete(req._writer)
        self.assertTrue(self.connection.close.called)
        self.assertTrue(self.protocol.set_exception.called)
        self.loop.run_until_complete(req.close())

    def test_data_stream_not_bytes(self):
        @asyncio.coroutine
        def gen():
            yield object()

        req = ClientRequest(
            'POST', 'http://python.org/', data=gen(), loop=self.loop)
        req.send(self.transport, self.protocol)
        self.loop.run_until_complete(req._writer)
        self.assertTrue(self.protocol.set_exception.called)
        self.loop.run_until_complete(req.close())

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
        resp._connection = self.connection
        self.loop.run_until_complete(req._writer)
        self.assertTrue(self.connection.close.called)
        self.assertTrue(self.protocol.set_exception.called)
        outer_exc = self.protocol.set_exception.call_args[0][0]
        self.assertIsInstance(outer_exc, aiohttp.ClientRequestError)
        self.assertIs(inner_exc, outer_exc.__context__)
        self.assertIs(inner_exc, outer_exc.__cause__)
        self.loop.run_until_complete(req.close())

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
        self.loop.run_until_complete(req.close())

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
        self.loop.run_until_complete(req.close())

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
        self.loop.run_until_complete(req.close())

    def test_custom_response_class(self):
        class CustomResponse(ClientResponse):
            def read(self, decode=False):
                return 'customized!'

        req = ClientRequest(
            'GET', 'http://python.org/', response_class=CustomResponse,
            loop=self.loop)
        resp = req.send(self.transport, self.protocol)
        self.assertEqual('customized!', resp.read())
        self.loop.run_until_complete(req.close())

    def test_terminate(self):
        req = ClientRequest('get', 'http://python.org', loop=self.loop)
        req.send(self.transport, self.protocol)
        self.assertIsNotNone(req._writer)
        writer = req._writer = unittest.mock.Mock()

        req.terminate()
        self.assertIsNone(req._writer)
        writer.cancel.assert_called_with()

    def test_terminate_with_closed_loop(self):
        if not hasattr(self.loop, 'is_closed'):
            self.skipTest("Required asyncio 3.4.2+")
        req = ClientRequest('get', 'http://python.org', loop=self.loop)
        req.send(self.transport, self.protocol)
        self.assertIsNotNone(req._writer)
        writer = req._writer = unittest.mock.Mock()

        self.loop.close()
        req.terminate()
        self.assertIsNone(req._writer)
        self.assertFalse(writer.cancel.called)

    def test_terminate_without_writer(self):
        req = ClientRequest('get', 'http://python.org', loop=self.loop)
        self.assertIsNone(req._writer)

        req.terminate()
        self.assertIsNone(req._writer)

    def test_default_loop(self):
        asyncio.set_event_loop(self.loop)
        self.addCleanup(asyncio.set_event_loop, None)
        req = ClientRequest('get', 'http://python.org/')
        self.assertIs(req.loop, self.loop)
