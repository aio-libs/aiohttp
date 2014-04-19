# -*- coding: utf-8 -*-
"""Tests for aiohttp/client.py"""

import asyncio
import inspect
import time
import unittest
import unittest.mock
import urllib.parse

import aiohttp
from aiohttp.client import HttpRequest, HttpResponse, HttpClient


class HttpResponseTests(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

        self.connection = unittest.mock.Mock()
        self.stream = aiohttp.StreamParser(loop=self.loop)
        self.response = HttpResponse('get', 'http://python.org')

    def tearDown(self):
        self.loop.close()

    def test_del(self):
        response = HttpResponse('get', 'http://python.org')

        response._connection = unittest.mock.Mock()
        close = response.close = unittest.mock.Mock()
        del response
        self.assertTrue(close.called)

    def test_close(self):
        self.response._connection = self.connection
        self.response.close()
        self.assertIsNone(self.response._connection)
        self.assertTrue(self.connection.release.called)
        self.response.close()
        self.response.close()

    def test_wait_for_100(self):
        response = HttpResponse(
            'get', 'http://python.org', continue100=object())
        self.assertTrue(response.waiting_for_continue())
        response = HttpResponse(
            'get', 'http://python.org')
        self.assertFalse(response.waiting_for_continue())

    def test_repr(self):
        self.response.status = 200
        self.response.reason = 'Ok'
        self.assertIn(
            '<HttpResponse(http://python.org) [200 Ok]>', repr(self.response))

    def test_read_and_close(self):
        self.response.read = unittest.mock.Mock()
        self.response.read.return_value = asyncio.Future(loop=self.loop)
        self.response.read.return_value.set_result(b'payload')
        self.response.close = unittest.mock.Mock()

        res = self.loop.run_until_complete(self.response.read_and_close())
        self.assertEqual(res, b'payload')
        self.assertTrue(self.response.read.called)
        self.assertTrue(self.response.close.called)


class HttpRequestTests(unittest.TestCase):

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
        req = HttpRequest('get', 'http://python.org/')
        self.assertEqual(req.method, 'GET')

        req = HttpRequest('head', 'http://python.org/')
        self.assertEqual(req.method, 'HEAD')

        req = HttpRequest('HEAD', 'http://python.org/')
        self.assertEqual(req.method, 'HEAD')

    def test_version(self):
        req = HttpRequest('get', 'http://python.org/', version='1.0')
        self.assertEqual(req.version, (1, 0))

    def test_version_err(self):
        self.assertRaises(
            ValueError,
            HttpRequest, 'get', 'http://python.org/', version='1.c')

    def test_host_port(self):
        req = HttpRequest('get', 'http://python.org/')
        self.assertEqual(req.host, 'python.org')
        self.assertEqual(req.port, 80)
        self.assertFalse(req.ssl)

        req = HttpRequest('get', 'https://python.org/')
        self.assertEqual(req.host, 'python.org')
        self.assertEqual(req.port, 443)
        self.assertTrue(req.ssl)

        req = HttpRequest('get', 'https://python.org:960/')
        self.assertEqual(req.host, 'python.org')
        self.assertEqual(req.port, 960)
        self.assertTrue(req.ssl)

    def test_host_port_err(self):
        self.assertRaises(
            ValueError, HttpRequest, 'get', 'http://python.org:123e/')

    def test_host_header(self):
        req = HttpRequest('get', 'http://python.org/')
        self.assertEqual(req.headers['host'], 'python.org')

        req = HttpRequest('get', 'http://python.org/',
                          headers={'host': 'example.com'})
        self.assertEqual(req.headers['host'], 'example.com')

    def test_headers(self):
        req = HttpRequest('get', 'http://python.org/',
                          headers={'Content-Type': 'text/plain'})
        self.assertIn('Content-Type', req.headers)
        self.assertEqual(req.headers['Content-Type'], 'text/plain')
        self.assertEqual(req.headers['Accept-Encoding'], 'gzip, deflate')

    def test_headers_list(self):
        req = HttpRequest('get', 'http://python.org/',
                          headers=[('Content-Type', 'text/plain')])
        self.assertIn('Content-Type', req.headers)
        self.assertEqual(req.headers['Content-Type'], 'text/plain')

    def test_headers_default(self):
        req = HttpRequest('get', 'http://python.org/',
                          headers={'Accept-Encoding': 'deflate'})
        self.assertEqual(req.headers['Accept-Encoding'], 'deflate')

    def test_invalid_url(self):
        self.assertRaises(ValueError, HttpRequest, 'get', 'hiwpefhipowhefopw')

    def test_invalid_idna(self):
        self.assertRaises(
            ValueError, HttpRequest, 'get', 'http://\u2061owhefopw.com')

    def test_no_path(self):
        req = HttpRequest('get', 'http://python.org')
        self.assertEqual('/', req.path)

    def test_basic_auth(self):
        req = HttpRequest('get', 'http://python.org', auth=('nkim', '1234'))
        self.assertIn('Authorization', req.headers)
        self.assertEqual('Basic bmtpbToxMjM0', req.headers['Authorization'])

    def test_basic_auth_from_url(self):
        req = HttpRequest('get', 'http://nkim:1234@python.org')
        self.assertIn('Authorization', req.headers)
        self.assertEqual('Basic bmtpbToxMjM0', req.headers['Authorization'])

        req = HttpRequest('get', 'http://nkim@python.org')
        self.assertIn('Authorization', req.headers)
        self.assertEqual('Basic bmtpbTo=', req.headers['Authorization'])

        req = HttpRequest(
            'get', 'http://nkim@python.org', auth=('nkim', '1234'))
        self.assertIn('Authorization', req.headers)
        self.assertEqual('Basic bmtpbToxMjM0', req.headers['Authorization'])

    def test_basic_auth_err(self):
        self.assertRaises(
            ValueError, HttpRequest,
            'get', 'http://python.org', auth=(1, 2, 3))

    def test_no_content_length(self):
        req = HttpRequest('get', 'http://python.org', loop=self.loop)
        req.send(self.transport, self.protocol)
        self.assertEqual('0', req.headers.get('Content-Length'))

        req = HttpRequest('head', 'http://python.org', loop=self.loop)
        req.send(self.transport, self.protocol)
        self.assertEqual('0', req.headers.get('Content-Length'))

    def test_path_is_not_double_encoded(self):
        req = HttpRequest('get', "http://0.0.0.0/get/test case")
        self.assertEqual(req.path, "/get/test%20case")

        req = HttpRequest('get', "http://0.0.0.0/get/test%20case")
        self.assertEqual(req.path, "/get/test%20case")

        req = HttpRequest('get', "http://0.0.0.0/get/test%2fcase")
        self.assertEqual(req.path, "/get/test%2fcase")

    def test_params_are_added_before_fragment(self):
        req = HttpRequest(
            'GET', "http://example.com/path#fragment", params={"a": "b"})
        self.assertEqual(
            req.path, "/path?a=b#fragment")

        req = HttpRequest(
            'GET',
            "http://example.com/path?key=value#fragment", params={"a": "b"})
        self.assertEqual(
            req.path, "/path?key=value&a=b#fragment")

    def test_cookies(self):
        req = HttpRequest(
            'get', 'http://test.com/path', cookies={'cookie1': 'val1'})
        self.assertIn('Cookie', req.headers)
        self.assertEqual('cookie1=val1', req.headers['cookie'])

        req = HttpRequest(
            'get', 'http://test.com/path',
            headers={'cookie': 'cookie1=val1'},
            cookies={'cookie2': 'val2'})
        self.assertEqual('cookie1=val1; cookie2=val2', req.headers['cookie'])

    def test_unicode_get(self):
        def join(*suffix):
            return urllib.parse.urljoin('http://python.org/', '/'.join(suffix))

        url = 'http://python.org'
        req = HttpRequest('get', url, params={'foo': 'f\xf8\xf8'})
        self.assertEqual('/?foo=f%C3%B8%C3%B8', req.path)
        req = HttpRequest('', url, params={'f\xf8\xf8': 'f\xf8\xf8'})
        self.assertEqual('/?f%C3%B8%C3%B8=f%C3%B8%C3%B8', req.path)
        req = HttpRequest('', url, params={'foo': 'foo'})
        self.assertEqual('/?foo=foo', req.path)
        req = HttpRequest('', join('\xf8'), params={'foo': 'foo'})
        self.assertEqual('/%C3%B8?foo=foo', req.path)

    def test_query_multivalued_param(self):
        for meth in HttpRequest.ALL_METHODS:
            req = HttpRequest(
                meth, 'http://python.org',
                params=(('test', 'foo'), ('test', 'baz')))
            self.assertEqual(req.path, '/?test=foo&test=baz')

    def test_post_data(self):
        for meth in HttpRequest.POST_METHODS:
            req = HttpRequest(
                meth, 'http://python.org/',
                data={'life': '42'}, loop=self.loop)
            req.send(self.transport, self.protocol)
            self.assertEqual('/', req.path)
            self.assertEqual(b'life=42', req.body)
            self.assertEqual('application/x-www-form-urlencoded',
                             req.headers['content-type'])

    def test_get_with_data(self):
        for meth in HttpRequest.GET_METHODS:
            req = HttpRequest(meth, 'http://python.org/', data={'life': '42'})
            self.assertEqual('/?life=42', req.path)

    def test_bytes_data(self):
        for meth in HttpRequest.POST_METHODS:
            req = HttpRequest(
                meth, 'http://python.org/',
                data=b'binary data', loop=self.loop)
            req.send(self.transport, self.protocol)
            self.assertEqual('/', req.path)
            self.assertEqual(b'binary data', req.body)
            self.assertEqual('application/octet-stream',
                             req.headers['content-type'])

    def test_files_and_bytes_data(self):
        self.assertRaises(
            NotImplementedError, HttpRequest,
            'POST', 'http://python.org/',
            data=b'binary data', files={'file': b'file data'})

    @unittest.mock.patch('aiohttp.client.aiohttp')
    def test_content_encoding(self, m_http):
        req = HttpRequest('get', 'http://python.org/',
                          compress='deflate', loop=self.loop)
        req.send(self.transport, self.protocol)
        self.assertEqual(req.headers['Transfer-encoding'], 'chunked')
        self.assertEqual(req.headers['Content-encoding'], 'deflate')
        m_http.Request.return_value\
            .add_compression_filter.assert_called_with('deflate')

    @unittest.mock.patch('aiohttp.client.aiohttp')
    def test_content_encoding_header(self, m_http):
        req = HttpRequest(
            'get', 'http://python.org/',
            headers={'Content-Encoding': 'deflate'}, loop=self.loop)
        req.send(self.transport, self.protocol)
        self.assertEqual(req.headers['Transfer-encoding'], 'chunked')
        self.assertEqual(req.headers['Content-encoding'], 'deflate')

        m_http.Request.return_value\
            .add_compression_filter.assert_called_with('deflate')
        m_http.Request.return_value\
            .add_chunking_filter.assert_called_with(8196)

    def test_chunked(self):
        req = HttpRequest(
            'get', 'http://python.org/',
            headers={'Transfer-encoding': 'gzip'}, loop=self.loop)
        req.send(self.transport, self.protocol)
        self.assertEqual('gzip', req.headers['Transfer-encoding'])

        req = HttpRequest(
            'get', 'http://python.org/',
            headers={'Transfer-encoding': 'chunked'}, loop=self.loop)
        req.send(self.transport, self.protocol)
        self.assertEqual('chunked', req.headers['Transfer-encoding'])

    @unittest.mock.patch('aiohttp.client.aiohttp')
    def test_chunked_explicit(self, m_http):
        req = HttpRequest(
            'get', 'http://python.org/', chunked=True, loop=self.loop)
        req.send(self.transport, self.protocol)

        self.assertEqual('chunked', req.headers['Transfer-encoding'])
        m_http.Request.return_value\
                      .add_chunking_filter.assert_called_with(8196)

    @unittest.mock.patch('aiohttp.client.aiohttp')
    def test_chunked_explicit_size(self, m_http):
        req = HttpRequest(
            'get', 'http://python.org/', chunked=1024, loop=self.loop)
        req.send(self.transport, self.protocol)
        self.assertEqual('chunked', req.headers['Transfer-encoding'])
        m_http.Request.return_value\
                      .add_chunking_filter.assert_called_with(1024)

    def test_chunked_length(self):
        req = HttpRequest(
            'get', 'http://python.org/',
            headers={'Content-Length': '1000'}, chunked=1024, loop=self.loop)
        req.send(self.transport, self.protocol)
        self.assertEqual(req.headers['Transfer-Encoding'], 'chunked')
        self.assertNotIn('Content-Length', req.headers)

    def test_expect100(self):
        req = HttpRequest('get', 'http://python.org/',
                          expect100=True, loop=self.loop)
        req.send(self.transport, self.protocol)
        self.assertEqual('100-continue', req.headers['expect'])
        self.assertIsNotNone(req._continue)

        req = HttpRequest('get', 'http://python.org/',
                          headers={'expect': '100-continue'}, loop=self.loop)
        req.send(self.transport, self.protocol)
        self.assertEqual('100-continue', req.headers['expect'])
        self.assertIsNotNone(req._continue)

    def test_data_stream(self):
        def gen():
            yield b'binary data'
            return b' result'

        req = HttpRequest(
            'POST', 'http://python.org/', data=gen(), loop=self.loop)
        self.assertTrue(req.chunked)
        self.assertTrue(inspect.isgenerator(req.body))
        self.assertEqual(req.headers['transfer-encoding'], 'chunked')

        resp = req.send(self.transport, self.protocol)
        self.assertIsInstance(req._writer, asyncio.Future)
        self.loop.run_until_complete(resp.wait_for_close())
        self.assertIsNone(req._writer)
        self.assertEqual(
            self.transport.write.mock_calls[-3:],
            [unittest.mock.call(b'binary data result'),
             unittest.mock.call(b'\r\n'),
             unittest.mock.call(b'0\r\n\r\n')])

    def test_data_stream_exc(self):
        fut = asyncio.Future(loop=self.loop)

        def gen():
            yield b'binary data'
            yield from fut
            return b' result'

        req = HttpRequest(
            'POST', 'http://python.org/', data=gen(), loop=self.loop)
        self.assertTrue(req.chunked)
        self.assertTrue(inspect.isgenerator(req.body))
        self.assertEqual(req.headers['transfer-encoding'], 'chunked')

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

    def test_data_stream_not_bytes(self):
        @asyncio.coroutine
        def gen():
            yield object()
            return b' result'

        req = HttpRequest(
            'POST', 'http://python.org/', data=gen(), loop=self.loop)
        req.send(self.transport, self.protocol)
        self.loop.run_until_complete(req._writer)
        self.assertTrue(self.protocol.set_exception.called)

    def test_data_stream_continue(self):
        def gen():
            yield b'binary data'
            return b' result'

        req = HttpRequest(
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
        req = HttpRequest(
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

        req = HttpRequest(
            'POST', 'http://python.org/', data=gen(), loop=self.loop)
        req.send(self.transport, self.protocol)
        self.loop.run_until_complete(req.close())
        self.assertEqual(
            self.transport.write.mock_calls[-3:],
            [unittest.mock.call(b'result'),
             unittest.mock.call(b'\r\n'),
             unittest.mock.call(b'0\r\n\r\n')])


class HttpClientTests(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    @unittest.mock.patch('aiohttp.client.asyncio')
    def test_ctor(self, asyncio):
        self.assertRaises(ValueError, HttpClient, ())
        self.assertRaises(ValueError, HttpClient, ('test:test',))

        c = HttpClient('localhost:8080', loop=self.loop)
        self.assertEqual(c._hosts, [('localhost', 8080)])

        c = HttpClient('localhost', loop=self.loop)
        self.assertEqual(c._hosts, [('localhost', 80)])

        c = HttpClient([('localhost', 1000)], loop=self.loop)
        self.assertEqual(c._hosts, [('localhost', 1000)])

        c = HttpClient([('localhost', 1000)])
        self.assertIs(c._loop, asyncio.get_event_loop.return_value)

        c = HttpClient([('localhost', 1000)], ssl=True, verify_ssl=False)
        self.assertFalse(c._connector._verify_ssl)

        c = HttpClient([('localhost', 1000)], conn_pool=False, loop=self.loop)
        self.assertIsNone(c._connector)

    def test_cleanup_resolved_hosts(self):
        loop = unittest.mock.Mock()
        c = HttpClient('localhost:8080', loop=loop, resolve=True)
        c._connector._resolved_hosts[('localhost', 123)] = object()
        loop.call_later.assert_called_with(
            c._resolve_timeout, c._cleanup_resolved_host)
        loop.reset_mock()

        c._cleanup_resolved_host()
        self.assertFalse(bool(c._connector._resolved_hosts))
        loop.call_later.assert_called_with(
            c._resolve_timeout, c._cleanup_resolved_host)

    def test_resurrect_failed(self):
        now = int(time.time())
        loop = unittest.mock.Mock()

        c = HttpClient(
            [('localhost', 1000), ('localhost', 1000)], loop=loop)
        c._hosts = []
        c._failed.append((('localhost', 1000), now - 10))
        c._failed.append((('localhost', 1001), now - 10))
        c._failed.append((('localhost', 1002), now + 10))
        c._resurrect_failed()

        self.assertEqual(
            c._hosts, [('localhost', 1000), ('localhost', 1001)])
        self.assertTrue(loop.call_later.called)

    @unittest.mock.patch('aiohttp.client.asyncio')
    def test_resurrect_failed_all(self, asyncio):
        now = int(time.time())

        c = HttpClient(
            [('localhost', 1000), ('localhost', 1000)],
            resolve=False, loop=self.loop)
        c._hosts = []
        c._failed.append((('localhost', 1000), now - 10))
        c._failed.append((('localhost', 1001), now - 10))
        c._resurrect_failed()

        self.assertEqual(
            c._hosts, [('localhost', 1000), ('localhost', 1001)])
        self.assertFalse(
            asyncio.get_event_loop.return_value.call_later.called)

    def test_failed_request(self):
        c = HttpClient(
            [('localhost', 56777), ('localhost', 56778)], loop=self.loop)

        self.assertRaises(
            aiohttp.ConnectionError,
            self.loop.run_until_complete,
            c.request('get', path='/', timeout=0.0001))

    def test_failed_request_conn(self):
        c = HttpClient(
            [('localhost', 56777), ('localhost', 56778)],
            conn_timeout=0.0001, loop=self.loop)

        self.assertRaises(
            aiohttp.ConnectionError,
            self.loop.run_until_complete, c.request('get', path='/'))

    def test_failed_request_one_failed(self):
        now = int(time.time())

        c = HttpClient(
            [('localhost', 56777), ('localhost', 56778)], loop=self.loop)
        c._hosts = []
        c._failed.append((('localhost', 1000), now - 10))
        c._failed.append((('localhost', 1001), now - 10))

        self.assertRaises(
            aiohttp.ConnectionError,
            self.loop.run_until_complete,
            c.request('get', path='/', timeout=0.0001))

    @unittest.mock.patch('aiohttp.client.request')
    def test_cleanup_resolved_hosts_on_500(self, m_request):
        c = HttpClient(
            [('localhost', 56777), ('localhost', 56778)],
            conn_timeout=0.0001, loop=self.loop)

        called = False

        class m:

            def clear(self):
                nonlocal called
                called = True

            def __contains__(self, key):
                return True

            def __getitem__(self, key):
                return 'localhost'

        c._connector._resolved_hosts = m()

        resp = unittest.mock.Mock()
        resp.status = 500

        m_request.return_value = asyncio.Future(loop=self.loop)
        m_request.return_value.set_result(resp)

        self.loop.run_until_complete(c.request('get', path='/'))
        self.assertTrue(called)
