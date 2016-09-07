# coding: utf-8

import asyncio
import gc
import inspect
import io
import os.path
import re
import unittest
import urllib.parse
import zlib
from http.cookies import SimpleCookie
from unittest import mock

import pytest
from multidict import CIMultiDict, CIMultiDictProxy, upstr

import aiohttp
from aiohttp import BaseConnector, helpers
from aiohttp.client_reqrep import ClientRequest, ClientResponse


@pytest.yield_fixture
def make_request(loop):
    request = None

    def maker(*args, **kwargs):
        nonlocal request
        request = ClientRequest(*args, loop=loop, **kwargs)
        return request

    yield maker
    if request is not None:
        loop.run_until_complete(request.close())


def test_method1(make_request):
    req = make_request('get', 'http://python.org/')
    assert req.method == 'GET'


def test_method2(make_request):
    req = make_request('head', 'http://python.org/')
    assert req.method == 'HEAD'


def test_method3(make_request):
    req = make_request('HEAD', 'http://python.org/')
    assert req.method == 'HEAD'


def test_version_1_0(make_request):
    req = make_request('get', 'http://python.org/', version='1.0')
    assert req.version == (1, 0)


def test_version_default(make_request):
    req = make_request('get', 'http://python.org/')
    assert req.version == (1, 1)


def test_version_err(make_request):
    with pytest.raises(ValueError):
        make_request('get', 'http://python.org/', version='1.c')


def test_host_port_default_http(make_request):
    req = make_request('get', 'http://python.org/')
    assert req.host == 'python.org'
    assert req.port == 80
    assert not req.ssl


def test_host_port_default_https(make_request):
    req = make_request('get', 'https://python.org/')
    assert req.host == 'python.org'
    assert req.port == 443
    assert req.ssl


def test_host_port_nondefault_http(make_request):
    req = make_request('get', 'http://python.org:960/')
    assert req.host == 'python.org'
    assert req.port == 960
    assert not req.ssl


def test_host_port_nondefault_https(make_request):
    req = make_request('get', 'https://python.org:960/')
    assert req.host == 'python.org'
    assert req.port == 960
    assert req.ssl


def test_host_port_default_ws(make_request):
    req = make_request('get', 'ws://python.org/')
    assert req.host == 'python.org'
    assert req.port == 80
    assert not req.ssl


def test_host_port_default_wss(make_request):
    req = make_request('get', 'wss://python.org/')
    assert req.host == 'python.org'
    assert req.port == 443
    assert req.ssl


def test_host_port_nondefault_ws(make_request):
    req = make_request('get', 'ws://python.org:960/')
    assert req.host == 'python.org'
    assert req.port == 960
    assert not req.ssl


def test_host_port_nondefault_wss(make_request):
    req = make_request('get', 'wss://python.org:960/')
    assert req.host == 'python.org'
    assert req.port == 960
    assert req.ssl


def test_host_port_err(make_request):
    with pytest.raises(ValueError):
        make_request('get', 'http://python.org:123e/')


def test_hostname_err(make_request):
    with pytest.raises(ValueError):
        make_request('get', 'http://:8080/')


def test_host_header_host_without_port(make_request):
    req = make_request('get', 'http://python.org/')
    assert req.headers['HOST'] == 'python.org'


def test_host_header_host_with_default_port(make_request):
    req = make_request('get', 'http://python.org:80/')
    assert req.headers['HOST'] == 'python.org:80'


def test_host_header_host_with_nondefault_port(make_request):
    req = make_request('get', 'http://python.org:99/')
    assert req.headers['HOST'] == 'python.org:99'


def test_host_header_explicit_host(make_request):
    req = make_request('get', 'http://python.org/',
                       headers={'host': 'example.com'})
    assert req.headers['HOST'] == 'example.com'


def test_host_header_explicit_host_with_port(make_request):
    req = make_request('get', 'http://python.org/',
                       headers={'host': 'example.com:99'})
    assert req.headers['HOST'] == 'example.com:99'


def test_default_loop(loop):
    asyncio.set_event_loop(loop)
    req = ClientRequest('get', 'http://python.org/')
    assert req.loop is loop


def test_default_headers_useragent(make_request):
    req = make_request('get', 'http://python.org/')

    assert 'SERVER' not in req.headers
    assert 'USER-AGENT' in req.headers


def test_default_headers_useragent_custom(make_request):
    req = make_request('get', 'http://python.org/',
                       headers={'user-agent': 'my custom agent'})

    assert 'USER-Agent' in req.headers
    assert 'my custom agent' == req.headers['User-Agent']


def test_skip_default_useragent_header(make_request):
    req = make_request('get', 'http://python.org/',
                       skip_auto_headers=set([upstr('user-agent')]))

    assert 'User-Agent' not in req.headers


def test_headers(make_request):
    req = make_request('get', 'http://python.org/',
                       headers={'Content-Type': 'text/plain'})

    assert 'CONTENT-TYPE' in req.headers
    assert req.headers['CONTENT-TYPE'] == 'text/plain'
    assert req.headers['ACCEPT-ENCODING'] == 'gzip, deflate'


def test_headers_list(make_request):
    req = make_request('get', 'http://python.org/',
                       headers=[('Content-Type', 'text/plain')])
    assert 'CONTENT-TYPE' in req.headers
    assert req.headers['CONTENT-TYPE'] == 'text/plain'


def test_headers_default(make_request):
    req = make_request('get', 'http://python.org/',
                       headers={'ACCEPT-ENCODING': 'deflate'})
    assert req.headers['ACCEPT-ENCODING'] == 'deflate'


def test_invalid_url(make_request):
    with pytest.raises(ValueError):
        make_request('get', 'hiwpefhipowhefopw')


def test_invalid_idna(make_request):
    with pytest.raises(ValueError):
        make_request('get', 'http://\u2061owhefopw.com')


def test_no_path(make_request):
    req = make_request('get', 'http://python.org')
    assert '/' == req.path


def test_ipv6_default_http_port(make_request):
    req = make_request('get', 'http://[2001:db8::1]/')
    assert req.host == '2001:db8::1'
    assert req.port == 80
    assert not req.ssl


def test_ipv6_default_https_port(make_request):
    req = make_request('get', 'https://[2001:db8::1]/')
    assert req.host == '2001:db8::1'
    assert req.port == 443
    assert req.ssl


def test_ipv6_nondefault_http_port(make_request):
    req = make_request('get', 'http://[2001:db8::1]:960/')
    assert req.host == '2001:db8::1'
    assert req.port == 960
    assert not req.ssl


def test_ipv6_nondefault_https_port(make_request):
    req = make_request('get', 'https://[2001:db8::1]:960/')
    assert req.host == '2001:db8::1'
    assert req.port == 960
    assert req.ssl


def test_basic_auth(make_request):
    req = make_request('get', 'http://python.org',
                       auth=aiohttp.helpers.BasicAuth('nkim', '1234'))
    assert 'AUTHORIZATION' in req.headers
    assert 'Basic bmtpbToxMjM0' == req.headers['AUTHORIZATION']


def test_basic_auth_utf8(make_request):
    req = make_request('get', 'http://python.org',
                       auth=aiohttp.helpers.BasicAuth('nkim', 'секрет',
                                                      'utf-8'))
    assert 'AUTHORIZATION' in req.headers
    assert 'Basic bmtpbTrRgdC10LrRgNC10YI=' == req.headers['AUTHORIZATION']


def test_basic_auth_tuple_forbidden(make_request):
    with pytest.raises(TypeError):
        make_request('get', 'http://python.org',
                     auth=('nkim', '1234'))


def test_basic_auth_from_url(make_request):
    req = make_request('get', 'http://nkim:1234@python.org')
    assert 'AUTHORIZATION' in req.headers
    assert 'Basic bmtpbToxMjM0' == req.headers['AUTHORIZATION']
    assert 'python.org' == req.netloc


def test_basic_auth_from_url_overriden(make_request):
    req = make_request('get', 'http://garbage@python.org',
                       auth=aiohttp.BasicAuth('nkim', '1234'))
    assert 'AUTHORIZATION' in req.headers
    assert 'Basic bmtpbToxMjM0' == req.headers['AUTHORIZATION']
    assert 'python.org' == req.netloc


def test_path_is_not_double_encoded1(make_request):
    req = make_request('get', "http://0.0.0.0/get/test case")
    assert req.path == "/get/test%20case"


def test_path_is_not_double_encoded2(make_request):
    req = make_request('get', "http://0.0.0.0/get/test%2fcase")
    assert req.path == "/get/test%2fcase"


def test_path_is_not_double_encoded3(make_request):
    req = make_request('get', "http://0.0.0.0/get/test%20case")
    assert req.path == "/get/test%20case"


def test_path_safe_chars_preserved(make_request):
    req = make_request('get', "http://0.0.0.0/get/%:=")
    assert req.path == "/get/%:="


def test_params_are_added_before_fragment1(make_request):
    req = make_request('GET', "http://example.com/path#fragment",
                       params={"a": "b"})
    assert req.url == "http://example.com/path?a=b#fragment"


def test_params_are_added_before_fragment2(make_request):
    req = make_request('GET', "http://example.com/path?key=value#fragment",
                       params={"a": "b"})
    assert req.url == "http://example.com/path?key=value&a=b#fragment"


def test_path_not_contain_fragment1(make_request):
    req = make_request('GET', "http://example.com/path#fragment")
    assert req.path == "/path"


def test_path_not_contain_fragment2(make_request):
    req = make_request('GET', "http://example.com/path?key=value#fragment")
    assert req.path == "/path?key=value"


def test_cookies(make_request):
    req = make_request('get', 'http://test.com/path',
                       cookies={'cookie1': 'val1'})

    assert 'COOKIE' in req.headers
    assert 'cookie1=val1' == req.headers['COOKIE']


def test_cookies_merge_with_headers(make_request):
    req = make_request('get', 'http://test.com/path',
                       headers={'cookie': 'cookie1=val1'},
                       cookies={'cookie2': 'val2'})

    assert 'cookie1=val1; cookie2=val2' == req.headers['COOKIE']


def test_unicode_get1(make_request):
    req = make_request('get', 'http://python.org',
                       params={'foo': 'f\xf8\xf8'})
    assert '/?foo=f%C3%B8%C3%B8' == req.path


def test_unicode_get2(make_request):
    req = make_request('', 'http://python.org',
                       params={'f\xf8\xf8': 'f\xf8\xf8'})

    assert '/?f%C3%B8%C3%B8=f%C3%B8%C3%B8' == req.path


def test_unicode_get3(make_request):
    req = make_request('', 'http://python.org', params={'foo': 'foo'})
    assert '/?foo=foo' == req.path


def test_unicode_get4(make_request):
    def join(*suffix):
        return urllib.parse.urljoin('http://python.org/', '/'.join(suffix))

    req = make_request('', join('\xf8'), params={'foo': 'foo'})
    assert '/%C3%B8?foo=foo' == req.path


def test_query_multivalued_param(make_request):
    for meth in ClientRequest.ALL_METHODS:
        req = make_request(
            meth, 'http://python.org',
            params=(('test', 'foo'), ('test', 'baz')))

        assert req.path == '/?test=foo&test=baz'


def test_query_str_param(make_request):
    for meth in ClientRequest.ALL_METHODS:
        req = make_request(meth, 'http://python.org', params='test=foo')
        assert req.path == '/?test=foo'


def test_query_bytes_param_raises(make_request):
    for meth in ClientRequest.ALL_METHODS:
        with pytest.raises(TypeError) as ctx:
            make_request(meth, 'http://python.org', params=b'test=foo')
        assert re.match('not a valid non-string.*or mapping', str(ctx.value))


def test_query_str_param_is_not_encoded(make_request):
    for meth in ClientRequest.ALL_METHODS:
        req = make_request(meth, 'http://python.org', params='test=f+oo')
        assert req.path == '/?test=f+oo'


def test_params_update_path_and_url(make_request):
    req = make_request('get', 'http://python.org',
                       params=(('test', 'foo'), ('test', 'baz')))
    assert req.path == '/?test=foo&test=baz'
    assert req.url == 'http://python.org/?test=foo&test=baz'


def test_params_empty_path_and_url(make_request):
    req_empty = make_request('get', 'http://python.org', params={})
    assert req_empty.path == '/'
    assert req_empty.url == 'http://python.org/'
    req_none = make_request('get', 'http://python.org')
    assert req_none.path == '/'
    assert req_none.url == 'http://python.org/'


def test_gen_netloc_all(make_request):
    req = make_request('get',
                       'https://aiohttp:pwpwpw@' +
                       '12345678901234567890123456789' +
                       '012345678901234567890:8080')
    assert req.netloc == '12345678901234567890123456789' +\
                         '012345678901234567890:8080'


def test_gen_netloc_no_port(make_request):
    req = make_request('get',
                       'https://aiohttp:pwpwpw@' +
                       '12345678901234567890123456789' +
                       '012345678901234567890/')
    assert req.netloc == '12345678901234567890123456789' +\
                         '012345678901234567890'


def test_gen_notloc_failed(make_request):
    with pytest.raises(ValueError) as excinfo:
        make_request('get',
                     'https://aiohttp:pwpwpw@' +
                     '123456789012345678901234567890123456789' +
                     '01234567890123456789012345/')
        assert excinfo.value.message == "URL has an invalid label."


class TestClientRequest(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

        self.transport = mock.Mock()
        self.connection = mock.Mock()
        self.protocol = mock.Mock()
        self.protocol.writer.drain.return_value = ()
        self.stream = aiohttp.StreamParser(loop=self.loop)
        self.connector = BaseConnector(loop=self.loop)

    def tearDown(self):
        self.connector.close()
        try:
            self.loop.stop()
            self.loop.run_forever()
        except RuntimeError:  # loop is already closed
            pass
        self.loop.close()
        gc.collect()

    def test_no_content_length(self):
        req = ClientRequest('get', 'http://python.org', loop=self.loop)
        resp = req.send(self.transport, self.protocol)
        self.assertEqual('0', req.headers.get('CONTENT-LENGTH'))
        self.loop.run_until_complete(req.close())
        resp.close()

    def test_no_content_length2(self):
        req = ClientRequest('head', 'http://python.org', loop=self.loop)
        resp = req.send(self.transport, self.protocol)
        self.assertEqual('0', req.headers.get('CONTENT-LENGTH'))
        self.loop.run_until_complete(req.close())
        resp.close()

    def test_content_type_auto_header_get(self):
        req = ClientRequest('get', 'http://python.org', loop=self.loop)
        resp = req.send(self.transport, self.protocol)
        self.assertNotIn('CONTENT-TYPE', req.headers)
        resp.close()

    def test_content_type_auto_header_form(self):
        req = ClientRequest('post', 'http://python.org', data={'hey': 'you'},
                            loop=self.loop)
        resp = req.send(self.transport, self.protocol)
        self.assertEqual('application/x-www-form-urlencoded',
                         req.headers.get('CONTENT-TYPE'))
        resp.close()

    def test_content_type_auto_header_bytes(self):
        req = ClientRequest('post', 'http://python.org', data=b'hey you',
                            loop=self.loop)
        resp = req.send(self.transport, self.protocol)
        self.assertEqual('application/octet-stream',
                         req.headers.get('CONTENT-TYPE'))
        resp.close()

    def test_content_type_skip_auto_header_bytes(self):
        req = ClientRequest('post', 'http://python.org', data=b'hey you',
                            skip_auto_headers={'Content-Type'},
                            loop=self.loop)
        resp = req.send(self.transport, self.protocol)
        self.assertNotIn('CONTENT-TYPE', req.headers)
        resp.close()

    def test_content_type_skip_auto_header_form(self):
        req = ClientRequest('post', 'http://python.org', data={'hey': 'you'},
                            loop=self.loop, skip_auto_headers={'Content-Type'})
        resp = req.send(self.transport, self.protocol)
        self.assertNotIn('CONTENT-TYPE', req.headers)
        resp.close()

    def test_content_type_auto_header_content_length_no_skip(self):
        req = ClientRequest('get', 'http://python.org',
                            data=io.BytesIO(b'hey'),
                            skip_auto_headers={'Content-Length'},
                            loop=self.loop)
        resp = req.send(self.transport, self.protocol)
        self.assertEqual(req.headers.get('CONTENT-LENGTH'), '3')
        resp.close()

    def test_post_data(self):
        for meth in ClientRequest.POST_METHODS:
            req = ClientRequest(
                meth, 'http://python.org/',
                data={'life': '42'}, loop=self.loop)
            resp = req.send(self.transport, self.protocol)
            self.assertEqual('/', req.path)
            self.assertEqual(b'life=42', req.body)
            self.assertEqual('application/x-www-form-urlencoded',
                             req.headers['CONTENT-TYPE'])
            self.loop.run_until_complete(req.close())
            resp.close()

    @mock.patch(
        'aiohttp.client_reqrep.ClientRequest.update_body_from_data')
    def test_pass_falsy_data(self, _):
        req = ClientRequest(
            'post', 'http://python.org/',
            data={}, loop=self.loop)
        req.update_body_from_data.assert_called_once_with({}, frozenset())
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
            resp = req.send(self.transport, self.protocol)
            self.assertEqual('/', req.path)
            self.assertEqual(b'binary data', req.body)
            self.assertEqual('application/octet-stream',
                             req.headers['CONTENT-TYPE'])
            self.loop.run_until_complete(req.close())
            resp.close()

    @mock.patch('aiohttp.client_reqrep.aiohttp')
    def test_content_encoding(self, m_http):
        req = ClientRequest('get', 'http://python.org/', data='foo',
                            compress='deflate', loop=self.loop)
        resp = req.send(self.transport, self.protocol)
        self.assertEqual(req.headers['TRANSFER-ENCODING'], 'chunked')
        self.assertEqual(req.headers['CONTENT-ENCODING'], 'deflate')
        m_http.Request.return_value\
            .add_compression_filter.assert_called_with('deflate')
        self.loop.run_until_complete(req.close())
        resp.close()

    @mock.patch('aiohttp.client_reqrep.aiohttp')
    def test_content_encoding_dont_set_headers_if_no_body(self, m_http):
        req = ClientRequest('get', 'http://python.org/',
                            compress='deflate', loop=self.loop)
        resp = req.send(self.transport, self.protocol)
        self.assertNotIn('TRANSFER-ENCODING', req.headers)
        self.assertNotIn('CONTENT-ENCODING', req.headers)
        self.loop.run_until_complete(req.close())
        resp.close()

    @mock.patch('aiohttp.client_reqrep.aiohttp')
    def test_content_encoding_header(self, m_http):
        req = ClientRequest(
            'get', 'http://python.org/', data='foo',
            headers={'Content-Encoding': 'deflate'}, loop=self.loop)
        resp = req.send(self.transport, self.protocol)
        self.assertEqual(req.headers['TRANSFER-ENCODING'], 'chunked')
        self.assertEqual(req.headers['CONTENT-ENCODING'], 'deflate')

        m_http.Request.return_value\
            .add_compression_filter.assert_called_with('deflate')
        m_http.Request.return_value\
            .add_chunking_filter.assert_called_with(8192)
        self.loop.run_until_complete(req.close())
        resp.close()

    def test_chunked(self):
        req = ClientRequest(
            'get', 'http://python.org/',
            headers={'TRANSFER-ENCODING': 'gzip'}, loop=self.loop)
        resp = req.send(self.transport, self.protocol)
        self.assertEqual('gzip', req.headers['TRANSFER-ENCODING'])
        self.loop.run_until_complete(req.close())
        resp.close()

        req = ClientRequest(
            'get', 'http://python.org/',
            headers={'Transfer-encoding': 'chunked'}, loop=self.loop)
        resp = req.send(self.transport, self.protocol)
        self.assertEqual('chunked', req.headers['TRANSFER-ENCODING'])
        self.loop.run_until_complete(req.close())
        resp.close()

    @mock.patch('aiohttp.client_reqrep.aiohttp')
    def test_chunked_explicit(self, m_http):
        req = ClientRequest(
            'get', 'http://python.org/', chunked=True, loop=self.loop)
        resp = req.send(self.transport, self.protocol)

        self.assertEqual('chunked', req.headers['TRANSFER-ENCODING'])
        m_http.Request.return_value\
                      .add_chunking_filter.assert_called_with(8192)
        self.loop.run_until_complete(req.close())
        resp.close()

    @mock.patch('aiohttp.client_reqrep.aiohttp')
    def test_chunked_explicit_size(self, m_http):
        req = ClientRequest(
            'get', 'http://python.org/', chunked=1024, loop=self.loop)
        resp = req.send(self.transport, self.protocol)
        self.assertEqual('chunked', req.headers['TRANSFER-ENCODING'])
        m_http.Request.return_value\
                      .add_chunking_filter.assert_called_with(1024)
        self.loop.run_until_complete(req.close())
        resp.close()

    def test_chunked_length(self):
        req = ClientRequest(
            'get', 'http://python.org/',
            headers={'CONTENT-LENGTH': '1000'}, chunked=1024, loop=self.loop)
        resp = req.send(self.transport, self.protocol)
        self.assertEqual(req.headers['TRANSFER-ENCODING'], 'chunked')
        self.assertNotIn('CONTENT-LENGTH', req.headers)
        self.loop.run_until_complete(req.close())
        resp.close()

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

    def test_precompressed_data_stays_intact(self):
        data = zlib.compress(b'foobar')
        req = ClientRequest(
            'post', 'http://python.org/',
            data=data,
            headers={'CONTENT-ENCODING': 'deflate'},
            compress=False,
            loop=self.loop)
        self.assertFalse(req.compress)
        self.assertFalse(req.chunked)
        self.assertEqual(req.headers['CONTENT-ENCODING'],
                         'deflate')
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
            self.transport.write.mock_calls[-2:],
            [mock.call(b'12\r\nbinary data result\r\n'),
             mock.call(b'0\r\n\r\n')])
        self.loop.run_until_complete(req.close())

    def test_data_file(self):
        req = ClientRequest(
            'POST', 'http://python.org/',
            data=io.BufferedReader(io.BytesIO(b'*' * 2)),
            loop=self.loop)
        self.assertTrue(req.chunked)
        self.assertTrue(isinstance(req.body, io.IOBase))
        self.assertEqual(req.headers['TRANSFER-ENCODING'], 'chunked')

        resp = req.send(self.transport, self.protocol)
        self.assertIsInstance(req._writer, asyncio.Future)
        self.loop.run_until_complete(resp.wait_for_close())
        self.assertIsNone(req._writer)
        self.assertEqual(
            self.transport.write.mock_calls[-2:],
            [mock.call(b'2\r\n' + b'*' * 2 + b'\r\n'),
             mock.call(b'0\r\n\r\n')])
        self.loop.run_until_complete(req.close())

    def test_data_stream_exc(self):
        fut = helpers.create_future(self.loop)

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
        resp = req.send(self.transport, self.protocol)
        self.loop.run_until_complete(req._writer)
        self.assertTrue(self.protocol.set_exception.called)
        self.loop.run_until_complete(req.close())
        resp.close()

    def test_data_stream_exc_chain(self):
        fut = helpers.create_future(self.loop)

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

        resp = req.send(self.transport, self.protocol)
        self.loop.run_until_complete(req._writer)
        self.assertEqual(
            self.transport.write.mock_calls[-2:],
            [mock.call(b'12\r\nbinary data result\r\n'),
             mock.call(b'0\r\n\r\n')])
        self.loop.run_until_complete(req.close())
        resp.close()

    def test_data_continue(self):
        req = ClientRequest(
            'POST', 'http://python.org/', data=b'data',
            expect100=True, loop=self.loop)

        def coro():
            yield from asyncio.sleep(0.0001, loop=self.loop)
            req._continue.set_result(1)

        asyncio.async(coro(), loop=self.loop)

        resp = req.send(self.transport, self.protocol)
        self.assertEqual(1, len(self.transport.write.mock_calls))

        self.loop.run_until_complete(req._writer)
        self.assertEqual(
            self.transport.write.mock_calls[-1],
            mock.call(b'data'))
        self.loop.run_until_complete(req.close())
        resp.close()

    def test_close(self):
        @asyncio.coroutine
        def gen():
            yield from asyncio.sleep(0.00001, loop=self.loop)
            return b'result'

        req = ClientRequest(
            'POST', 'http://python.org/', data=gen(), loop=self.loop)
        resp = req.send(self.transport, self.protocol)
        self.loop.run_until_complete(req.close())
        self.assertEqual(
            self.transport.write.mock_calls[-2:],
            [mock.call(b'6\r\nresult\r\n'),
             mock.call(b'0\r\n\r\n')])
        self.loop.run_until_complete(req.close())
        resp.close()

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
        resp.close()

    def test_terminate(self):
        req = ClientRequest('get', 'http://python.org', loop=self.loop)
        resp = req.send(self.transport, self.protocol)
        self.assertIsNotNone(req._writer)
        writer = req._writer = mock.Mock()

        req.terminate()
        self.assertIsNone(req._writer)
        writer.cancel.assert_called_with()
        resp.close()

    def test_terminate_with_closed_loop(self):
        req = ClientRequest('get', 'http://python.org', loop=self.loop)
        resp = req.send(self.transport, self.protocol)
        self.assertIsNotNone(req._writer)
        writer = req._writer = mock.Mock()

        self.loop.close()
        req.terminate()
        self.assertIsNone(req._writer)
        self.assertFalse(writer.cancel.called)
        resp.close()

    def test_terminate_without_writer(self):
        req = ClientRequest('get', 'http://python.org', loop=self.loop)
        self.assertIsNone(req._writer)

        req.terminate()
        self.assertIsNone(req._writer)

    def test_custom_req_rep(self):
        @asyncio.coroutine
        def go():
            conn = None

            class CustomResponse(ClientResponse):
                @asyncio.coroutine
                def start(self, connection, read_until_eof=False):
                    nonlocal conn
                    conn = connection
                    self.status = 123
                    self.reason = 'Test OK'
                    self.headers = CIMultiDictProxy(CIMultiDict())
                    self.cookies = SimpleCookie()
                    return

            called = False

            class CustomRequest(ClientRequest):

                def send(self, writer, reader):
                    resp = self.response_class(self.method,
                                               self.url,
                                               self.host,
                                               writer=self._writer,
                                               continue100=self._continue)
                    resp._post_init(self.loop)
                    self.response = resp
                    nonlocal called
                    called = True
                    return resp

            @asyncio.coroutine
            def create_connection(req):
                self.assertIsInstance(req, CustomRequest)
                return self.transport, self.protocol
            self.connector._create_connection = create_connection

            resp = yield from aiohttp.request('get',
                                              'http://example.com/path/to',
                                              request_class=CustomRequest,
                                              response_class=CustomResponse,
                                              connector=self.connector,
                                              loop=self.loop)
            self.assertIsInstance(resp, CustomResponse)
            self.assertTrue(called)
            resp.close()
            conn.close()

        self.loop.run_until_complete(go())
