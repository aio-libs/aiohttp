# coding: utf-8

import asyncio
import inspect
import io
import os.path
import urllib.parse
import zlib
from unittest import mock

import pytest
from multidict import CIMultiDict, CIMultiDictProxy, upstr
from yarl import URL

import aiohttp
from aiohttp import BaseConnector, hdrs, helpers
from aiohttp.client_reqrep import ClientRequest, ClientResponse
from aiohttp.helpers import SimpleCookie


@pytest.yield_fixture
def make_request(loop):
    request = None

    def maker(method, url, *args, **kwargs):
        nonlocal request
        request = ClientRequest(method, URL(url), *args, loop=loop, **kwargs)
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
    assert req.headers['HOST'] == 'python.org'


def test_host_header_host_with_nondefault_port(make_request):
    req = make_request('get', 'http://python.org:99/')
    assert req.headers['HOST'] == 'python.org:99'


def test_host_header_host_idna_encode(make_request):
    req = make_request('get', 'http://xn--9caa.com')
    assert req.headers['HOST'] == 'xn--9caa.com'


def test_host_header_host_unicode(make_request):
    req = make_request('get', 'http://éé.com')
    assert req.headers['HOST'] == 'xn--9caa.com'


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
    req = ClientRequest('get', URL('http://python.org/'))
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
    assert '/' == req.url.path


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
    assert 'python.org' == req.host


def test_basic_auth_from_url_overriden(make_request):
    req = make_request('get', 'http://garbage@python.org',
                       auth=aiohttp.BasicAuth('nkim', '1234'))
    assert 'AUTHORIZATION' in req.headers
    assert 'Basic bmtpbToxMjM0' == req.headers['AUTHORIZATION']
    assert 'python.org' == req.host


def test_path_is_not_double_encoded1(make_request):
    req = make_request('get', "http://0.0.0.0/get/test case")
    assert req.url.raw_path == "/get/test%20case"


def test_path_is_not_double_encoded2(make_request):
    req = make_request('get', "http://0.0.0.0/get/test%2fcase")
    assert req.url.raw_path == "/get/test%2Fcase"


def test_path_is_not_double_encoded3(make_request):
    req = make_request('get', "http://0.0.0.0/get/test%20case")
    assert req.url.raw_path == "/get/test%20case"


def test_path_safe_chars_preserved(make_request):
    req = make_request('get', "http://0.0.0.0/get/:=+/%2B/")
    assert req.url.path == "/get/:=+/+/"


def test_params_are_added_before_fragment1(make_request):
    req = make_request('GET', "http://example.com/path#fragment",
                       params={"a": "b"})
    assert str(req.url) == "http://example.com/path?a=b"


def test_params_are_added_before_fragment2(make_request):
    req = make_request('GET', "http://example.com/path?key=value#fragment",
                       params={"a": "b"})
    assert str(req.url) == "http://example.com/path?key=value&a=b"


def test_path_not_contain_fragment1(make_request):
    req = make_request('GET', "http://example.com/path#fragment")
    assert req.url.path == "/path"


def test_path_not_contain_fragment2(make_request):
    req = make_request('GET', "http://example.com/path?key=value#fragment")
    assert str(req.url) == "http://example.com/path?key=value"


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
    assert 'http://python.org/?foo=f%C3%B8%C3%B8' == str(req.url)


def test_unicode_get2(make_request):
    req = make_request('', 'http://python.org',
                       params={'f\xf8\xf8': 'f\xf8\xf8'})

    assert 'http://python.org/?f%C3%B8%C3%B8=f%C3%B8%C3%B8' == str(req.url)


def test_unicode_get3(make_request):
    req = make_request('', 'http://python.org', params={'foo': 'foo'})
    assert 'http://python.org/?foo=foo' == str(req.url)


def test_unicode_get4(make_request):
    def join(*suffix):
        return urllib.parse.urljoin('http://python.org/', '/'.join(suffix))

    req = make_request('', join('\xf8'), params={'foo': 'foo'})
    assert 'http://python.org/%C3%B8?foo=foo' == str(req.url)


def test_query_multivalued_param(make_request):
    for meth in ClientRequest.ALL_METHODS:
        req = make_request(
            meth, 'http://python.org',
            params=(('test', 'foo'), ('test', 'baz')))

        assert str(req.url) == 'http://python.org/?test=foo&test=baz'


def test_query_str_param(make_request):
    for meth in ClientRequest.ALL_METHODS:
        req = make_request(meth, 'http://python.org', params='test=foo')
        assert str(req.url) == 'http://python.org/?test=foo'


def test_query_bytes_param_raises(make_request):
    for meth in ClientRequest.ALL_METHODS:
        with pytest.raises(TypeError):
            make_request(meth, 'http://python.org', params=b'test=foo')


def test_query_str_param_is_not_encoded(make_request):
    for meth in ClientRequest.ALL_METHODS:
        req = make_request(meth, 'http://python.org', params='test=f+oo')
        assert str(req.url) == 'http://python.org/?test=f+oo'


def test_params_update_path_and_url(make_request):
    req = make_request('get', 'http://python.org',
                       params=(('test', 'foo'), ('test', 'baz')))
    assert str(req.url) == 'http://python.org/?test=foo&test=baz'


def test_params_empty_path_and_url(make_request):
    req_empty = make_request('get', 'http://python.org', params={})
    assert str(req_empty.url) == 'http://python.org'
    req_none = make_request('get', 'http://python.org')
    assert str(req_none.url) == 'http://python.org'


def test_gen_netloc_all(make_request):
    req = make_request('get',
                       'https://aiohttp:pwpwpw@' +
                       '12345678901234567890123456789' +
                       '012345678901234567890:8080')
    assert req.headers['HOST'] == '12345678901234567890123456789' +\
        '012345678901234567890:8080'


def test_gen_netloc_no_port(make_request):
    req = make_request('get',
                       'https://aiohttp:pwpwpw@' +
                       '12345678901234567890123456789' +
                       '012345678901234567890/')
    assert req.headers['HOST'] == '12345678901234567890123456789' +\
        '012345678901234567890'


@asyncio.coroutine
def test_no_content_length(loop):
    req = ClientRequest('get', URL('http://python.org'), loop=loop)
    resp = req.send(mock.Mock(), mock.Mock())
    assert '0' == req.headers.get('CONTENT-LENGTH')
    yield from req.close()
    resp.close()


@asyncio.coroutine
def test_no_content_length2(loop):
    req = ClientRequest('head', URL('http://python.org'), loop=loop)
    resp = req.send(mock.Mock(), mock.Mock())
    assert '0' == req.headers.get('CONTENT-LENGTH')
    yield from req.close()
    resp.close()


def test_content_type_auto_header_get(loop):
    req = ClientRequest('get', URL('http://python.org'), loop=loop)
    resp = req.send(mock.Mock(), mock.Mock())
    assert 'CONTENT-TYPE' not in req.headers
    resp.close()


def test_content_type_auto_header_form(loop):
    req = ClientRequest('post', URL('http://python.org'),
                        data={'hey': 'you'}, loop=loop)
    resp = req.send(mock.Mock(), mock.Mock())
    assert 'application/x-www-form-urlencoded' == \
        req.headers.get('CONTENT-TYPE')
    resp.close()


def test_content_type_auto_header_bytes(loop):
    req = ClientRequest('post', URL('http://python.org'), data=b'hey you',
                        loop=loop)
    resp = req.send(mock.Mock(), mock.Mock())
    assert 'application/octet-stream' == req.headers.get('CONTENT-TYPE')
    resp.close()


def test_content_type_skip_auto_header_bytes(loop):
    req = ClientRequest('post', URL('http://python.org'), data=b'hey you',
                        skip_auto_headers={'Content-Type'},
                        loop=loop)
    resp = req.send(mock.Mock(), mock.Mock())
    assert 'CONTENT-TYPE' not in req.headers
    resp.close()


def test_content_type_skip_auto_header_form(loop):
    req = ClientRequest('post', URL('http://python.org'),
                        data={'hey': 'you'}, loop=loop,
                        skip_auto_headers={'Content-Type'})
    resp = req.send(mock.Mock(), mock.Mock())
    assert 'CONTENT-TYPE' not in req.headers
    resp.close()


def test_content_type_auto_header_content_length_no_skip(loop):
    req = ClientRequest('get', URL('http://python.org'),
                        data=io.BytesIO(b'hey'),
                        skip_auto_headers={'Content-Length'},
                        loop=loop)
    resp = req.send(mock.Mock(), mock.Mock())
    assert req.headers.get('CONTENT-LENGTH') == '3'
    resp.close()


@asyncio.coroutine
def test_post_data(loop):
    for meth in ClientRequest.POST_METHODS:
        req = ClientRequest(
            meth, URL('http://python.org/'),
            data={'life': '42'}, loop=loop)
        resp = req.send(mock.Mock(), mock.Mock())
        assert '/' == req.url.path
        assert b'life=42' == req.body
        assert 'application/x-www-form-urlencoded' ==\
            req.headers['CONTENT-TYPE']
        yield from req.close()
        resp.close()


@asyncio.coroutine
def test_pass_falsy_data(loop):
    with mock.patch(
            'aiohttp.client_reqrep.ClientRequest.update_body_from_data'):
        req = ClientRequest(
            'post', URL('http://python.org/'),
            data={}, loop=loop)
        req.update_body_from_data.assert_called_once_with({}, frozenset())
    yield from req.close()


@asyncio.coroutine
def test_pass_falsy_data_file(loop, tmpdir):
    testfile = tmpdir.join('tmpfile').open('w+b')
    testfile.write(b'data')
    testfile.seek(0)
    skip = frozenset([hdrs.CONTENT_TYPE])
    req = ClientRequest(
        'post', URL('http://python.org/'),
        data=testfile,
        skip_auto_headers=skip,
        loop=loop)
    assert req.headers.get('CONTENT-LENGTH', None) is not None
    yield from req.close()


@asyncio.coroutine
def test_get_with_data(loop):
    for meth in ClientRequest.GET_METHODS:
        req = ClientRequest(
            meth, URL('http://python.org/'), data={'life': '42'},
            loop=loop)
        assert '/' == req.url.path
        assert b'life=42' == req.body
        yield from req.close()


@asyncio.coroutine
def test_bytes_data(loop):
    for meth in ClientRequest.POST_METHODS:
        req = ClientRequest(
            meth, URL('http://python.org/'),
            data=b'binary data', loop=loop)
        resp = req.send(mock.Mock(), mock.Mock())
        assert '/' == req.url.path
        assert b'binary data' == req.body
        assert 'application/octet-stream' == req.headers['CONTENT-TYPE']
        yield from req.close()
        resp.close()


@asyncio.coroutine
def test_content_encoding(loop):
    req = ClientRequest('get', URL('http://python.org/'), data='foo',
                        compress='deflate', loop=loop)
    with mock.patch('aiohttp.client_reqrep.aiohttp') as m_http:
        resp = req.send(mock.Mock(), mock.Mock())
    assert req.headers['TRANSFER-ENCODING'] == 'chunked'
    assert req.headers['CONTENT-ENCODING'] == 'deflate'
    m_http.Request.return_value\
        .add_compression_filter.assert_called_with('deflate')
    yield from req.close()
    resp.close()


@asyncio.coroutine
def test_content_encoding_dont_set_headers_if_no_body(loop):
    req = ClientRequest('get', URL('http://python.org/'),
                        compress='deflate', loop=loop)
    with mock.patch('aiohttp.client_reqrep.aiohttp'):
        resp = req.send(mock.Mock(), mock.Mock())
    assert 'TRANSFER-ENCODING' not in req.headers
    assert 'CONTENT-ENCODING' not in req.headers
    yield from req.close()
    resp.close()


@asyncio.coroutine
def test_content_encoding_header(loop):
    req = ClientRequest(
        'get', URL('http://python.org/'), data='foo',
        headers={'Content-Encoding': 'deflate'}, loop=loop)
    with mock.patch('aiohttp.client_reqrep.aiohttp') as m_http:
        resp = req.send(mock.Mock(), mock.Mock())
    assert req.headers['TRANSFER-ENCODING'] == 'chunked'
    assert req.headers['CONTENT-ENCODING'] == 'deflate'

    m_http.Request.return_value\
        .add_compression_filter.assert_called_with('deflate')
    m_http.Request.return_value\
        .add_chunking_filter.assert_called_with(8192)
    yield from req.close()
    resp.close()


@asyncio.coroutine
def test_chunked(loop):
    req = ClientRequest(
        'get', URL('http://python.org/'),
        headers={'TRANSFER-ENCODING': 'gzip'}, loop=loop)
    resp = req.send(mock.Mock(), mock.Mock())
    assert 'gzip' == req.headers['TRANSFER-ENCODING']
    yield from req.close()
    resp.close()


@asyncio.coroutine
def test_chunked2(loop):
    req = ClientRequest(
        'get', URL('http://python.org/'),
        headers={'Transfer-encoding': 'chunked'}, loop=loop)
    resp = req.send(mock.Mock(), mock.Mock())
    assert 'chunked' == req.headers['TRANSFER-ENCODING']
    yield from req.close()
    resp.close()


@asyncio.coroutine
def test_chunked_explicit(loop):
    req = ClientRequest(
        'get', URL('http://python.org/'), chunked=True, loop=loop)
    with mock.patch('aiohttp.client_reqrep.aiohttp') as m_http:
        resp = req.send(mock.Mock(), mock.Mock())

    assert 'chunked' == req.headers['TRANSFER-ENCODING']
    m_http.Request.return_value\
                  .add_chunking_filter.assert_called_with(8192)
    yield from req.close()
    resp.close()


@asyncio.coroutine
def test_chunked_explicit_size(loop):
    req = ClientRequest(
        'get', URL('http://python.org/'), chunked=1024, loop=loop)
    with mock.patch('aiohttp.client_reqrep.aiohttp') as m_http:
        resp = req.send(mock.Mock(), mock.Mock())
    assert 'chunked' == req.headers['TRANSFER-ENCODING']
    m_http.Request.return_value\
                  .add_chunking_filter.assert_called_with(1024)
    yield from req.close()
    resp.close()


@asyncio.coroutine
def test_chunked_length(loop):
    req = ClientRequest(
        'get', URL('http://python.org/'),
        headers={'CONTENT-LENGTH': '1000'}, chunked=1024, loop=loop)
    resp = req.send(mock.Mock(), mock.Mock())
    assert req.headers['TRANSFER-ENCODING'] == 'chunked'
    assert 'CONTENT-LENGTH' not in req.headers
    yield from req.close()
    resp.close()


@asyncio.coroutine
def test_file_upload_not_chunked(loop):
    here = os.path.dirname(__file__)
    fname = os.path.join(here, 'sample.key')
    with open(fname, 'rb') as f:
        req = ClientRequest(
            'post', URL('http://python.org/'),
            data=f,
            loop=loop)
        assert not req.chunked
        assert req.headers['CONTENT-LENGTH'] == str(os.path.getsize(fname))
        yield from req.close()


@asyncio.coroutine
def test_precompressed_data_stays_intact(loop):
    data = zlib.compress(b'foobar')
    req = ClientRequest(
        'post', URL('http://python.org/'),
        data=data,
        headers={'CONTENT-ENCODING': 'deflate'},
        compress=False,
        loop=loop)
    assert not req.compress
    assert not req.chunked
    assert req.headers['CONTENT-ENCODING'] == 'deflate'
    yield from req.close()


@asyncio.coroutine
def test_file_upload_not_chunked_seek(loop):
    here = os.path.dirname(__file__)
    fname = os.path.join(here, 'sample.key')
    with open(fname, 'rb') as f:
        f.seek(100)
        req = ClientRequest(
            'post', URL('http://python.org/'),
            data=f,
            loop=loop)
        assert req.headers['CONTENT-LENGTH'] == \
            str(os.path.getsize(fname) - 100)
        yield from req.close()


@asyncio.coroutine
def test_file_upload_force_chunked(loop):
    here = os.path.dirname(__file__)
    fname = os.path.join(here, 'sample.key')
    with open(fname, 'rb') as f:
        req = ClientRequest(
            'post', URL('http://python.org/'),
            data=f,
            chunked=True,
            loop=loop)
        assert req.chunked
        assert 'CONTENT-LENGTH' not in req.headers
        yield from req.close()


def test_expect100(loop):
    req = ClientRequest('get', URL('http://python.org/'),
                        expect100=True, loop=loop)
    resp = req.send(mock.Mock(), mock.Mock())
    assert '100-continue' == req.headers['EXPECT']
    assert req._continue is not None
    req.terminate()
    resp.close()


def test_expect_100_continue_header(loop):
    req = ClientRequest('get', URL('http://python.org/'),
                        headers={'expect': '100-continue'}, loop=loop)
    resp = req.send(mock.Mock(), mock.Mock())
    assert '100-continue' == req.headers['EXPECT']
    assert req._continue is not None
    req.terminate()
    resp.close()


@asyncio.coroutine
def test_data_stream(loop):
    def gen():
        yield b'binary data'
        return b' result'

    req = ClientRequest(
        'POST', URL('http://python.org/'), data=gen(), loop=loop)
    assert req.chunked
    assert inspect.isgenerator(req.body)
    assert req.headers['TRANSFER-ENCODING'] == 'chunked'

    transport = mock.Mock()
    resp = req.send(transport, mock.Mock())
    assert isinstance(req._writer, asyncio.Future)
    yield from resp.wait_for_close()
    assert req._writer is None
    assert transport.write.mock_calls[-2:] == [
        mock.call(b'12\r\nbinary data result\r\n'),
        mock.call(b'0\r\n\r\n')]
    yield from req.close()


@asyncio.coroutine
def test_data_file(loop):
    req = ClientRequest(
        'POST', URL('http://python.org/'),
        data=io.BufferedReader(io.BytesIO(b'*' * 2)),
        loop=loop)
    assert req.chunked
    assert isinstance(req.body, io.IOBase)
    assert req.headers['TRANSFER-ENCODING'] == 'chunked'

    transport = mock.Mock()
    resp = req.send(transport, mock.Mock())
    assert isinstance(req._writer, asyncio.Future)
    yield from resp.wait_for_close()
    assert req._writer is None
    assert transport.write.mock_calls[-2:] == [
        mock.call(b'2\r\n' + b'*' * 2 + b'\r\n'),
        mock.call(b'0\r\n\r\n')]
    yield from req.close()


@asyncio.coroutine
def test_data_stream_exc(loop):
    fut = helpers.create_future(loop)

    def gen():
        yield b'binary data'
        yield from fut

    req = ClientRequest(
        'POST', URL('http://python.org/'), data=gen(), loop=loop)
    assert req.chunked
    assert inspect.isgenerator(req.body)
    assert req.headers['TRANSFER-ENCODING'] == 'chunked'

    @asyncio.coroutine
    def exc():
        yield from asyncio.sleep(0.01, loop=loop)
        fut.set_exception(ValueError)

    helpers.ensure_future(exc(), loop=loop)

    protocol = mock.Mock()
    resp = req.send(mock.Mock(), protocol)
    connection = mock.Mock()
    resp._connection = connection
    yield from req._writer
    assert connection.close.called
    assert protocol.set_exception.called
    yield from req.close()


@asyncio.coroutine
def test_data_stream_not_bytes(loop):
    @asyncio.coroutine
    def gen():
        yield object()

    req = ClientRequest(
        'POST', URL('http://python.org/'), data=gen(), loop=loop)
    protocol = mock.Mock()
    resp = req.send(mock.Mock(), protocol)
    yield from req._writer
    assert protocol.set_exception.called
    yield from req.close()
    resp.close()


@asyncio.coroutine
def test_data_stream_exc_chain(loop):
    fut = helpers.create_future(loop)

    def gen():
        yield from fut

    req = ClientRequest('POST', URL('http://python.org/'),
                        data=gen(), loop=loop)

    inner_exc = ValueError()

    @asyncio.coroutine
    def exc():
        yield from asyncio.sleep(0.01, loop=loop)
        fut.set_exception(inner_exc)

    helpers.ensure_future(exc(), loop=loop)

    protocol = mock.Mock()
    resp = req.send(mock.Mock(), protocol)
    connection = mock.Mock()
    resp._connection = connection
    yield from req._writer
    assert connection.close.called
    assert protocol.set_exception.called
    outer_exc = protocol.set_exception.call_args[0][0]
    assert isinstance(outer_exc, aiohttp.ClientRequestError)
    assert inner_exc is outer_exc.__context__
    assert inner_exc is outer_exc.__cause__
    yield from req.close()


@asyncio.coroutine
def test_data_stream_continue(loop):
    def gen():
        yield b'binary data'
        return b' result'

    req = ClientRequest(
        'POST', URL('http://python.org/'), data=gen(),
        expect100=True, loop=loop)
    assert req.chunked
    assert inspect.isgenerator(req.body)

    def coro():
        yield from asyncio.sleep(0.0001, loop=loop)
        req._continue.set_result(1)

    helpers.ensure_future(coro(), loop=loop)

    transport = mock.Mock()
    resp = req.send(transport, mock.Mock())
    yield from req._writer
    assert transport.write.mock_calls[-2:] == [
        mock.call(b'12\r\nbinary data result\r\n'),
        mock.call(b'0\r\n\r\n')]
    yield from req.close()
    resp.close()


@asyncio.coroutine
def test_data_continue(loop):
    req = ClientRequest(
        'POST', URL('http://python.org/'), data=b'data',
        expect100=True, loop=loop)

    def coro():
        yield from asyncio.sleep(0.0001, loop=loop)
        req._continue.set_result(1)

    helpers.ensure_future(coro(), loop=loop)

    transport = mock.Mock()
    resp = req.send(transport, mock.Mock())
    assert 1 == len(transport.write.mock_calls)

    yield from req._writer
    assert transport.write.mock_calls[-1] == mock.call(b'data')
    yield from req.close()
    resp.close()


@asyncio.coroutine
def test_close(loop):
    @asyncio.coroutine
    def gen():
        yield from asyncio.sleep(0.00001, loop=loop)
        return b'result'

    req = ClientRequest(
        'POST', URL('http://python.org/'), data=gen(), loop=loop)
    transport = mock.Mock()
    resp = req.send(transport, mock.Mock())
    yield from req.close()
    assert transport.write.mock_calls[-2:] == [
        mock.call(b'6\r\nresult\r\n'),
        mock.call(b'0\r\n\r\n')]
    yield from req.close()
    resp.close()


@asyncio.coroutine
def test_custom_response_class(loop):
    class CustomResponse(ClientResponse):
        def read(self, decode=False):
            return 'customized!'

    req = ClientRequest(
        'GET', URL('http://python.org/'), response_class=CustomResponse,
        loop=loop)
    resp = req.send(mock.Mock(), mock.Mock())
    assert 'customized!' == resp.read()
    yield from req.close()
    resp.close()


@asyncio.coroutine
def test_terminate(loop):
    req = ClientRequest('get', URL('http://python.org'), loop=loop)
    resp = req.send(mock.Mock(), mock.Mock())
    assert req._writer is not None
    writer = req._writer = mock.Mock()

    req.terminate()
    assert req._writer is None
    writer.cancel.assert_called_with()
    resp.close()


def test_terminate_with_closed_loop(loop):
    req = ClientRequest('get', URL('http://python.org'), loop=loop)
    resp = req.send(mock.Mock(), mock.Mock())
    assert req._writer is not None
    writer = req._writer = mock.Mock()

    loop.close()
    req.terminate()
    assert req._writer is None
    assert not writer.cancel.called
    resp.close()


def test_terminate_without_writer(loop):
    req = ClientRequest('get', URL('http://python.org'), loop=loop)
    assert req._writer is None

    req.terminate()
    assert req._writer is None


@asyncio.coroutine
def test_custom_req_rep(loop):
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
                                       writer=self._writer,
                                       continue100=self._continue)
            resp._post_init(self.loop)
            self.response = resp
            nonlocal called
            called = True
            return resp

    @asyncio.coroutine
    def create_connection(req):
        assert isinstance(req, CustomRequest)
        return mock.Mock(), mock.Mock()
    connector = BaseConnector(loop=loop)
    connector._create_connection = create_connection

    resp = yield from aiohttp.request(
        'get',
        URL('http://example.com/path/to'),
        request_class=CustomRequest,
        response_class=CustomResponse,
        connector=connector,
        loop=loop)
    assert isinstance(resp, CustomResponse)
    assert called
    resp.close()
    conn.close()
