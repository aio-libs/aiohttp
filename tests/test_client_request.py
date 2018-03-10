# coding: utf-8

import asyncio
import hashlib
import io
import os.path
import urllib.parse
import zlib
from http.cookies import SimpleCookie
from unittest import mock

import pytest
from multidict import CIMultiDict, CIMultiDictProxy, istr
from yarl import URL

import aiohttp
from aiohttp import BaseConnector, hdrs, payload
from aiohttp.client_reqrep import (ClientRequest, ClientResponse, Fingerprint,
                                   _merge_ssl_params)
from aiohttp.test_utils import make_mocked_coro


@pytest.fixture
def make_request(loop):
    request = None

    def maker(method, url, *args, **kwargs):
        nonlocal request
        request = ClientRequest(method, URL(url), *args, loop=loop, **kwargs)
        return request

    yield maker
    if request is not None:
        loop.run_until_complete(request.close())


@pytest.fixture
def buf():
    return bytearray()


@pytest.fixture
def protocol(loop):
    protocol = mock.Mock()
    protocol._drain_helper.return_value = loop.create_future()
    protocol._drain_helper.return_value.set_result(None)
    return protocol


@pytest.fixture
def transport(buf):
    transport = mock.Mock()

    def write(chunk):
        buf.extend(chunk)

    async def write_eof():
        pass

    transport.write.side_effect = write
    transport.write_eof.side_effect = write_eof
    transport.is_closing.return_value = False

    return transport


@pytest.fixture
def conn(transport, protocol):
    return mock.Mock(
        transport=transport,
        protocol=protocol
    )


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


def test_request_info(make_request):
    req = make_request('get', 'http://python.org/')
    assert req.request_info == aiohttp.RequestInfo(URL('http://python.org/'),
                                                   'GET',
                                                   req.headers)


def test_version_err(make_request):
    with pytest.raises(ValueError):
        make_request('get', 'http://python.org/', version='1.c')


def test_https_proxy(make_request):
    with pytest.raises(ValueError):
        make_request(
            'get', 'http://python.org/', proxy=URL('https://proxy.org'))


def test_keep_alive(make_request):
    req = make_request('get', 'http://python.org/', version=(0, 9))
    assert not req.keep_alive()

    req = make_request('get', 'http://python.org/', version=(1, 0))
    assert not req.keep_alive()

    req = make_request('get', 'http://python.org/',
                       version=(1, 0), headers={'connection': 'keep-alive'})
    assert req.keep_alive()

    req = make_request('get', 'http://python.org/', version=(1, 1))
    assert req.keep_alive()

    req = make_request('get', 'http://python.org/',
                       version=(1, 1), headers={'connection': 'close'})
    assert not req.keep_alive()


def test_host_port_default_http(make_request):
    req = make_request('get', 'http://python.org/')
    assert req.host == 'python.org'
    assert req.port == 80
    assert not req.ssl


def test_host_port_default_https(make_request):
    req = make_request('get', 'https://python.org/')
    assert req.host == 'python.org'
    assert req.port == 443
    assert req.is_ssl()


def test_host_port_nondefault_http(make_request):
    req = make_request('get', 'http://python.org:960/')
    assert req.host == 'python.org'
    assert req.port == 960
    assert not req.is_ssl()


def test_host_port_nondefault_https(make_request):
    req = make_request('get', 'https://python.org:960/')
    assert req.host == 'python.org'
    assert req.port == 960
    assert req.is_ssl()


def test_host_port_default_ws(make_request):
    req = make_request('get', 'ws://python.org/')
    assert req.host == 'python.org'
    assert req.port == 80
    assert not req.is_ssl()


def test_host_port_default_wss(make_request):
    req = make_request('get', 'wss://python.org/')
    assert req.host == 'python.org'
    assert req.port == 443
    assert req.is_ssl()


def test_host_port_nondefault_ws(make_request):
    req = make_request('get', 'ws://python.org:960/')
    assert req.host == 'python.org'
    assert req.port == 960
    assert not req.is_ssl()


def test_host_port_nondefault_wss(make_request):
    req = make_request('get', 'wss://python.org:960/')
    assert req.host == 'python.org'
    assert req.port == 960
    assert req.is_ssl()


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
                       skip_auto_headers=set([istr('user-agent')]))

    assert 'User-Agent' not in req.headers


def test_headers(make_request):
    req = make_request('post', 'http://python.org/',
                       headers={'Content-Type': 'text/plain'})

    assert 'CONTENT-TYPE' in req.headers
    assert req.headers['CONTENT-TYPE'] == 'text/plain'
    assert req.headers['ACCEPT-ENCODING'] == 'gzip, deflate'


def test_headers_list(make_request):
    req = make_request('post', 'http://python.org/',
                       headers=[('Content-Type', 'text/plain')])
    assert 'CONTENT-TYPE' in req.headers
    assert req.headers['CONTENT-TYPE'] == 'text/plain'


def test_headers_default(make_request):
    req = make_request('get', 'http://python.org/',
                       headers={'ACCEPT-ENCODING': 'deflate'})
    assert req.headers['ACCEPT-ENCODING'] == 'deflate'


def test_invalid_url(make_request):
    with pytest.raises(aiohttp.InvalidURL):
        make_request('get', 'hiwpefhipowhefopw')


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
    assert req.is_ssl()


def test_ipv6_nondefault_http_port(make_request):
    req = make_request('get', 'http://[2001:db8::1]:960/')
    assert req.host == '2001:db8::1'
    assert req.port == 960
    assert not req.is_ssl()


def test_ipv6_nondefault_https_port(make_request):
    req = make_request('get', 'https://[2001:db8::1]:960/')
    assert req.host == '2001:db8::1'
    assert req.port == 960
    assert req.is_ssl()


def test_basic_auth(make_request):
    req = make_request('get', 'http://python.org',
                       auth=aiohttp.BasicAuth('nkim', '1234'))
    assert 'AUTHORIZATION' in req.headers
    assert 'Basic bmtpbToxMjM0' == req.headers['AUTHORIZATION']


def test_basic_auth_utf8(make_request):
    req = make_request('get', 'http://python.org',
                       auth=aiohttp.BasicAuth('nkim', 'секрет', 'utf-8'))
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


async def test_connection_header(loop, conn):
    req = ClientRequest('get', URL('http://python.org'), loop=loop)
    req.keep_alive = mock.Mock()
    req.headers.clear()

    req.keep_alive.return_value = True
    req.version = (1, 1)
    req.headers.clear()
    await req.send(conn)
    assert req.headers.get('CONNECTION') is None

    req.version = (1, 0)
    req.headers.clear()
    await req.send(conn)
    assert req.headers.get('CONNECTION') == 'keep-alive'

    req.keep_alive.return_value = False
    req.version = (1, 1)
    req.headers.clear()
    await req.send(conn)
    assert req.headers.get('CONNECTION') == 'close'


async def test_no_content_length(loop, conn):
    req = ClientRequest('get', URL('http://python.org'), loop=loop)
    resp = await req.send(conn)
    assert req.headers.get('CONTENT-LENGTH') is None
    await req.close()
    resp.close()


async def test_no_content_length_head(loop, conn):
    req = ClientRequest('head', URL('http://python.org'), loop=loop)
    resp = await req.send(conn)
    assert req.headers.get('CONTENT-LENGTH') is None
    await req.close()
    resp.close()


async def test_content_type_auto_header_get(loop, conn):
    req = ClientRequest('get', URL('http://python.org'), loop=loop)
    resp = await req.send(conn)
    assert 'CONTENT-TYPE' not in req.headers
    resp.close()


async def test_content_type_auto_header_form(loop, conn):
    req = ClientRequest('post', URL('http://python.org'),
                        data={'hey': 'you'}, loop=loop)
    resp = await req.send(conn)
    assert 'application/x-www-form-urlencoded' == \
        req.headers.get('CONTENT-TYPE')
    resp.close()


async def test_content_type_auto_header_bytes(loop, conn):
    req = ClientRequest('post', URL('http://python.org'), data=b'hey you',
                        loop=loop)
    resp = await req.send(conn)
    assert 'application/octet-stream' == req.headers.get('CONTENT-TYPE')
    resp.close()


async def test_content_type_skip_auto_header_bytes(loop, conn):
    req = ClientRequest('post', URL('http://python.org'), data=b'hey you',
                        skip_auto_headers={'Content-Type'},
                        loop=loop)
    resp = await req.send(conn)
    assert 'CONTENT-TYPE' not in req.headers
    resp.close()


async def test_content_type_skip_auto_header_form(loop, conn):
    req = ClientRequest('post', URL('http://python.org'),
                        data={'hey': 'you'}, loop=loop,
                        skip_auto_headers={'Content-Type'})
    resp = await req.send(conn)
    assert 'CONTENT-TYPE' not in req.headers
    resp.close()


async def test_content_type_auto_header_content_length_no_skip(loop, conn):
    req = ClientRequest('post', URL('http://python.org'),
                        data=io.BytesIO(b'hey'),
                        skip_auto_headers={'Content-Length'},
                        loop=loop)
    resp = await req.send(conn)
    assert req.headers.get('CONTENT-LENGTH') == '3'
    resp.close()


async def test_urlencoded_formdata_charset(loop, conn):
    req = ClientRequest(
        'post', URL('http://python.org'),
        data=aiohttp.FormData({'hey': 'you'}, charset='koi8-r'), loop=loop)
    await req.send(conn)
    assert 'application/x-www-form-urlencoded; charset=koi8-r' == \
        req.headers.get('CONTENT-TYPE')


async def test_post_data(loop, conn):
    for meth in ClientRequest.POST_METHODS:
        req = ClientRequest(
            meth, URL('http://python.org/'),
            data={'life': '42'}, loop=loop)
        resp = await req.send(conn)
        assert '/' == req.url.path
        assert b'life=42' == req.body._value
        assert 'application/x-www-form-urlencoded' ==\
            req.headers['CONTENT-TYPE']
        await req.close()
        resp.close()


async def test_pass_falsy_data(loop):
    with mock.patch(
            'aiohttp.client_reqrep.ClientRequest.update_body_from_data'):
        req = ClientRequest(
            'post', URL('http://python.org/'),
            data={}, loop=loop)
        req.update_body_from_data.assert_called_once_with({})
    await req.close()


async def test_pass_falsy_data_file(loop, tmpdir):
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
    await req.close()


# Elasticsearch API requires to send request body with GET-requests
async def test_get_with_data(loop):
    for meth in ClientRequest.GET_METHODS:
        req = ClientRequest(
            meth, URL('http://python.org/'), data={'life': '42'},
            loop=loop)
        assert '/' == req.url.path
        assert b'life=42' == req.body._value
        await req.close()


async def test_bytes_data(loop, conn):
    for meth in ClientRequest.POST_METHODS:
        req = ClientRequest(
            meth, URL('http://python.org/'),
            data=b'binary data', loop=loop)
        resp = await req.send(conn)
        assert '/' == req.url.path
        assert isinstance(req.body, payload.BytesPayload)
        assert b'binary data' == req.body._value
        assert 'application/octet-stream' == req.headers['CONTENT-TYPE']
        await req.close()
        resp.close()


async def test_content_encoding(loop, conn):
    req = ClientRequest('post', URL('http://python.org/'), data='foo',
                        compress='deflate', loop=loop)
    with mock.patch('aiohttp.client_reqrep.StreamWriter') as m_writer:
        m_writer.return_value.write_headers = make_mocked_coro()
        resp = await req.send(conn)
    assert req.headers['TRANSFER-ENCODING'] == 'chunked'
    assert req.headers['CONTENT-ENCODING'] == 'deflate'
    m_writer.return_value\
        .enable_compression.assert_called_with('deflate')
    await req.close()
    resp.close()


async def test_content_encoding_dont_set_headers_if_no_body(loop, conn):
    req = ClientRequest('post', URL('http://python.org/'),
                        compress='deflate', loop=loop)
    with mock.patch('aiohttp.client_reqrep.http'):
        resp = await req.send(conn)
    assert 'TRANSFER-ENCODING' not in req.headers
    assert 'CONTENT-ENCODING' not in req.headers
    await req.close()
    resp.close()


async def test_content_encoding_header(loop, conn):
    req = ClientRequest(
        'post', URL('http://python.org/'), data='foo',
        headers={'Content-Encoding': 'deflate'}, loop=loop)
    with mock.patch('aiohttp.client_reqrep.StreamWriter') as m_writer:
        m_writer.return_value.write_headers = make_mocked_coro()
        resp = await req.send(conn)

    assert not m_writer.return_value.enable_compression.called
    assert not m_writer.return_value.enable_chunking.called
    await req.close()
    resp.close()


async def test_compress_and_content_encoding(loop, conn):
    with pytest.raises(ValueError):
        ClientRequest('post', URL('http://python.org/'), data='foo',
                      headers={'content-encoding': 'deflate'},
                      compress='deflate', loop=loop)


async def test_chunked(loop, conn):
    req = ClientRequest(
        'post', URL('http://python.org/'),
        headers={'TRANSFER-ENCODING': 'gzip'}, loop=loop)
    resp = await req.send(conn)
    assert 'gzip' == req.headers['TRANSFER-ENCODING']
    await req.close()
    resp.close()


async def test_chunked2(loop, conn):
    req = ClientRequest(
        'post', URL('http://python.org/'),
        headers={'Transfer-encoding': 'chunked'}, loop=loop)
    resp = await req.send(conn)
    assert 'chunked' == req.headers['TRANSFER-ENCODING']
    await req.close()
    resp.close()


async def test_chunked_explicit(loop, conn):
    req = ClientRequest(
        'post', URL('http://python.org/'), chunked=True, loop=loop)
    with mock.patch('aiohttp.client_reqrep.StreamWriter') as m_writer:
        m_writer.return_value.write_headers = make_mocked_coro()
        resp = await req.send(conn)

    assert 'chunked' == req.headers['TRANSFER-ENCODING']
    m_writer.return_value.enable_chunking.assert_called_with()
    await req.close()
    resp.close()


async def test_chunked_length(loop, conn):
    with pytest.raises(ValueError):
        ClientRequest(
            'post', URL('http://python.org/'),
            headers={'CONTENT-LENGTH': '1000'}, chunked=True, loop=loop)


async def test_chunked_transfer_encoding(loop, conn):
    with pytest.raises(ValueError):
        ClientRequest(
            'post', URL('http://python.org/'),
            headers={'TRANSFER-ENCODING': 'chunked'}, chunked=True, loop=loop)


async def test_file_upload_not_chunked(loop):
    here = os.path.dirname(__file__)
    fname = os.path.join(here, 'sample.key')
    with open(fname, 'rb') as f:
        req = ClientRequest(
            'post', URL('http://python.org/'),
            data=f,
            loop=loop)
        assert not req.chunked
        assert req.headers['CONTENT-LENGTH'] == str(os.path.getsize(fname))
        await req.close()


async def test_precompressed_data_stays_intact(loop):
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
    await req.close()


async def test_file_upload_not_chunked_seek(loop):
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
        await req.close()


async def test_file_upload_force_chunked(loop):
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
        await req.close()


async def test_expect100(loop, conn):
    req = ClientRequest('get', URL('http://python.org/'),
                        expect100=True, loop=loop)
    resp = await req.send(conn)
    assert '100-continue' == req.headers['EXPECT']
    assert req._continue is not None
    req.terminate()
    resp.close()


async def test_expect_100_continue_header(loop, conn):
    req = ClientRequest('get', URL('http://python.org/'),
                        headers={'expect': '100-continue'}, loop=loop)
    resp = await req.send(conn)
    assert '100-continue' == req.headers['EXPECT']
    assert req._continue is not None
    req.terminate()
    resp.close()


async def test_data_stream(loop, buf, conn):
    @aiohttp.streamer
    async def gen(writer):
        await writer.write(b'binary data')
        await writer.write(b' result')

    req = ClientRequest(
        'POST', URL('http://python.org/'), data=gen(), loop=loop)
    assert req.chunked
    assert req.headers['TRANSFER-ENCODING'] == 'chunked'

    resp = await req.send(conn)
    assert asyncio.isfuture(req._writer)
    await resp.wait_for_close()
    assert req._writer is None
    assert buf.split(b'\r\n\r\n', 1)[1] == \
        b'b\r\nbinary data\r\n7\r\n result\r\n0\r\n\r\n'
    await req.close()


async def test_data_file(loop, buf, conn):
    req = ClientRequest(
        'POST', URL('http://python.org/'),
        data=io.BufferedReader(io.BytesIO(b'*' * 2)),
        loop=loop)
    assert req.chunked
    assert isinstance(req.body, payload.BufferedReaderPayload)
    assert req.headers['TRANSFER-ENCODING'] == 'chunked'

    resp = await req.send(conn)
    assert asyncio.isfuture(req._writer)
    await resp.wait_for_close()
    assert req._writer is None
    assert buf.split(b'\r\n\r\n', 1)[1] == \
        b'2\r\n' + b'*' * 2 + b'\r\n0\r\n\r\n'
    await req.close()


async def test_data_stream_exc(loop, conn):
    fut = loop.create_future()

    @aiohttp.streamer
    async def gen(writer):
        await writer.write(b'binary data')
        await fut

    req = ClientRequest(
        'POST', URL('http://python.org/'), data=gen(), loop=loop)
    assert req.chunked
    assert req.headers['TRANSFER-ENCODING'] == 'chunked'

    async def throw_exc():
        await asyncio.sleep(0.01, loop=loop)
        fut.set_exception(ValueError)

    loop.create_task(throw_exc())

    await req.send(conn)
    await req._writer
    # assert conn.close.called
    assert conn.protocol.set_exception.called
    await req.close()


async def test_data_stream_exc_chain(loop, conn):
    fut = loop.create_future()

    @aiohttp.streamer
    async def gen(writer):
        await fut

    req = ClientRequest('POST', URL('http://python.org/'),
                        data=gen(), loop=loop)

    inner_exc = ValueError()

    async def throw_exc():
        await asyncio.sleep(0.01, loop=loop)
        fut.set_exception(inner_exc)

    loop.create_task(throw_exc())

    await req.send(conn)
    await req._writer
    # assert connection.close.called
    assert conn.protocol.set_exception.called
    outer_exc = conn.protocol.set_exception.call_args[0][0]
    assert isinstance(outer_exc, ValueError)
    assert inner_exc is outer_exc
    assert inner_exc is outer_exc
    await req.close()


async def test_data_stream_continue(loop, buf, conn):
    @aiohttp.streamer
    async def gen(writer):
        await writer.write(b'binary data')
        await writer.write(b' result')
        await writer.write_eof()

    req = ClientRequest(
        'POST', URL('http://python.org/'), data=gen(),
        expect100=True, loop=loop)
    assert req.chunked

    async def coro():
        await asyncio.sleep(0.0001, loop=loop)
        req._continue.set_result(1)

    loop.create_task(coro())

    resp = await req.send(conn)
    await req._writer
    assert buf.split(b'\r\n\r\n', 1)[1] == \
        b'b\r\nbinary data\r\n7\r\n result\r\n0\r\n\r\n'
    await req.close()
    resp.close()


async def test_data_continue(loop, buf, conn):
    req = ClientRequest(
        'POST', URL('http://python.org/'), data=b'data',
        expect100=True, loop=loop)

    async def coro():
        await asyncio.sleep(0.0001, loop=loop)
        req._continue.set_result(1)

    loop.create_task(coro())

    resp = await req.send(conn)

    await req._writer
    assert buf.split(b'\r\n\r\n', 1)[1] == b'data'
    await req.close()
    resp.close()


async def test_close(loop, buf, conn):
    @aiohttp.streamer
    async def gen(writer):
        await asyncio.sleep(0.00001, loop=loop)
        await writer.write(b'result')

    req = ClientRequest(
        'POST', URL('http://python.org/'), data=gen(), loop=loop)
    resp = await req.send(conn)
    await req.close()
    assert buf.split(b'\r\n\r\n', 1)[1] == b'6\r\nresult\r\n0\r\n\r\n'
    await req.close()
    resp.close()


async def test_custom_response_class(loop, conn):
    class CustomResponse(ClientResponse):
        def read(self, decode=False):
            return 'customized!'

    req = ClientRequest(
        'GET', URL('http://python.org/'), response_class=CustomResponse,
        loop=loop)
    resp = await req.send(conn)
    assert 'customized!' == resp.read()
    await req.close()
    resp.close()


async def test_oserror_on_write_bytes(loop, conn):
    req = ClientRequest(
        'POST', URL('http://python.org/'), loop=loop)

    writer = mock.Mock()
    writer.write.side_effect = OSError

    await req.write_bytes(writer, conn)

    assert conn.protocol.set_exception.called
    exc = conn.protocol.set_exception.call_args[0][0]
    assert isinstance(exc, aiohttp.ClientOSError)


async def test_terminate(loop, conn):
    req = ClientRequest('get', URL('http://python.org'), loop=loop)
    resp = await req.send(conn)
    assert req._writer is not None
    writer = req._writer = mock.Mock()

    req.terminate()
    assert req._writer is None
    writer.cancel.assert_called_with()
    resp.close()


def test_terminate_with_closed_loop(loop, conn):
    req = resp = writer = None

    async def go():
        nonlocal req, resp, writer
        req = ClientRequest('get', URL('http://python.org'))
        resp = await req.send(conn)
        assert req._writer is not None
        writer = req._writer = mock.Mock()

        await asyncio.sleep(0.05)

    loop.run_until_complete(go())

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


async def test_custom_req_rep(loop):
    conn = None

    class CustomResponse(ClientResponse):

        async def start(self, connection, read_until_eof=False):
            nonlocal conn
            conn = connection
            self.status = 123
            self.reason = 'Test OK'
            self.headers = CIMultiDictProxy(CIMultiDict())
            self.cookies = SimpleCookie()
            return

    called = False

    class CustomRequest(ClientRequest):

        async def send(self, conn):
            resp = self.response_class(self.method,
                                       self.url,
                                       writer=self._writer,
                                       continue100=self._continue,
                                       timer=self._timer,
                                       request_info=self.request_info,
                                       auto_decompress=self._auto_decompress,
                                       traces=self._traces,
                                       loop=self.loop,
                                       session=self._session)
            self.response = resp
            nonlocal called
            called = True
            return resp

    async def create_connection(req, traces=None):
        assert isinstance(req, CustomRequest)
        return mock.Mock()
    connector = BaseConnector(loop=loop)
    connector._create_connection = create_connection

    session = aiohttp.ClientSession(
        request_class=CustomRequest,
        response_class=CustomResponse,
        connector=connector,
        loop=loop)

    resp = await session.request(
        'get', URL('http://example.com/path/to'))
    assert isinstance(resp, CustomResponse)
    assert called
    resp.close()
    await session.close()
    conn.close()


def test_verify_ssl_false_with_ssl_context(loop):
    with pytest.warns(DeprecationWarning):
        with pytest.raises(ValueError):
            _merge_ssl_params(None, verify_ssl=False,
                              ssl_context=mock.Mock(), fingerprint=None)


def test_bad_fingerprint(loop):
    with pytest.raises(ValueError):
        Fingerprint(b'invalid')


def test_insecure_fingerprint_md5(loop):
    with pytest.raises(ValueError):
        Fingerprint(hashlib.md5(b"foo").digest())


def test_insecure_fingerprint_sha1(loop):
    with pytest.raises(ValueError):
        Fingerprint(hashlib.sha1(b"foo").digest())
