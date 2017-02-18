import asyncio
from collections import MutableMapping
from unittest import mock

import pytest
from multidict import CIMultiDict, MultiDict
from yarl import URL

from aiohttp.protocol import HttpVersion
from aiohttp.streams import StreamReader
from aiohttp.test_utils import make_mocked_request
from aiohttp.web_exceptions import HTTPRequestEntityTooLarge


@pytest.fixture
def make_request():
    return make_mocked_request


def test_ctor(make_request):
    req = make_request('GET', '/path/to?a=1&b=2')

    assert 'GET' == req.method
    assert HttpVersion(1, 1) == req.version
    assert req.host is None
    assert '/path/to?a=1&b=2' == req.path_qs
    assert '/path/to' == req.path
    assert 'a=1&b=2' == req.query_string
    assert CIMultiDict() == req.headers
    assert () == req.raw_headers

    get = req.GET
    assert MultiDict([('a', '1'), ('b', '2')]) == get
    # second call should return the same object
    assert get is req.GET

    assert req.keep_alive

    # just make sure that all lines of make_mocked_request covered
    headers = CIMultiDict(FOO='bar')
    reader = mock.Mock()
    writer = mock.Mock()
    payload = mock.Mock()
    transport = mock.Mock()
    app = mock.Mock()
    req = make_request('GET', '/path/to?a=1&b=2', headers=headers,
                       writer=writer, reader=reader, payload=payload,
                       transport=transport, app=app)
    assert req.app is app
    assert req.content is payload
    assert req.transport is transport
    assert req._reader is reader
    assert req._writer is writer
    assert req.headers == headers
    assert req.raw_headers == ((b'Foo', b'bar'),)


def test_doubleslashes(make_request):
    # NB: //foo/bar is an absolute URL with foo netloc and /bar path
    req = make_request('GET', '/bar//foo/')
    assert '/bar//foo/' == req.path


def test_POST(make_request):
    req = make_request('POST', '/')
    with pytest.raises(RuntimeError):
        req.POST

    marker = object()
    req._post = marker
    assert req.POST is marker
    assert req.POST is marker


def test_content_type_not_specified(make_request):
    req = make_request('Get', '/')
    assert 'application/octet-stream' == req.content_type


def test_content_type_from_spec(make_request):
    req = make_request('Get', '/',
                       CIMultiDict([('CONTENT-TYPE', 'application/json')]))
    assert 'application/json' == req.content_type


def test_content_type_from_spec_with_charset(make_request):
    req = make_request(
        'Get', '/',
        CIMultiDict([('CONTENT-TYPE', 'text/html; charset=UTF-8')]))
    assert 'text/html' == req.content_type
    assert 'UTF-8' == req.charset


def test_calc_content_type_on_getting_charset(make_request):
    req = make_request(
        'Get', '/',
        CIMultiDict([('CONTENT-TYPE', 'text/html; charset=UTF-8')]))
    assert 'UTF-8' == req.charset
    assert 'text/html' == req.content_type


def test_urlencoded_querystring(make_request):
    req = make_request('GET',
                       '/yandsearch?text=%D1%82%D0%B5%D0%BA%D1%81%D1%82')
    assert {'text': 'текст'} == req.GET


def test_non_ascii_path(make_request):
    req = make_request('GET', '/путь')
    assert '/путь' == req.path


def test_non_ascii_raw_path(make_request):
    req = make_request('GET', '/путь')
    assert '/%D0%BF%D1%83%D1%82%D1%8C' == req.raw_path


def test_content_length(make_request):
    req = make_request('Get', '/',
                       CIMultiDict([('CONTENT-LENGTH', '123')]))

    assert 123 == req.content_length


def test_non_keepalive_on_http10(make_request):
    req = make_request('GET', '/', version=HttpVersion(1, 0))
    assert not req.keep_alive


def test_non_keepalive_on_closing(make_request):
    req = make_request('GET', '/', closing=True)
    assert not req.keep_alive


@asyncio.coroutine
def test_call_POST_on_GET_request(make_request):
    req = make_request('GET', '/')

    ret = yield from req.post()
    assert CIMultiDict() == ret


@asyncio.coroutine
def test_call_POST_on_weird_content_type(make_request):
    req = make_request(
        'POST', '/',
        headers=CIMultiDict({'CONTENT-TYPE': 'something/weird'}))

    ret = yield from req.post()
    assert CIMultiDict() == ret


@asyncio.coroutine
def test_call_POST_twice(make_request):
    req = make_request('GET', '/')

    ret1 = yield from req.post()
    ret2 = yield from req.post()
    assert ret1 is ret2


def test_no_request_cookies(make_request):
    req = make_request('GET', '/')

    assert req.cookies == {}

    cookies = req.cookies
    assert cookies is req.cookies


def test_request_cookie(make_request):
    headers = CIMultiDict(COOKIE='cookie1=value1; cookie2=value2')
    req = make_request('GET', '/', headers=headers)

    assert req.cookies == {'cookie1': 'value1',
                           'cookie2': 'value2'}


def test_request_cookie__set_item(make_request):
    headers = CIMultiDict(COOKIE='name=value')
    req = make_request('GET', '/', headers=headers)

    assert req.cookies == {'name': 'value'}

    with pytest.raises(TypeError):
        req.cookies['my'] = 'value'


def test_match_info(make_request):
    req = make_request('GET', '/')
    assert req._match_info is req.match_info


def test_request_is_mutable_mapping(make_request):
    req = make_request('GET', '/')
    assert isinstance(req, MutableMapping)
    req['key'] = 'value'
    assert 'value' == req['key']


def test_request_delitem(make_request):
    req = make_request('GET', '/')
    req['key'] = 'value'
    assert 'value' == req['key']
    del req['key']
    assert 'key' not in req


def test_request_len(make_request):
    req = make_request('GET', '/')
    assert len(req) == 0
    req['key'] = 'value'
    assert len(req) == 1


def test_request_iter(make_request):
    req = make_request('GET', '/')
    req['key'] = 'value'
    req['key2'] = 'value2'
    assert set(req) == {'key', 'key2'}


def test___repr__(make_request):
    req = make_request('GET', '/path/to')
    assert "<Request GET /path/to >" == repr(req)


def test___repr___non_ascii_path(make_request):
    req = make_request('GET', '/path/\U0001f415\U0001f308')
    assert "<Request GET /path/\\U0001f415\\U0001f308 >" == repr(req)


def test_http_scheme(make_request):
    req = make_request('GET', '/')
    assert "http" == req.scheme


def test_https_scheme_by_ssl_transport(make_request):
    req = make_request('GET', '/', sslcontext=True)
    assert "https" == req.scheme


def test_https_scheme_by_secure_proxy_ssl_header(make_request):
    req = make_request('GET', '/',
                       secure_proxy_ssl_header=('X-HEADER', '1'),
                       headers=CIMultiDict({'X-HEADER': '1'}))
    assert "https" == req.scheme


def test_https_scheme_by_secure_proxy_ssl_header_false_test(make_request):
    req = make_request('GET', '/',
                       secure_proxy_ssl_header=('X-HEADER', '1'),
                       headers=CIMultiDict({'X-HEADER': '0'}))
    assert "http" == req.scheme


def test_raw_headers(make_request):
    req = make_request('GET', '/',
                       headers=CIMultiDict({'X-HEADER': 'aaa'}))
    assert req.raw_headers == ((b'X-Header', b'aaa'),)


def test_rel_url(make_request):
    req = make_request('GET', '/path')
    assert URL('/path') == req.rel_url


def test_url_url(make_request):
    req = make_request('GET', '/path', headers={'HOST': 'example.com'})
    assert URL('http://example.com/path') == req.url


def test_clone():
    req = make_mocked_request('GET', '/path')
    req2 = req.clone()
    assert req2.method == 'GET'
    assert req2.rel_url == URL('/path')


def test_clone_method():
    req = make_mocked_request('GET', '/path')
    req2 = req.clone(method='POST')
    assert req2.method == 'POST'
    assert req2.rel_url == URL('/path')


def test_clone_rel_url():
    req = make_mocked_request('GET', '/path')
    req2 = req.clone(rel_url=URL('/path2'))
    assert req2.rel_url == URL('/path2')


def test_clone_rel_url_str():
    req = make_mocked_request('GET', '/path')
    req2 = req.clone(rel_url='/path2')
    assert req2.rel_url == URL('/path2')


def test_clone_headers():
    req = make_mocked_request('GET', '/path', headers={'A': 'B'})
    req2 = req.clone(headers=CIMultiDict({'B': 'C'}))
    assert req2.headers == CIMultiDict({'B': 'C'})
    assert req2.raw_headers == ((b'B', b'C'),)


def test_clone_headers_dict():
    req = make_mocked_request('GET', '/path', headers={'A': 'B'})
    req2 = req.clone(headers={'B': 'C'})
    assert req2.headers == CIMultiDict({'B': 'C'})
    assert req2.raw_headers == ((b'B', b'C'),)


@asyncio.coroutine
def test_cannot_clone_after_read(loop):
    payload = StreamReader(loop=loop)
    payload.feed_data(b'data')
    payload.feed_eof()
    req = make_mocked_request('GET', '/path', payload=payload)
    yield from req.read()
    with pytest.raises(RuntimeError):
        req.clone()


@asyncio.coroutine
def test_make_too_big_request(loop):
    payload = StreamReader(loop=loop)
    large_file = 1024 ** 2 * b'x'
    too_large_file = large_file + b'x'
    payload.feed_data(too_large_file)
    payload.feed_eof()
    req = make_mocked_request('POST', '/', payload=payload)
    with pytest.raises(HTTPRequestEntityTooLarge) as err:
        yield from req.read()

    assert err.value.status_code == 413


@asyncio.coroutine
def test_make_too_big_request_adjust_limit(loop):
    payload = StreamReader(loop=loop)
    large_file = 1024 ** 2 * b'x'
    too_large_file = large_file + b'x'
    payload.feed_data(too_large_file)
    payload.feed_eof()
    max_size = 1024**2 + 2
    req = make_mocked_request('POST', '/', payload=payload,
                              client_max_size=max_size)
    txt = yield from req.read()
    assert len(txt) == 1024**2 + 1


@asyncio.coroutine
def test_make_too_big_request_limit_None(loop):
    payload = StreamReader(loop=loop)
    large_file = 1024 ** 2 * b'x'
    too_large_file = large_file + b'x'
    payload.feed_data(too_large_file)
    payload.feed_eof()
    max_size = None
    req = make_mocked_request('POST', '/', payload=payload,
                              client_max_size=max_size)
    txt = yield from req.read()
    assert len(txt) == 1024**2 + 1
