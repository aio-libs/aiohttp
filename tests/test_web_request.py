import asyncio
from collections import MutableMapping
from unittest import mock

import pytest
from multidict import CIMultiDict, MultiDict
from yarl import URL

from aiohttp import HttpVersion
from aiohttp.streams import StreamReader
from aiohttp.test_utils import make_mocked_request
from aiohttp.web import HTTPRequestEntityTooLarge


def test_ctor():
    req = make_mocked_request('GET', '/path/to?a=1&b=2')

    assert 'GET' == req.method
    assert HttpVersion(1, 1) == req.version
    assert req.host is None
    assert '/path/to?a=1&b=2' == req.path_qs
    assert '/path/to' == req.path
    assert 'a=1&b=2' == req.query_string
    assert CIMultiDict() == req.headers
    assert () == req.raw_headers
    assert req.message == req._message

    get = req.query
    assert MultiDict([('a', '1'), ('b', '2')]) == get
    # second call should return the same object
    assert get is req.query

    assert req.keep_alive

    # just make sure that all lines of make_mocked_request covered
    headers = CIMultiDict(FOO='bar')
    payload = mock.Mock()
    protocol = mock.Mock()
    app = mock.Mock()
    req = make_mocked_request('GET', '/path/to?a=1&b=2', headers=headers,
                              protocol=protocol, payload=payload, app=app)
    assert req.app is app
    assert req.content is payload
    assert req.protocol is protocol
    assert req.transport is protocol.transport
    assert req.headers == headers
    assert req.raw_headers == ((b'FOO', b'bar'),)
    assert req.task is req._task

    with pytest.warns(DeprecationWarning):
        assert req.GET is req.query


def test_doubleslashes():
    # NB: //foo/bar is an absolute URL with foo netloc and /bar path
    req = make_mocked_request('GET', '/bar//foo/')
    assert '/bar//foo/' == req.path


def test_content_type_not_specified():
    req = make_mocked_request('Get', '/')
    assert 'application/octet-stream' == req.content_type


def test_content_type_from_spec():
    req = make_mocked_request('Get', '/',
                              CIMultiDict([('CONTENT-TYPE',
                                            'application/json')]))
    assert 'application/json' == req.content_type


def test_content_type_from_spec_with_charset():
    req = make_mocked_request(
        'Get', '/',
        CIMultiDict([('CONTENT-TYPE', 'text/html; charset=UTF-8')]))
    assert 'text/html' == req.content_type
    assert 'UTF-8' == req.charset


def test_calc_content_type_on_getting_charset():
    req = make_mocked_request(
        'Get', '/',
        CIMultiDict([('CONTENT-TYPE', 'text/html; charset=UTF-8')]))
    assert 'UTF-8' == req.charset
    assert 'text/html' == req.content_type


def test_urlencoded_querystring():
    req = make_mocked_request(
        'GET', '/yandsearch?text=%D1%82%D0%B5%D0%BA%D1%81%D1%82')
    assert {'text': 'текст'} == req.query


def test_non_ascii_path():
    req = make_mocked_request('GET', '/путь')
    assert '/путь' == req.path


def test_non_ascii_raw_path():
    req = make_mocked_request('GET', '/путь')
    assert '/путь' == req.raw_path


def test_content_length():
    req = make_mocked_request('Get', '/',
                              CIMultiDict([('CONTENT-LENGTH', '123')]))

    assert 123 == req.content_length


def test_non_keepalive_on_http10():
    req = make_mocked_request('GET', '/', version=HttpVersion(1, 0))
    assert not req.keep_alive


def test_non_keepalive_on_closing():
    req = make_mocked_request('GET', '/', closing=True)
    assert not req.keep_alive


@asyncio.coroutine
def test_call_POST_on_GET_request():
    req = make_mocked_request('GET', '/')

    ret = yield from req.post()
    assert CIMultiDict() == ret


@asyncio.coroutine
def test_call_POST_on_weird_content_type():
    req = make_mocked_request(
        'POST', '/',
        headers=CIMultiDict({'CONTENT-TYPE': 'something/weird'}))

    ret = yield from req.post()
    assert CIMultiDict() == ret


@asyncio.coroutine
def test_call_POST_twice():
    req = make_mocked_request('GET', '/')

    ret1 = yield from req.post()
    ret2 = yield from req.post()
    assert ret1 is ret2


def test_no_request_cookies():
    req = make_mocked_request('GET', '/')

    assert req.cookies == {}

    cookies = req.cookies
    assert cookies is req.cookies


def test_request_cookie():
    headers = CIMultiDict(COOKIE='cookie1=value1; cookie2=value2')
    req = make_mocked_request('GET', '/', headers=headers)

    assert req.cookies == {'cookie1': 'value1',
                           'cookie2': 'value2'}


def test_request_cookie__set_item():
    headers = CIMultiDict(COOKIE='name=value')
    req = make_mocked_request('GET', '/', headers=headers)

    assert req.cookies == {'name': 'value'}

    with pytest.raises(TypeError):
        req.cookies['my'] = 'value'


def test_match_info():
    req = make_mocked_request('GET', '/')
    assert req._match_info is req.match_info


def test_request_is_mutable_mapping():
    req = make_mocked_request('GET', '/')
    assert isinstance(req, MutableMapping)
    req['key'] = 'value'
    assert 'value' == req['key']


def test_request_delitem():
    req = make_mocked_request('GET', '/')
    req['key'] = 'value'
    assert 'value' == req['key']
    del req['key']
    assert 'key' not in req


def test_request_len():
    req = make_mocked_request('GET', '/')
    assert len(req) == 0
    req['key'] = 'value'
    assert len(req) == 1


def test_request_iter():
    req = make_mocked_request('GET', '/')
    req['key'] = 'value'
    req['key2'] = 'value2'
    assert set(req) == {'key', 'key2'}


def test___repr__():
    req = make_mocked_request('GET', '/path/to')
    assert "<Request GET /path/to >" == repr(req)


def test___repr___non_ascii_path():
    req = make_mocked_request('GET', '/path/\U0001f415\U0001f308')
    assert "<Request GET /path/\\U0001f415\\U0001f308 >" == repr(req)


def test_http_scheme():
    req = make_mocked_request('GET', '/')
    assert "http" == req.scheme
    assert req.secure is False


def test_https_scheme_by_ssl_transport():
    req = make_mocked_request('GET', '/', sslcontext=True)
    assert "https" == req.scheme
    assert req.secure is True


def test_https_scheme_by_secure_proxy_ssl_header():
    req = make_mocked_request('GET', '/',
                              secure_proxy_ssl_header=('X-HEADER', '1'),
                              headers=CIMultiDict({'X-HEADER': '1'}))
    assert "https" == req.scheme
    assert req.secure is True


def test_https_scheme_by_secure_proxy_ssl_header_false_test():
    req = make_mocked_request('GET', '/',
                              secure_proxy_ssl_header=('X-HEADER', '1'),
                              headers=CIMultiDict({'X-HEADER': '0'}))
    assert "http" == req.scheme
    assert req.secure is False


def test_single_forwarded_header():
    header = 'by=identifier;for=identifier;host=identifier;proto=identifier'
    req = make_mocked_request('GET', '/',
                              headers=CIMultiDict({'Forwarded': header}))
    assert req.forwarded[0]['by'] == 'identifier'
    assert req.forwarded[0]['for'] == 'identifier'
    assert req.forwarded[0]['host'] == 'identifier'
    assert req.forwarded[0]['proto'] == 'identifier'


def test_single_forwarded_header_camelcase():
    header = 'bY=identifier;fOr=identifier;HOst=identifier;pRoTO=identifier'
    req = make_mocked_request('GET', '/',
                              headers=CIMultiDict({'Forwarded': header}))
    assert req.forwarded[0]['by'] == 'identifier'
    assert req.forwarded[0]['for'] == 'identifier'
    assert req.forwarded[0]['host'] == 'identifier'
    assert req.forwarded[0]['proto'] == 'identifier'


def test_single_forwarded_header_single_param():
    header = 'BY=identifier'
    req = make_mocked_request('GET', '/',
                              headers=CIMultiDict({'Forwarded': header}))
    assert req.forwarded[0]['by'] == 'identifier'


def test_single_forwarded_header_multiple_param():
    header = 'By=identifier1,BY=identifier2,  By=identifier3 ,  BY=identifier4'
    req = make_mocked_request('GET', '/',
                              headers=CIMultiDict({'Forwarded': header}))
    assert len(req.forwarded) == 4
    assert req.forwarded[0]['by'] == 'identifier1'
    assert req.forwarded[1]['by'] == 'identifier2'
    assert req.forwarded[2]['by'] == 'identifier3'
    assert req.forwarded[3]['by'] == 'identifier4'


def test_single_forwarded_header_quoted_escaped():
    header = 'BY=identifier;pROTO="\lala lan\d\~ 123\!&"'
    req = make_mocked_request('GET', '/',
                              headers=CIMultiDict({'Forwarded': header}))
    assert req.forwarded[0]['by'] == 'identifier'
    assert req.forwarded[0]['proto'] == 'lala land~ 123!&'


def test_multiple_forwarded_headers():
    headers = CIMultiDict()
    headers.add('Forwarded', 'By=identifier1;for=identifier2, BY=identifier3')
    headers.add('Forwarded', 'By=identifier4;fOr=identifier5')
    req = make_mocked_request('GET', '/', headers=headers)
    assert len(req.forwarded) == 3
    assert req.forwarded[0]['by'] == 'identifier1'
    assert req.forwarded[0]['for'] == 'identifier2'
    assert req.forwarded[1]['by'] == 'identifier3'
    assert req.forwarded[2]['by'] == 'identifier4'
    assert req.forwarded[2]['for'] == 'identifier5'


def test_https_scheme_by_forwarded_header():
    req = make_mocked_request('GET', '/',
                              headers=CIMultiDict(
                                  {'Forwarded': 'by=;for=;host=;proto=https'}))
    assert "https" == req.scheme
    assert req.secure is True


def test_https_scheme_by_malformed_forwarded_header():
    req = make_mocked_request('GET', '/',
                              headers=CIMultiDict({'Forwarded':
                                                   'malformed value'}))
    assert "http" == req.scheme
    assert req.secure is False


def test_https_scheme_by_x_forwarded_proto_header():
    req = make_mocked_request('GET', '/',
                              headers=CIMultiDict({'X-Forwarded-Proto':
                                                   'https'}))
    assert "https" == req.scheme
    assert req.secure is True


def test_https_scheme_by_x_forwarded_proto_header_no_tls():
    req = make_mocked_request('GET', '/',
                              headers=CIMultiDict({'X-Forwarded-Proto':
                                                   'http'}))
    assert "http" == req.scheme
    assert req.secure is False


def test_host_by_forwarded_header():
    headers = CIMultiDict()
    headers.add('Forwarded', 'By=identifier1;for=identifier2, BY=identifier3')
    headers.add('Forwarded', 'by=;for=;host=example.com')
    req = make_mocked_request('GET', '/', headers=headers)
    assert req.host == 'example.com'


def test_host_by_forwarded_header_malformed():
    req = make_mocked_request('GET', '/',
                              headers=CIMultiDict({'Forwarded':
                                                   'malformed value'}))
    assert req.host is None


def test_host_by_x_forwarded_host_header():
    req = make_mocked_request('GET', '/',
                              headers=CIMultiDict(
                                  {'X-Forwarded-Host': 'example.com'}))
    assert req.host == 'example.com'


def test_host_by_host_header():
    req = make_mocked_request('GET', '/',
                              headers=CIMultiDict({'Host': 'example.com'}))
    assert req.host == 'example.com'


def test_raw_headers():
    req = make_mocked_request('GET', '/',
                              headers=CIMultiDict({'X-HEADER': 'aaa'}))
    assert req.raw_headers == ((b'X-HEADER', b'aaa'),)


def test_rel_url():
    req = make_mocked_request('GET', '/path')
    assert URL('/path') == req.rel_url


def test_url_url():
    req = make_mocked_request('GET', '/path', headers={'HOST': 'example.com'})
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
def test_multipart_formdata(loop):
    payload = StreamReader(loop=loop)
    payload.feed_data(b"""-----------------------------326931944431359\r
Content-Disposition: form-data; name="a"\r
\r
b\r
-----------------------------326931944431359\r
Content-Disposition: form-data; name="c"\r
\r
d\r
-----------------------------326931944431359--\r\n""")
    content_type = "multipart/form-data; boundary="\
                   "---------------------------326931944431359"
    payload.feed_eof()
    req = make_mocked_request('POST', '/',
                              headers={'CONTENT-TYPE': content_type},
                              payload=payload)
    result = yield from req.post()
    assert dict(result) == {'a': 'b', 'c': 'd'}


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


def test_remote_peername_tcp():
    transp = mock.Mock()
    transp.get_extra_info.return_value = ('10.10.10.10', 1234)
    req = make_mocked_request('GET', '/', transport=transp)
    assert req.remote == '10.10.10.10'


def test_remote_peername_unix():
    transp = mock.Mock()
    transp.get_extra_info.return_value = '/path/to/sock'
    req = make_mocked_request('GET', '/', transport=transp)
    assert req.remote == '/path/to/sock'


def test_remote_peername_x_forwarded():
    transp = mock.Mock()
    transp.get_extra_info.return_value = ('10.10.10.10', 1234)
    req = make_mocked_request(
        'GET', '/', transport=transp,
        headers={'X-Forwarded-For': '11.11.11.11, 12.12.12.12'})
    assert req.remote == '11.11.11.11'


def test_remote_peername_forwarded():
    transp = mock.Mock()
    transp.get_extra_info.return_value = ('10.10.10.10', 1234)
    req = make_mocked_request(
        'GET', '/', transport=transp,
        headers={'Forwarded': 'for=11.11.11.11, for=12.12.12.12'})
    assert req.remote == '11.11.11.11'


def test_remote_peername_forwarded_overrides_x_forwarded():
    transp = mock.Mock()
    transp.get_extra_info.return_value = ('10.10.10.10', 1234)
    req = make_mocked_request(
        'GET', '/', transport=transp,
        headers={'Forwarded': 'for=11.11.11.11, for=12.12.12.12',
                 'X-Forwarded-For': '13.13.13.13'})
    assert req.remote == '11.11.11.11'
