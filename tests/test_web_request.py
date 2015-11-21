import pytest
from unittest import mock
from aiohttp.signals import Signal
from aiohttp.web import Request
from aiohttp.multidict import MultiDict, CIMultiDict
from aiohttp.protocol import HttpVersion
from aiohttp.protocol import RawRequestMessage


@pytest.fixture
def make_request():
    def maker(method, path, headers=CIMultiDict(), *,
              version=HttpVersion(1, 1), closing=False,
              sslcontext=None,
              secure_proxy_ssl_header=None):
        if version < HttpVersion(1, 1):
            closing = True
        app = mock.Mock()
        app._debug = False
        app.on_response_prepare = Signal(app)
        message = RawRequestMessage(method, path, version, headers, closing,
                                    False)
        payload = mock.Mock()
        transport = mock.Mock()

        def get_extra_info(key):
            if key == 'sslcontext':
                return sslcontext
            else:
                return None

        transport.get_extra_info.side_effect = get_extra_info
        writer = mock.Mock()
        reader = mock.Mock()
        req = Request(app, message, payload,
                      transport, reader, writer,
                      secure_proxy_ssl_header=secure_proxy_ssl_header)

        assert req.app is app
        assert req.content is payload
        assert req.transport is transport

        return req
    return maker


def test_ctor(make_request, warning):
    req = make_request('GET', '/path/to?a=1&b=2')

    assert 'GET' == req.method
    assert HttpVersion(1, 1) == req.version
    assert req.host is None
    assert '/path/to?a=1&b=2' == req.path_qs
    assert '/path/to' == req.path
    assert 'a=1&b=2' == req.query_string

    get = req.GET
    assert MultiDict([('a', '1'), ('b', '2')]) == get
    # second call should return the same object
    assert get is req.GET

    with warning(DeprecationWarning):
        req.payload

    assert req.keep_alive


def test_doubleslashes(make_request):
    req = make_request('GET', '//foo/')
    assert '//foo/' == req.path


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


@pytest.mark.run_loop
def test_call_POST_on_GET_request(make_request):
    req = make_request('GET', '/')

    ret = yield from req.post()
    assert CIMultiDict() == ret


@pytest.mark.run_loop
def test_call_POST_on_weird_content_type(make_request):
    req = make_request(
        'POST', '/',
        headers=CIMultiDict({'CONTENT-TYPE': 'something/weird'}))

    ret = yield from req.post()
    assert CIMultiDict() == ret


@pytest.mark.run_loop
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
    assert req.match_info is None
    match = {'a': 'b'}
    req._match_info = match
    assert match is req.match_info


def test_request_is_dict(make_request):
    req = make_request('GET', '/')
    assert isinstance(req, dict)
    req['key'] = 'value'
    assert 'value' == req['key']


def test_copy(make_request):
    req = make_request('GET', '/')
    with pytest.raises(NotImplementedError):
        req.copy()


def test___repr__(make_request):
    req = make_request('GET', '/path/to')
    assert "<Request GET /path/to >" == repr(req)


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
