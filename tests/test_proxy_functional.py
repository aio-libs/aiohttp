import asyncio
from functools import partial
from unittest import mock

import pytest
from yarl import URL

import aiohttp
import aiohttp.helpers
import aiohttp.web


@pytest.fixture
def proxy_test_server(raw_test_server, loop, monkeypatch):
    """Handle all proxy requests and imitate remote server response."""

    _patch_ssl_transport(monkeypatch)

    default_response = dict(
        status=200,
        headers=None,
        body=None)

    @asyncio.coroutine
    def proxy_handler(request, proxy_mock):
        proxy_mock.request = request
        proxy_mock.requests_list.append(request)

        response = default_response.copy()
        if isinstance(proxy_mock.return_value, dict):
            response.update(proxy_mock.return_value)

        return aiohttp.web.Response(**response)

    @asyncio.coroutine
    def proxy_server():
        proxy_mock = mock.Mock()
        proxy_mock.request = None
        proxy_mock.requests_list = []

        handler = partial(proxy_handler, proxy_mock=proxy_mock)
        server = yield from raw_test_server(handler)

        proxy_mock.server = server
        proxy_mock.url = server.make_url('/')

        return proxy_mock

    return proxy_server


@asyncio.coroutine
def _request(method, url, loop=None, **kwargs):
    with aiohttp.ClientSession(loop=loop) as client:
        resp = yield from client.request(method, url, **kwargs)
        yield from resp.release()
        return resp


@pytest.fixture()
def get_request(loop):
    return partial(_request, method='GET', loop=loop)


@asyncio.coroutine
def test_proxy_http_absolute_path(proxy_test_server, get_request):
    url = 'http://aiohttp.io/path?query=yes'
    proxy = yield from proxy_test_server()

    yield from get_request(url=url, proxy=proxy.url)

    assert len(proxy.requests_list) == 1
    assert proxy.request.method == 'GET'
    assert proxy.request.host == 'aiohttp.io'
    assert proxy.request.path_qs == 'http://aiohttp.io/path?query=yes'


@asyncio.coroutine
def test_proxy_http_raw_path(proxy_test_server, get_request):
    url = 'http://aiohttp.io:2561/space sheep?q=can:fly'
    raw_url = 'http://aiohttp.io:2561/space%20sheep?q=can:fly'
    proxy = yield from proxy_test_server()

    yield from get_request(url=url, proxy=proxy.url)

    assert proxy.request.host == 'aiohttp.io:2561'
    assert proxy.request.path_qs == raw_url


@asyncio.coroutine
def test_proxy_http_connection_error(get_request):
    url = 'http://aiohttp.io/path'
    proxy_url = 'http://localhost:2242/'

    with pytest.raises(aiohttp.ProxyConnectionError):
        yield from get_request(url=url, proxy=proxy_url)


@asyncio.coroutine
def test_proxy_http_bad_response(proxy_test_server, get_request):
    url = 'http://aiohttp.io/path'
    proxy = yield from proxy_test_server()
    proxy.return_value = dict(
        status=502,
        headers={'Proxy-Agent': 'TestProxy'})

    resp = yield from get_request(url=url, proxy=proxy.url)

    assert resp.status == 502
    assert resp.headers['Proxy-Agent'] == 'TestProxy'


@asyncio.coroutine
def test_proxy_http_auth(proxy_test_server, get_request):
    url = 'http://aiohttp.io/path'
    proxy = yield from proxy_test_server()

    yield from get_request(url=url, proxy=proxy.url)

    assert 'Authorization' not in proxy.request.headers
    assert 'Proxy-Authorization' not in proxy.request.headers

    auth = aiohttp.helpers.BasicAuth('user', 'pass')
    yield from get_request(url=url, auth=auth, proxy=proxy.url)

    assert 'Authorization' in proxy.request.headers
    assert 'Proxy-Authorization' not in proxy.request.headers

    yield from get_request(url=url, proxy_auth=auth, proxy=proxy.url)

    assert 'Authorization' not in proxy.request.headers
    assert 'Proxy-Authorization' in proxy.request.headers

    yield from get_request(url=url, auth=auth,
                           proxy_auth=auth, proxy=proxy.url)

    assert 'Authorization' in proxy.request.headers
    assert 'Proxy-Authorization' in proxy.request.headers


@asyncio.coroutine
def test_proxy_http_auth_utf8(proxy_test_server, get_request):
    url = 'http://aiohttp.io/path'
    auth = aiohttp.helpers.BasicAuth('юзер', 'пасс', 'utf-8')
    proxy = yield from proxy_test_server()

    yield from get_request(url=url, auth=auth, proxy=proxy.url)

    assert 'Authorization' in proxy.request.headers
    assert 'Proxy-Authorization' not in proxy.request.headers


@asyncio.coroutine
def test_proxy_http_auth_from_url(proxy_test_server, get_request):
    url = 'http://aiohttp.io/path'
    proxy = yield from proxy_test_server()

    auth_url = URL(url).with_user('user').with_password('pass')
    yield from get_request(url=auth_url, proxy=proxy.url)

    assert 'Authorization' in proxy.request.headers
    assert 'Proxy-Authorization' not in proxy.request.headers

    proxy_url = URL(proxy.url).with_user('user').with_password('pass')
    yield from get_request(url=url, proxy=proxy_url)

    assert 'Authorization' not in proxy.request.headers
    assert 'Proxy-Authorization' in proxy.request.headers


@asyncio.coroutine
def test_proxy_https_connect(proxy_test_server, get_request):
    proxy = yield from proxy_test_server()
    url = 'https://www.google.com.ua/search?q=aiohttp proxy'

    yield from get_request(url=url, proxy=proxy.url)

    connect = proxy.requests_list[0]
    assert connect.method == 'CONNECT'
    assert connect.path == 'www.google.com.ua:443'
    assert connect.host == 'www.google.com.ua'

    assert proxy.request.host == 'www.google.com.ua'
    assert proxy.request.path_qs == '/search?q=aiohttp+proxy'


@asyncio.coroutine
def test_proxy_https_connect_with_port(proxy_test_server, get_request):
    proxy = yield from proxy_test_server()
    url = 'https://secure.aiohttp.io:2242/path'

    yield from get_request(url=url, proxy=proxy.url)

    connect = proxy.requests_list[0]
    assert connect.method == 'CONNECT'
    assert connect.path == 'secure.aiohttp.io:2242'
    assert connect.host == 'secure.aiohttp.io:2242'

    assert proxy.request.host == 'secure.aiohttp.io:2242'
    assert proxy.request.path_qs == '/path'


@asyncio.coroutine
def test_proxy_https_connection_error(get_request):
    url = 'https://secure.aiohttp.io/path'
    proxy_url = 'http://localhost:2242/'

    with pytest.raises(aiohttp.ProxyConnectionError):
        yield from get_request(url=url, proxy=proxy_url)


@asyncio.coroutine
def test_proxy_https_bad_response(proxy_test_server, get_request):
    url = 'https://secure.aiohttp.io/path'
    proxy = yield from proxy_test_server()
    proxy.return_value = dict(
        status=502,
        headers={'Proxy-Agent': 'TestProxy'})

    with pytest.raises(aiohttp.HttpProxyError):
        yield from get_request(url=url, proxy=proxy.url)

    assert len(proxy.requests_list) == 1
    assert proxy.request.method == 'CONNECT'
    assert proxy.request.path == 'secure.aiohttp.io:443'


@asyncio.coroutine
def test_proxy_https_auth(proxy_test_server, get_request):
    url = 'https://secure.aiohttp.io/path'
    auth = aiohttp.helpers.BasicAuth('user', 'pass')

    proxy = yield from proxy_test_server()
    yield from get_request(url=url, proxy=proxy.url)

    connect = proxy.requests_list[0]
    assert 'Authorization' not in connect.headers
    assert 'Proxy-Authorization' not in connect.headers
    assert 'Authorization' not in proxy.request.headers
    assert 'Proxy-Authorization' not in proxy.request.headers

    proxy = yield from proxy_test_server()
    yield from get_request(url=url, auth=auth, proxy=proxy.url)

    connect = proxy.requests_list[0]
    assert 'Authorization' not in connect.headers
    assert 'Proxy-Authorization' not in connect.headers
    assert 'Authorization' in proxy.request.headers
    assert 'Proxy-Authorization' not in proxy.request.headers

    proxy = yield from proxy_test_server()
    yield from get_request(url=url, proxy_auth=auth, proxy=proxy.url)

    connect = proxy.requests_list[0]
    assert 'Authorization' not in connect.headers
    assert 'Proxy-Authorization' in connect.headers
    assert 'Authorization' not in proxy.request.headers
    assert 'Proxy-Authorization' not in proxy.request.headers

    proxy = yield from proxy_test_server()
    yield from get_request(url=url, auth=auth,
                           proxy_auth=auth, proxy=proxy.url)

    connect = proxy.requests_list[0]
    assert 'Authorization' not in connect.headers
    assert 'Proxy-Authorization' in connect.headers
    assert 'Authorization' in proxy.request.headers
    assert 'Proxy-Authorization' not in proxy.request.headers


def _patch_ssl_transport(monkeypatch):
    """Make ssl transport substitution to prevent ssl handshake."""
    def _make_ssl_transport_dummy(self, rawsock, protocol, sslcontext,
                                  waiter=None, **kwargs):
        return self._make_socket_transport(rawsock, protocol, waiter)

    monkeypatch.setattr(
        "asyncio.selector_events.BaseSelectorEventLoop._make_ssl_transport",
        _make_ssl_transport_dummy)
