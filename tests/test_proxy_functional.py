import asyncio
import os
from unittest import mock

import pytest
from yarl import URL

import aiohttp
from aiohttp import web


@pytest.fixture
def proxy_test_server(raw_test_server, loop, monkeypatch):
    """Handle all proxy requests and imitate remote server response."""

    _patch_ssl_transport(monkeypatch)

    default_response = dict(
        status=200,
        headers=None,
        body=None)

    proxy_mock = mock.Mock()

    @asyncio.coroutine
    def proxy_handler(request):
        proxy_mock.request = request
        proxy_mock.requests_list.append(request)

        response = default_response.copy()
        if isinstance(proxy_mock.return_value, dict):
            response.update(proxy_mock.return_value)

        headers = response['headers']
        if not headers:
            headers = {}

        if request.method == 'CONNECT':
            response['body'] = None

        response['headers'] = headers

        resp = web.Response(**response)
        yield from resp.prepare(request)
        yield from resp.write_eof()
        return resp

    @asyncio.coroutine
    def proxy_server():
        proxy_mock.request = None
        proxy_mock.auth = None
        proxy_mock.requests_list = []

        server = yield from raw_test_server(proxy_handler)

        proxy_mock.server = server
        proxy_mock.url = server.make_url('/')

        return proxy_mock

    return proxy_server


@pytest.fixture()
def get_request(loop):
    @asyncio.coroutine
    def _request(method='GET', *, url, trust_env=False, **kwargs):
        connector = aiohttp.TCPConnector(verify_ssl=False, loop=loop)
        client = aiohttp.ClientSession(connector=connector,
                                       trust_env=trust_env)
        try:
            resp = yield from client.request(method, url, **kwargs)
            yield from resp.release()
            return resp
        finally:
            yield from client.close()
    return _request


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
def test_proxy_http_idna_support(proxy_test_server, get_request):
    url = 'http://éé.com/'
    raw_url = 'http://xn--9caa.com/'
    proxy = yield from proxy_test_server()

    yield from get_request(url=url, proxy=proxy.url)

    assert proxy.request.host == 'xn--9caa.com'
    assert proxy.request.path_qs == raw_url


@asyncio.coroutine
def test_proxy_http_connection_error(get_request):
    url = 'http://aiohttp.io/path'
    proxy_url = 'http://localhost:2242/'

    with pytest.raises(aiohttp.ClientConnectorError):
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

    auth = aiohttp.BasicAuth('user', 'pass')
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
    auth = aiohttp.BasicAuth('юзер', 'пасс', 'utf-8')
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
def test_proxy_http_acquired_cleanup(proxy_test_server, loop):
    url = 'http://aiohttp.io/path'

    conn = aiohttp.TCPConnector(loop=loop)
    sess = aiohttp.ClientSession(connector=conn, loop=loop)
    proxy = yield from proxy_test_server()

    assert 0 == len(conn._acquired)

    resp = yield from sess.get(url, proxy=proxy.url)
    assert resp.closed

    assert 0 == len(conn._acquired)

    sess.close()


@pytest.mark.skip('we need to reconsider how we test this')
@asyncio.coroutine
def test_proxy_http_acquired_cleanup_force(proxy_test_server, loop):
    url = 'http://aiohttp.io/path'

    conn = aiohttp.TCPConnector(force_close=True, loop=loop)
    sess = aiohttp.ClientSession(connector=conn, loop=loop)
    proxy = yield from proxy_test_server()

    assert 0 == len(conn._acquired)

    @asyncio.coroutine
    def request():
        resp = yield from sess.get(url, proxy=proxy.url)

        assert 1 == len(conn._acquired)

        yield from resp.release()

    yield from request()

    assert 0 == len(conn._acquired)

    yield from sess.close()


@pytest.mark.skip('we need to reconsider how we test this')
@asyncio.coroutine
def test_proxy_http_multi_conn_limit(proxy_test_server, loop):
    url = 'http://aiohttp.io/path'
    limit, multi_conn_num = 1, 5

    conn = aiohttp.TCPConnector(limit=limit, loop=loop)
    sess = aiohttp.ClientSession(connector=conn, loop=loop)
    proxy = yield from proxy_test_server()

    current_pid = None

    @asyncio.coroutine
    def request(pid):
        # process requests only one by one
        nonlocal current_pid

        resp = yield from sess.get(url, proxy=proxy.url)

        current_pid = pid
        yield from asyncio.sleep(0.2, loop=loop)
        assert current_pid == pid

        yield from resp.release()
        return resp

    requests = [request(pid) for pid in range(multi_conn_num)]
    responses = yield from asyncio.gather(*requests, loop=loop)

    assert len(responses) == multi_conn_num
    assert set(resp.status for resp in responses) == {200}

    yield from sess.close()


# @pytest.mark.xfail
@asyncio.coroutine
def xtest_proxy_https_connect(proxy_test_server, get_request):
    proxy = yield from proxy_test_server()
    url = 'https://www.google.com.ua/search?q=aiohttp proxy'

    yield from get_request(url=url, proxy=proxy.url)

    connect = proxy.requests_list[0]
    assert connect.method == 'CONNECT'
    assert connect.path == 'www.google.com.ua:443'
    assert connect.host == 'www.google.com.ua'

    assert proxy.request.host == 'www.google.com.ua'
    assert proxy.request.path_qs == '/search?q=aiohttp+proxy'


# @pytest.mark.xfail
@asyncio.coroutine
def xtest_proxy_https_connect_with_port(proxy_test_server, get_request):
    proxy = yield from proxy_test_server()
    url = 'https://secure.aiohttp.io:2242/path'

    yield from get_request(url=url, proxy=proxy.url)

    connect = proxy.requests_list[0]
    assert connect.method == 'CONNECT'
    assert connect.path == 'secure.aiohttp.io:2242'
    assert connect.host == 'secure.aiohttp.io:2242'

    assert proxy.request.host == 'secure.aiohttp.io:2242'
    assert proxy.request.path_qs == '/path'


# @pytest.mark.xfail
@asyncio.coroutine
def xtest_proxy_https_send_body(proxy_test_server, loop):
    sess = aiohttp.ClientSession(loop=loop)
    proxy = yield from proxy_test_server()
    proxy.return_value = {'status': 200, 'body': b'1'*(2**20)}
    url = 'https://www.google.com.ua/search?q=aiohttp proxy'

    resp = yield from sess.get(url, proxy=proxy.url)
    body = yield from resp.read()
    yield from resp.release()
    yield from sess.close()

    assert body == b'1'*(2**20)


# @pytest.mark.xfail
@asyncio.coroutine
def xtest_proxy_https_idna_support(proxy_test_server, get_request):
    url = 'https://éé.com/'
    proxy = yield from proxy_test_server()

    yield from get_request(url=url, proxy=proxy.url)

    connect = proxy.requests_list[0]
    assert connect.method == 'CONNECT'
    assert connect.path == 'xn--9caa.com:443'
    assert connect.host == 'xn--9caa.com'


@asyncio.coroutine
def test_proxy_https_connection_error(get_request):
    url = 'https://secure.aiohttp.io/path'
    proxy_url = 'http://localhost:2242/'

    with pytest.raises(aiohttp.ClientConnectorError):
        yield from get_request(url=url, proxy=proxy_url)


@asyncio.coroutine
def test_proxy_https_bad_response(proxy_test_server, get_request):
    url = 'https://secure.aiohttp.io/path'
    proxy = yield from proxy_test_server()
    proxy.return_value = dict(
        status=502,
        headers={'Proxy-Agent': 'TestProxy'})

    with pytest.raises(aiohttp.ClientHttpProxyError):
        yield from get_request(url=url, proxy=proxy.url)

    assert len(proxy.requests_list) == 1
    assert proxy.request.method == 'CONNECT'
    assert proxy.request.path == 'secure.aiohttp.io:443'


# @pytest.mark.xfail
@asyncio.coroutine
def xtest_proxy_https_auth(proxy_test_server, get_request):
    url = 'https://secure.aiohttp.io/path'
    auth = aiohttp.BasicAuth('user', 'pass')

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


# @pytest.mark.xfail
@asyncio.coroutine
def xtest_proxy_https_acquired_cleanup(proxy_test_server, loop):
    url = 'https://secure.aiohttp.io/path'

    conn = aiohttp.TCPConnector(loop=loop)
    sess = aiohttp.ClientSession(connector=conn, loop=loop)
    proxy = yield from proxy_test_server()

    assert 0 == len(conn._acquired)

    @asyncio.coroutine
    def request():
        resp = yield from sess.get(url, proxy=proxy.url)

        assert 1 == len(conn._acquired)

        yield from resp.release()

    yield from request()

    assert 0 == len(conn._acquired)

    yield from sess.close()


# @pytest.mark.xfail
@asyncio.coroutine
def xtest_proxy_https_acquired_cleanup_force(proxy_test_server, loop):
    url = 'https://secure.aiohttp.io/path'

    conn = aiohttp.TCPConnector(force_close=True, loop=loop)
    sess = aiohttp.ClientSession(connector=conn, loop=loop)
    proxy = yield from proxy_test_server()

    assert 0 == len(conn._acquired)

    @asyncio.coroutine
    def request():
        resp = yield from sess.get(url, proxy=proxy.url)

        assert 1 == len(conn._acquired)

        yield from resp.release()

    yield from request()

    assert 0 == len(conn._acquired)

    yield from sess.close()


# @pytest.mark.xfail
@asyncio.coroutine
def xtest_proxy_https_multi_conn_limit(proxy_test_server, loop):
    url = 'https://secure.aiohttp.io/path'
    limit, multi_conn_num = 1, 5

    conn = aiohttp.TCPConnector(limit=limit, loop=loop)
    sess = aiohttp.ClientSession(connector=conn, loop=loop)
    proxy = yield from proxy_test_server()

    current_pid = None

    @asyncio.coroutine
    def request(pid):
        # process requests only one by one
        nonlocal current_pid

        resp = yield from sess.get(url, proxy=proxy.url)

        current_pid = pid
        yield from asyncio.sleep(0.2, loop=loop)
        assert current_pid == pid

        yield from resp.release()
        return resp

    requests = [request(pid) for pid in range(multi_conn_num)]
    responses = yield from asyncio.gather(*requests, loop=loop)

    assert len(responses) == multi_conn_num
    assert set(resp.status for resp in responses) == {200}

    yield from sess.close()


def _patch_ssl_transport(monkeypatch):
    """Make ssl transport substitution to prevent ssl handshake."""
    def _make_ssl_transport_dummy(self, rawsock, protocol, sslcontext,
                                  waiter=None, **kwargs):
        return self._make_socket_transport(rawsock, protocol, waiter,
                                           extra=kwargs.get('extra'),
                                           server=kwargs.get('server'))

    monkeypatch.setattr(
        "asyncio.selector_events.BaseSelectorEventLoop._make_ssl_transport",
        _make_ssl_transport_dummy)


@asyncio.coroutine
def test_proxy_from_env_http(proxy_test_server, get_request, mocker):
    url = 'http://aiohttp.io/path'
    proxy = yield from proxy_test_server()
    mocker.patch.dict(os.environ, {'http_proxy': str(proxy.url)})

    yield from get_request(url=url, trust_env=True)

    assert len(proxy.requests_list) == 1
    assert proxy.request.method == 'GET'
    assert proxy.request.host == 'aiohttp.io'
    assert proxy.request.path_qs == 'http://aiohttp.io/path'
    assert 'Proxy-Authorization' not in proxy.request.headers


@asyncio.coroutine
def test_proxy_from_env_http_with_auth(proxy_test_server, get_request, mocker):
    url = 'http://aiohttp.io/path'
    proxy = yield from proxy_test_server()
    auth = aiohttp.BasicAuth('user', 'pass')
    mocker.patch.dict(os.environ, {'http_proxy':
                                   str(proxy.url
                                       .with_user(auth.login)
                                       .with_password(auth.password))})

    yield from get_request(url=url, trust_env=True)

    assert len(proxy.requests_list) == 1
    assert proxy.request.method == 'GET'
    assert proxy.request.host == 'aiohttp.io'
    assert proxy.request.path_qs == 'http://aiohttp.io/path'
    assert proxy.request.headers['Proxy-Authorization'] == auth.encode()


@asyncio.coroutine
def xtest_proxy_from_env_https(proxy_test_server, get_request, mocker):
    url = 'https://aiohttp.io/path'
    proxy = yield from proxy_test_server()
    mocker.patch.dict(os.environ, {'https_proxy': str(proxy.url)})

    yield from get_request(url=url, trust_env=True)

    assert len(proxy.requests_list) == 2
    assert proxy.request.method == 'GET'
    assert proxy.request.host == 'aiohttp.io'
    assert proxy.request.path_qs == 'https://aiohttp.io/path'
    assert 'Proxy-Authorization' not in proxy.request.headers


@asyncio.coroutine
def xtest_proxy_from_env_https_with_auth(proxy_test_server,
                                         get_request, mocker):
    url = 'https://aiohttp.io/path'
    proxy = yield from proxy_test_server()
    auth = aiohttp.BasicAuth('user', 'pass')
    mocker.patch.dict(os.environ, {'https_proxy':
                                   str(proxy.url
                                       .with_user(auth.login)
                                       .with_password(auth.password))})

    yield from get_request(url=url, trust_env=True)

    assert len(proxy.requests_list) == 2

    assert proxy.request.method == 'GET'
    assert proxy.request.host == 'aiohttp.io'
    assert proxy.request.path_qs == '/path'
    assert 'Proxy-Authorization' not in proxy.request.headers

    r2 = proxy.requests_list[0]
    assert r2.method == 'CONNECT'
    assert r2.host == 'aiohttp.io'
    assert r2.path_qs == '/path'
    assert r2.headers['Proxy-Authorization'] == auth.encode()
