from unittest import mock

import pytest

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

    async def proxy_handler(request):
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
        await resp.prepare(request)
        await resp.write_eof()
        return resp

    async def proxy_server():
        proxy_mock.request = None
        proxy_mock.auth = None
        proxy_mock.requests_list = []

        server = await raw_test_server(proxy_handler)

        proxy_mock.server = server
        proxy_mock.url = server.make_url('/')

        return proxy_mock

    return proxy_server


@pytest.fixture()
def get_request(loop):
    async def _request(method='GET', *, url, trust_env=False, **kwargs):
        connector = aiohttp.TCPConnector(verify_ssl=False, loop=loop)
        client = aiohttp.ClientSession(connector=connector,
                                       trust_env=trust_env)
        try:
            resp = await client.request(method, url, **kwargs)
            await resp.release()
            return resp
        finally:
            await client.close()
    return _request


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


async def test_session_proxy_http(proxy_test_server, loop):
    url = 'http://aiohttp.io/path'
    proxy = await proxy_test_server()
    proxy.return_value = dict(body=b'test')

    conn = aiohttp.TCPConnector(loop=loop)
    sess = aiohttp.ClientSession(connector=conn, loop=loop, proxy=proxy.url)

    resp = await sess.get(url)
    assert (await resp.read()) == b'test'


async def test_session_proxy_http_auth(proxy_test_server, loop):
    url = 'http://aiohttp.io/path'
    proxy = await proxy_test_server()

    conn = aiohttp.TCPConnector(loop=loop)
    sess = aiohttp.ClientSession(connector=conn, loop=loop, proxy=proxy.url)
    await sess.get(url)
    assert 'Authorization' not in proxy.request.headers
    assert 'Proxy-Authorization' not in proxy.request.headers

    conn = aiohttp.TCPConnector(loop=loop)
    auth = aiohttp.BasicAuth('user', 'pass')
    sess = aiohttp.ClientSession(connector=conn, loop=loop,
                                 proxy_auth=auth, proxy=proxy.url)
    await sess.get(url)
    assert 'Authorization' not in proxy.request.headers
    assert 'Proxy-Authorization' in proxy.request.headers

    conn = aiohttp.TCPConnector(loop=loop)
    auth = aiohttp.BasicAuth('user', 'pass')
    sess = aiohttp.ClientSession(connector=conn, loop=loop,
                                 auth=auth, proxy_auth=auth, proxy=proxy.url)
    await sess.get(url)
    assert 'Authorization' in proxy.request.headers
    assert 'Proxy-Authorization' in proxy.request.headers
