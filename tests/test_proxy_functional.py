import asyncio
import os
import socket
import ssl
import struct
from unittest import mock

import pytest
from yarl import URL

import aiohttp
from aiohttp import web
from aiohttp.test_utils import RawTestServer, unused_port


try:
    import aiosocks
except ImportError:
    aiosocks = None


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


class FakeSocks4Srv:
    def __init__(self, loop):
        self._loop = loop
        self._retranslators = []
        self._writers = []
        self._srv = None
        self.port = unused_port()

    async def negotiate(self, reader, writer):
        writer.write(b'\x00\x5a\x04W\x01\x01\x01\x01')
        data = await reader.readexactly(9)

        dst_port = struct.unpack('>H', data[2:4])[0]
        dst_addr = socket.inet_ntoa(data[4:8])

        cl_reader, cl_writer = await asyncio.open_connection(
            host=dst_addr, port=dst_port, loop=self._loop)
        self._writers.append(cl_writer)

        cl_fut = asyncio.ensure_future(
            self.retranslate(reader, cl_writer), loop=self._loop)
        dst_fut = asyncio.ensure_future(
            self.retranslate(cl_reader, writer), loop=self._loop)

        self._retranslators += [cl_fut, dst_fut]

    async def retranslate(self, reader, writer):
        while True:
            try:
                bytes = await reader.read(10)
                if not bytes:
                    break
                writer.write(bytes)
                await writer.drain()
            except:  # noqa
                break

    async def start_server(self):
        class Socks4Protocol(asyncio.StreamReaderProtocol):
            def __init__(self, _loop, socks_srv):
                self._loop = _loop
                self._socks_srv = socks_srv
                reader = asyncio.StreamReader(loop=self._loop)
                super().__init__(
                    reader, client_connected_cb=socks_srv.negotiate,
                    loop=self._loop)

        def factory():
            return Socks4Protocol(_loop=self._loop, socks_srv=self)

        self._srv = await self._loop.create_server(
            factory, '127.0.0.1', self.port)

    async def close(self):
        for writer in self._writers:
            writer.close()

        for fut in self._retranslators:
            if not fut.cancelled() or not fut.done():
                fut.cancel()

        self._srv.close()
        await self._srv.wait_closed()


@pytest.fixture
def fake_socks4_server(loop):
    servers = []

    async def go():
        server = FakeSocks4Srv(loop)
        await server.start_server()
        servers.append(server)
        return server

    yield go

    async def finalize():
        while servers:
            await servers.pop().close()

    loop.run_until_complete(finalize())


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


async def test_proxy_http_absolute_path(proxy_test_server, get_request):
    url = 'http://aiohttp.io/path?query=yes'
    proxy = await proxy_test_server()

    await get_request(url=url, proxy=proxy.url)

    assert len(proxy.requests_list) == 1
    assert proxy.request.method == 'GET'
    assert proxy.request.host == 'aiohttp.io'
    assert proxy.request.path_qs == 'http://aiohttp.io/path?query=yes'


async def test_proxy_http_raw_path(proxy_test_server, get_request):
    url = 'http://aiohttp.io:2561/space sheep?q=can:fly'
    raw_url = 'http://aiohttp.io:2561/space%20sheep?q=can:fly'
    proxy = await proxy_test_server()

    await get_request(url=url, proxy=proxy.url)

    assert proxy.request.host == 'aiohttp.io:2561'
    assert proxy.request.path_qs == raw_url


async def test_proxy_http_idna_support(proxy_test_server, get_request):
    url = 'http://éé.com/'
    raw_url = 'http://xn--9caa.com/'
    proxy = await proxy_test_server()

    await get_request(url=url, proxy=proxy.url)

    assert proxy.request.host == 'xn--9caa.com'
    assert proxy.request.path_qs == raw_url


async def test_proxy_http_connection_error(get_request):
    url = 'http://aiohttp.io/path'
    proxy_url = 'http://localhost:2242/'

    with pytest.raises(aiohttp.ClientConnectorError):
        await get_request(url=url, proxy=proxy_url)


async def test_proxy_http_bad_response(proxy_test_server, get_request):
    url = 'http://aiohttp.io/path'
    proxy = await proxy_test_server()
    proxy.return_value = dict(
        status=502,
        headers={'Proxy-Agent': 'TestProxy'})

    resp = await get_request(url=url, proxy=proxy.url)

    assert resp.status == 502
    assert resp.headers['Proxy-Agent'] == 'TestProxy'


async def test_proxy_http_auth(proxy_test_server, get_request):
    url = 'http://aiohttp.io/path'
    proxy = await proxy_test_server()

    await get_request(url=url, proxy=proxy.url)

    assert 'Authorization' not in proxy.request.headers
    assert 'Proxy-Authorization' not in proxy.request.headers

    auth = aiohttp.BasicAuth('user', 'pass')
    await get_request(url=url, auth=auth, proxy=proxy.url)

    assert 'Authorization' in proxy.request.headers
    assert 'Proxy-Authorization' not in proxy.request.headers

    await get_request(url=url, proxy_auth=auth, proxy=proxy.url)

    assert 'Authorization' not in proxy.request.headers
    assert 'Proxy-Authorization' in proxy.request.headers

    await get_request(url=url, auth=auth,
                      proxy_auth=auth, proxy=proxy.url)

    assert 'Authorization' in proxy.request.headers
    assert 'Proxy-Authorization' in proxy.request.headers


async def test_proxy_http_auth_utf8(proxy_test_server, get_request):
    url = 'http://aiohttp.io/path'
    auth = aiohttp.BasicAuth('юзер', 'пасс', 'utf-8')
    proxy = await proxy_test_server()

    await get_request(url=url, auth=auth, proxy=proxy.url)

    assert 'Authorization' in proxy.request.headers
    assert 'Proxy-Authorization' not in proxy.request.headers


async def test_proxy_http_auth_from_url(proxy_test_server, get_request):
    url = 'http://aiohttp.io/path'
    proxy = await proxy_test_server()

    auth_url = URL(url).with_user('user').with_password('pass')
    await get_request(url=auth_url, proxy=proxy.url)

    assert 'Authorization' in proxy.request.headers
    assert 'Proxy-Authorization' not in proxy.request.headers

    proxy_url = URL(proxy.url).with_user('user').with_password('pass')
    await get_request(url=url, proxy=proxy_url)

    assert 'Authorization' not in proxy.request.headers
    assert 'Proxy-Authorization' in proxy.request.headers


async def test_proxy_http_acquired_cleanup(proxy_test_server, loop):
    url = 'http://aiohttp.io/path'

    conn = aiohttp.TCPConnector(loop=loop)
    sess = aiohttp.ClientSession(connector=conn, loop=loop)
    proxy = await proxy_test_server()

    assert 0 == len(conn._acquired)

    resp = await sess.get(url, proxy=proxy.url)
    assert resp.closed

    assert 0 == len(conn._acquired)

    await sess.close()


@pytest.mark.skip('we need to reconsider how we test this')
async def test_proxy_http_acquired_cleanup_force(proxy_test_server, loop):
    url = 'http://aiohttp.io/path'

    conn = aiohttp.TCPConnector(force_close=True, loop=loop)
    sess = aiohttp.ClientSession(connector=conn, loop=loop)
    proxy = await proxy_test_server()

    assert 0 == len(conn._acquired)

    async def request():
        resp = await sess.get(url, proxy=proxy.url)

        assert 1 == len(conn._acquired)

        await resp.release()

    await request()

    assert 0 == len(conn._acquired)

    await sess.close()


@pytest.mark.skip('we need to reconsider how we test this')
async def test_proxy_http_multi_conn_limit(proxy_test_server, loop):
    url = 'http://aiohttp.io/path'
    limit, multi_conn_num = 1, 5

    conn = aiohttp.TCPConnector(limit=limit, loop=loop)
    sess = aiohttp.ClientSession(connector=conn, loop=loop)
    proxy = await proxy_test_server()

    current_pid = None

    async def request(pid):
        # process requests only one by one
        nonlocal current_pid

        resp = await sess.get(url, proxy=proxy.url)

        current_pid = pid
        await asyncio.sleep(0.2, loop=loop)
        assert current_pid == pid

        await resp.release()
        return resp

    requests = [request(pid) for pid in range(multi_conn_num)]
    responses = await asyncio.gather(*requests, loop=loop)

    assert len(responses) == multi_conn_num
    assert set(resp.status for resp in responses) == {200}

    await sess.close()


@pytest.mark.xfail
async def xtest_proxy_https_connect(proxy_test_server, get_request):
    proxy = await proxy_test_server()
    url = 'https://www.google.com.ua/search?q=aiohttp proxy'

    await get_request(url=url, proxy=proxy.url)

    connect = proxy.requests_list[0]
    assert connect.method == 'CONNECT'
    assert connect.path == 'www.google.com.ua:443'
    assert connect.host == 'www.google.com.ua'

    assert proxy.request.host == 'www.google.com.ua'
    assert proxy.request.path_qs == '/search?q=aiohttp+proxy'


@pytest.mark.xfail
async def xtest_proxy_https_connect_with_port(proxy_test_server, get_request):
    proxy = await proxy_test_server()
    url = 'https://secure.aiohttp.io:2242/path'

    await get_request(url=url, proxy=proxy.url)

    connect = proxy.requests_list[0]
    assert connect.method == 'CONNECT'
    assert connect.path == 'secure.aiohttp.io:2242'
    assert connect.host == 'secure.aiohttp.io:2242'

    assert proxy.request.host == 'secure.aiohttp.io:2242'
    assert proxy.request.path_qs == '/path'


@pytest.mark.xfail
async def xtest_proxy_https_send_body(proxy_test_server, loop):
    sess = aiohttp.ClientSession(loop=loop)
    proxy = await proxy_test_server()
    proxy.return_value = {'status': 200, 'body': b'1'*(2**20)}
    url = 'https://www.google.com.ua/search?q=aiohttp proxy'

    resp = await sess.get(url, proxy=proxy.url)
    body = await resp.read()
    await resp.release()
    await sess.close()

    assert body == b'1'*(2**20)


@pytest.mark.xfail
async def xtest_proxy_https_idna_support(proxy_test_server, get_request):
    url = 'https://éé.com/'
    proxy = await proxy_test_server()

    await get_request(url=url, proxy=proxy.url)

    connect = proxy.requests_list[0]
    assert connect.method == 'CONNECT'
    assert connect.path == 'xn--9caa.com:443'
    assert connect.host == 'xn--9caa.com'


async def test_proxy_https_connection_error(get_request):
    url = 'https://secure.aiohttp.io/path'
    proxy_url = 'http://localhost:2242/'

    with pytest.raises(aiohttp.ClientConnectorError):
        await get_request(url=url, proxy=proxy_url)


async def test_proxy_https_bad_response(proxy_test_server, get_request):
    url = 'https://secure.aiohttp.io/path'
    proxy = await proxy_test_server()
    proxy.return_value = dict(
        status=502,
        headers={'Proxy-Agent': 'TestProxy'})

    with pytest.raises(aiohttp.ClientHttpProxyError):
        await get_request(url=url, proxy=proxy.url)

    assert len(proxy.requests_list) == 1
    assert proxy.request.method == 'CONNECT'
    assert proxy.request.path == 'secure.aiohttp.io:443'


@pytest.mark.xfail
async def xtest_proxy_https_auth(proxy_test_server, get_request):
    url = 'https://secure.aiohttp.io/path'
    auth = aiohttp.BasicAuth('user', 'pass')

    proxy = await proxy_test_server()
    await get_request(url=url, proxy=proxy.url)

    connect = proxy.requests_list[0]
    assert 'Authorization' not in connect.headers
    assert 'Proxy-Authorization' not in connect.headers
    assert 'Authorization' not in proxy.request.headers
    assert 'Proxy-Authorization' not in proxy.request.headers

    proxy = await proxy_test_server()
    await get_request(url=url, auth=auth, proxy=proxy.url)

    connect = proxy.requests_list[0]
    assert 'Authorization' not in connect.headers
    assert 'Proxy-Authorization' not in connect.headers
    assert 'Authorization' in proxy.request.headers
    assert 'Proxy-Authorization' not in proxy.request.headers

    proxy = await proxy_test_server()
    await get_request(url=url, proxy_auth=auth, proxy=proxy.url)

    connect = proxy.requests_list[0]
    assert 'Authorization' not in connect.headers
    assert 'Proxy-Authorization' in connect.headers
    assert 'Authorization' not in proxy.request.headers
    assert 'Proxy-Authorization' not in proxy.request.headers

    proxy = await proxy_test_server()
    await get_request(url=url, auth=auth,
                      proxy_auth=auth, proxy=proxy.url)

    connect = proxy.requests_list[0]
    assert 'Authorization' not in connect.headers
    assert 'Proxy-Authorization' in connect.headers
    assert 'Authorization' in proxy.request.headers
    assert 'Proxy-Authorization' not in proxy.request.headers


@pytest.mark.xfail
async def xtest_proxy_https_acquired_cleanup(proxy_test_server, loop):
    url = 'https://secure.aiohttp.io/path'

    conn = aiohttp.TCPConnector(loop=loop)
    sess = aiohttp.ClientSession(connector=conn, loop=loop)
    proxy = await proxy_test_server()

    assert 0 == len(conn._acquired)

    async def request():
        resp = await sess.get(url, proxy=proxy.url)

        assert 1 == len(conn._acquired)

        await resp.release()

    await request()

    assert 0 == len(conn._acquired)

    await sess.close()


@pytest.mark.xfail
async def xtest_proxy_https_acquired_cleanup_force(proxy_test_server, loop):
    url = 'https://secure.aiohttp.io/path'

    conn = aiohttp.TCPConnector(force_close=True, loop=loop)
    sess = aiohttp.ClientSession(connector=conn, loop=loop)
    proxy = await proxy_test_server()

    assert 0 == len(conn._acquired)

    async def request():
        resp = await sess.get(url, proxy=proxy.url)

        assert 1 == len(conn._acquired)

        await resp.release()

    await request()

    assert 0 == len(conn._acquired)

    await sess.close()


@pytest.mark.xfail
async def xtest_proxy_https_multi_conn_limit(proxy_test_server, loop):
    url = 'https://secure.aiohttp.io/path'
    limit, multi_conn_num = 1, 5

    conn = aiohttp.TCPConnector(limit=limit, loop=loop)
    sess = aiohttp.ClientSession(connector=conn, loop=loop)
    proxy = await proxy_test_server()

    current_pid = None

    async def request(pid):
        # process requests only one by one
        nonlocal current_pid

        resp = await sess.get(url, proxy=proxy.url)

        current_pid = pid
        await asyncio.sleep(0.2, loop=loop)
        assert current_pid == pid

        await resp.release()
        return resp

    requests = [request(pid) for pid in range(multi_conn_num)]
    responses = await asyncio.gather(*requests, loop=loop)

    assert len(responses) == multi_conn_num
    assert set(resp.status for resp in responses) == {200}

    await sess.close()


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


async def test_proxy_from_env_http(proxy_test_server, get_request, mocker):
    url = 'http://aiohttp.io/path'
    proxy = await proxy_test_server()
    mocker.patch.dict(os.environ, {'http_proxy': str(proxy.url)})

    await get_request(url=url, trust_env=True)

    assert len(proxy.requests_list) == 1
    assert proxy.request.method == 'GET'
    assert proxy.request.host == 'aiohttp.io'
    assert proxy.request.path_qs == 'http://aiohttp.io/path'
    assert 'Proxy-Authorization' not in proxy.request.headers


async def test_proxy_from_env_http_with_auth(proxy_test_server,
                                             get_request, mocker):
    url = 'http://aiohttp.io/path'
    proxy = await proxy_test_server()
    auth = aiohttp.BasicAuth('user', 'pass')
    mocker.patch.dict(os.environ, {'http_proxy':
                                   str(proxy.url
                                       .with_user(auth.login)
                                       .with_password(auth.password))})

    await get_request(url=url, trust_env=True)

    assert len(proxy.requests_list) == 1
    assert proxy.request.method == 'GET'
    assert proxy.request.host == 'aiohttp.io'
    assert proxy.request.path_qs == 'http://aiohttp.io/path'
    assert proxy.request.headers['Proxy-Authorization'] == auth.encode()


@pytest.mark.xfail
async def xtest_proxy_from_env_https(proxy_test_server, get_request, mocker):
    url = 'https://aiohttp.io/path'
    proxy = await proxy_test_server()
    mocker.patch.dict(os.environ, {'https_proxy': str(proxy.url)})

    await get_request(url=url, trust_env=True)

    assert len(proxy.requests_list) == 2
    assert proxy.request.method == 'GET'
    assert proxy.request.host == 'aiohttp.io'
    assert proxy.request.path_qs == 'https://aiohttp.io/path'
    assert 'Proxy-Authorization' not in proxy.request.headers


@pytest.mark.xfail
async def xtest_proxy_from_env_https_with_auth(proxy_test_server,
                                               get_request, mocker):
    url = 'https://aiohttp.io/path'
    proxy = await proxy_test_server()
    auth = aiohttp.BasicAuth('user', 'pass')
    mocker.patch.dict(os.environ, {'https_proxy':
                                   str(proxy.url
                                       .with_user(auth.login)
                                       .with_password(auth.password))})

    await get_request(url=url, trust_env=True)

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


@pytest.mark.skipif(aiosocks is None, reason="aiosocks library required")
async def test_socks_http_connect(loop, raw_test_server, fake_socks4_server):
    async def handler(request):
        return web.Response(text='Test message')

    raw_http_server = await raw_test_server(handler)
    socks_server = await fake_socks4_server()

    async with aiohttp.ClientSession(loop=loop) as session:
        proxy = URL('socks4://127.0.0.1:{}'.format(socks_server.port))

        async with session.get(
                raw_http_server.make_url('/'), proxy=proxy) as resp:
            assert resp.status == 200
            assert (await resp.text()) == 'Test message'


@pytest.mark.skipif(aiosocks is None, reason="aiosocks library required")
async def test_socks_https_connect(loop, fake_socks4_server):
    async def handler(request):
        return web.Response(text='Test message')

    here = os.path.join(os.path.dirname(__file__), '..', 'tests')
    keyfile = os.path.join(here, 'sample.key')
    certfile = os.path.join(here, 'sample.crt')
    sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    sslcontext.load_cert_chain(certfile, keyfile)

    raw_http_server = RawTestServer(
        handler, scheme='https', host='127.0.0.1', loop=loop)
    await raw_http_server.start_server(loop=loop, ssl=sslcontext)

    socks_server = await fake_socks4_server()

    valid_fp = (b'0\x9a\xc9D\x83\xdc\x91\'\x88\x91\x11\xa1d\x97\xfd'
                b'\xcb~7U\x14D@L'
                b'\x11\xab\x99\xa8\xae\xb7\x14\xee\x8b')

    invalid_fp = (b'0\x9d\xc9D\x83\xdc\x91\'\x88\x91\x11\xa1d\x97\xfd'
                  b'\xcb~7U\x14D@L'
                  b'\x11\xab\x99\xa8\xae\xb7\x14\xee\x9e')
    url = raw_http_server.make_url('/')
    proxy = URL('socks4://127.0.0.1:{}'.format(socks_server.port))

    async with aiohttp.ClientSession(loop=loop) as session:
        async with session.get(
                url, proxy=proxy, fingerprint=valid_fp,
                verify_ssl=False) as resp:
            assert resp.status == 200
            assert (await resp.text()) == 'Test message'

    async with aiohttp.ClientSession(loop=loop) as session:
        with pytest.raises(aiohttp.ServerFingerprintMismatch):
            async with session.get(
                    url, proxy=proxy, fingerprint=invalid_fp,
                    verify_ssl=False):
                pass

    await raw_http_server.close()
