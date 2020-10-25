import asyncio
import os
import pathlib
from unittest import mock

import pytest
from yarl import URL

import aiohttp
from aiohttp import web


@pytest.fixture
def proxy_test_server(aiohttp_raw_server, loop, monkeypatch):
    # Handle all proxy requests and imitate remote server response.

    _patch_ssl_transport(monkeypatch)

    default_response = dict(status=200, headers=None, body=None)

    proxy_mock = mock.Mock()

    async def proxy_handler(request):
        proxy_mock.request = request
        proxy_mock.requests_list.append(request)

        response = default_response.copy()
        if isinstance(proxy_mock.return_value, dict):
            response.update(proxy_mock.return_value)

        headers = response["headers"]
        if not headers:
            headers = {}

        if request.method == "CONNECT":
            response["body"] = None

        response["headers"] = headers

        resp = web.Response(**response)
        await resp.prepare(request)
        await resp.write_eof()
        return resp

    async def proxy_server():
        proxy_mock.request = None
        proxy_mock.auth = None
        proxy_mock.requests_list = []

        server = await aiohttp_raw_server(proxy_handler)

        proxy_mock.server = server
        proxy_mock.url = server.make_url("/")

        return proxy_mock

    return proxy_server


@pytest.fixture()
def get_request(loop):
    async def _request(method="GET", *, url, trust_env=False, **kwargs):
        connector = aiohttp.TCPConnector(ssl=False, loop=loop)
        client = aiohttp.ClientSession(connector=connector, trust_env=trust_env)
        try:
            resp = await client.request(method, url, **kwargs)
            await resp.release()
            return resp
        finally:
            await client.close()

    return _request


async def test_proxy_http_absolute_path(proxy_test_server, get_request) -> None:
    url = "http://aiohttp.io/path?query=yes"
    proxy = await proxy_test_server()

    await get_request(url=url, proxy=proxy.url)

    assert len(proxy.requests_list) == 1
    assert proxy.request.method == "GET"
    assert proxy.request.host == "aiohttp.io"
    assert proxy.request.path_qs == "http://aiohttp.io/path?query=yes"


async def test_proxy_http_raw_path(proxy_test_server, get_request) -> None:
    url = "http://aiohttp.io:2561/space sheep?q=can:fly"
    raw_url = "http://aiohttp.io:2561/space%20sheep?q=can:fly"
    proxy = await proxy_test_server()

    await get_request(url=url, proxy=proxy.url)

    assert proxy.request.host == "aiohttp.io:2561"
    assert proxy.request.path_qs == raw_url


async def test_proxy_http_idna_support(proxy_test_server, get_request) -> None:
    url = "http://éé.com/"
    raw_url = "http://xn--9caa.com/"
    proxy = await proxy_test_server()

    await get_request(url=url, proxy=proxy.url)

    assert proxy.request.host == "xn--9caa.com"
    assert proxy.request.path_qs == raw_url


async def test_proxy_http_connection_error(get_request) -> None:
    url = "http://aiohttp.io/path"
    proxy_url = "http://localhost:2242/"

    with pytest.raises(aiohttp.ClientConnectorError):
        await get_request(url=url, proxy=proxy_url)


async def test_proxy_http_bad_response(proxy_test_server, get_request) -> None:
    url = "http://aiohttp.io/path"
    proxy = await proxy_test_server()
    proxy.return_value = dict(status=502, headers={"Proxy-Agent": "TestProxy"})

    resp = await get_request(url=url, proxy=proxy.url)

    assert resp.status == 502
    assert resp.headers["Proxy-Agent"] == "TestProxy"


async def test_proxy_http_auth(proxy_test_server, get_request) -> None:
    url = "http://aiohttp.io/path"
    proxy = await proxy_test_server()

    await get_request(url=url, proxy=proxy.url)

    assert "Authorization" not in proxy.request.headers
    assert "Proxy-Authorization" not in proxy.request.headers

    auth = aiohttp.BasicAuth("user", "pass")
    await get_request(url=url, auth=auth, proxy=proxy.url)

    assert "Authorization" in proxy.request.headers
    assert "Proxy-Authorization" not in proxy.request.headers

    await get_request(url=url, proxy_auth=auth, proxy=proxy.url)

    assert "Authorization" not in proxy.request.headers
    assert "Proxy-Authorization" in proxy.request.headers

    await get_request(url=url, auth=auth, proxy_auth=auth, proxy=proxy.url)

    assert "Authorization" in proxy.request.headers
    assert "Proxy-Authorization" in proxy.request.headers


async def test_proxy_http_auth_utf8(proxy_test_server, get_request) -> None:
    url = "http://aiohttp.io/path"
    auth = aiohttp.BasicAuth("юзер", "пасс", "utf-8")
    proxy = await proxy_test_server()

    await get_request(url=url, auth=auth, proxy=proxy.url)

    assert "Authorization" in proxy.request.headers
    assert "Proxy-Authorization" not in proxy.request.headers


async def test_proxy_http_auth_from_url(proxy_test_server, get_request) -> None:
    url = "http://aiohttp.io/path"
    proxy = await proxy_test_server()

    auth_url = URL(url).with_user("user").with_password("pass")
    await get_request(url=auth_url, proxy=proxy.url)

    assert "Authorization" in proxy.request.headers
    assert "Proxy-Authorization" not in proxy.request.headers

    proxy_url = URL(proxy.url).with_user("user").with_password("pass")
    await get_request(url=url, proxy=proxy_url)

    assert "Authorization" not in proxy.request.headers
    assert "Proxy-Authorization" in proxy.request.headers


async def test_proxy_http_acquired_cleanup(proxy_test_server, loop) -> None:
    url = "http://aiohttp.io/path"

    conn = aiohttp.TCPConnector(loop=loop)
    sess = aiohttp.ClientSession(connector=conn, loop=loop)
    proxy = await proxy_test_server()

    assert 0 == len(conn._acquired)

    resp = await sess.get(url, proxy=proxy.url)
    assert resp.closed

    assert 0 == len(conn._acquired)

    await sess.close()


@pytest.mark.skip("we need to reconsider how we test this")
async def test_proxy_http_acquired_cleanup_force(proxy_test_server, loop) -> None:
    url = "http://aiohttp.io/path"

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


@pytest.mark.skip("we need to reconsider how we test this")
async def test_proxy_http_multi_conn_limit(proxy_test_server, loop) -> None:
    url = "http://aiohttp.io/path"
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
    assert {resp.status for resp in responses} == {200}

    await sess.close()


@pytest.mark.xfail
async def xtest_proxy_https_connect(proxy_test_server, get_request):
    proxy = await proxy_test_server()
    url = "https://www.google.com.ua/search?q=aiohttp proxy"

    await get_request(url=url, proxy=proxy.url)

    connect = proxy.requests_list[0]
    assert connect.method == "CONNECT"
    assert connect.path == "www.google.com.ua:443"
    assert connect.host == "www.google.com.ua"

    assert proxy.request.host == "www.google.com.ua"
    assert proxy.request.path_qs == "/search?q=aiohttp+proxy"


@pytest.mark.xfail
async def xtest_proxy_https_connect_with_port(proxy_test_server, get_request):
    proxy = await proxy_test_server()
    url = "https://secure.aiohttp.io:2242/path"

    await get_request(url=url, proxy=proxy.url)

    connect = proxy.requests_list[0]
    assert connect.method == "CONNECT"
    assert connect.path == "secure.aiohttp.io:2242"
    assert connect.host == "secure.aiohttp.io:2242"

    assert proxy.request.host == "secure.aiohttp.io:2242"
    assert proxy.request.path_qs == "/path"


@pytest.mark.xfail
async def xtest_proxy_https_send_body(proxy_test_server, loop):
    sess = aiohttp.ClientSession(loop=loop)
    proxy = await proxy_test_server()
    proxy.return_value = {"status": 200, "body": b"1" * (2 ** 20)}
    url = "https://www.google.com.ua/search?q=aiohttp proxy"

    resp = await sess.get(url, proxy=proxy.url)
    body = await resp.read()
    await resp.release()
    await sess.close()

    assert body == b"1" * (2 ** 20)


@pytest.mark.xfail
async def xtest_proxy_https_idna_support(proxy_test_server, get_request):
    url = "https://éé.com/"
    proxy = await proxy_test_server()

    await get_request(url=url, proxy=proxy.url)

    connect = proxy.requests_list[0]
    assert connect.method == "CONNECT"
    assert connect.path == "xn--9caa.com:443"
    assert connect.host == "xn--9caa.com"


async def test_proxy_https_connection_error(get_request) -> None:
    url = "https://secure.aiohttp.io/path"
    proxy_url = "http://localhost:2242/"

    with pytest.raises(aiohttp.ClientConnectorError):
        await get_request(url=url, proxy=proxy_url)


async def test_proxy_https_bad_response(proxy_test_server, get_request) -> None:
    url = "https://secure.aiohttp.io/path"
    proxy = await proxy_test_server()
    proxy.return_value = dict(status=502, headers={"Proxy-Agent": "TestProxy"})

    with pytest.raises(aiohttp.ClientHttpProxyError):
        await get_request(url=url, proxy=proxy.url)

    assert len(proxy.requests_list) == 1
    assert proxy.request.method == "CONNECT"
    # The following check fails on MacOS
    # assert proxy.request.path == 'secure.aiohttp.io:443'


@pytest.mark.xfail
async def xtest_proxy_https_auth(proxy_test_server, get_request):
    url = "https://secure.aiohttp.io/path"
    auth = aiohttp.BasicAuth("user", "pass")

    proxy = await proxy_test_server()
    await get_request(url=url, proxy=proxy.url)

    connect = proxy.requests_list[0]
    assert "Authorization" not in connect.headers
    assert "Proxy-Authorization" not in connect.headers
    assert "Authorization" not in proxy.request.headers
    assert "Proxy-Authorization" not in proxy.request.headers

    proxy = await proxy_test_server()
    await get_request(url=url, auth=auth, proxy=proxy.url)

    connect = proxy.requests_list[0]
    assert "Authorization" not in connect.headers
    assert "Proxy-Authorization" not in connect.headers
    assert "Authorization" in proxy.request.headers
    assert "Proxy-Authorization" not in proxy.request.headers

    proxy = await proxy_test_server()
    await get_request(url=url, proxy_auth=auth, proxy=proxy.url)

    connect = proxy.requests_list[0]
    assert "Authorization" not in connect.headers
    assert "Proxy-Authorization" in connect.headers
    assert "Authorization" not in proxy.request.headers
    assert "Proxy-Authorization" not in proxy.request.headers

    proxy = await proxy_test_server()
    await get_request(url=url, auth=auth, proxy_auth=auth, proxy=proxy.url)

    connect = proxy.requests_list[0]
    assert "Authorization" not in connect.headers
    assert "Proxy-Authorization" in connect.headers
    assert "Authorization" in proxy.request.headers
    assert "Proxy-Authorization" not in proxy.request.headers


@pytest.mark.xfail
async def xtest_proxy_https_acquired_cleanup(proxy_test_server, loop):
    url = "https://secure.aiohttp.io/path"

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
    url = "https://secure.aiohttp.io/path"

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
    url = "https://secure.aiohttp.io/path"
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
    assert {resp.status for resp in responses} == {200}

    await sess.close()


def _patch_ssl_transport(monkeypatch):
    # Make ssl transport substitution to prevent ssl handshake.
    def _make_ssl_transport_dummy(
        self, rawsock, protocol, sslcontext, waiter=None, **kwargs
    ):
        return self._make_socket_transport(
            rawsock,
            protocol,
            waiter,
            extra=kwargs.get("extra"),
            server=kwargs.get("server"),
        )

    monkeypatch.setattr(
        "asyncio.selector_events.BaseSelectorEventLoop._make_ssl_transport",
        _make_ssl_transport_dummy,
    )


original_is_file = pathlib.Path.is_file


def mock_is_file(self):
    # make real netrc file invisible in home dir
    if self.name in ["_netrc", ".netrc"] and self.parent == self.home():
        return False
    else:
        return original_is_file(self)


async def test_proxy_from_env_http(proxy_test_server, get_request, mocker) -> None:
    url = "http://aiohttp.io/path"
    proxy = await proxy_test_server()
    mocker.patch.dict(os.environ, {"http_proxy": str(proxy.url)})
    mocker.patch("pathlib.Path.is_file", mock_is_file)

    await get_request(url=url, trust_env=True)

    assert len(proxy.requests_list) == 1
    assert proxy.request.method == "GET"
    assert proxy.request.host == "aiohttp.io"
    assert proxy.request.path_qs == "http://aiohttp.io/path"
    assert "Proxy-Authorization" not in proxy.request.headers


async def test_proxy_from_env_http_with_auth(proxy_test_server, get_request, mocker):
    url = "http://aiohttp.io/path"
    proxy = await proxy_test_server()
    auth = aiohttp.BasicAuth("user", "pass")
    mocker.patch.dict(
        os.environ,
        {
            "http_proxy": str(
                proxy.url.with_user(auth.login).with_password(auth.password)
            )
        },
    )

    await get_request(url=url, trust_env=True)

    assert len(proxy.requests_list) == 1
    assert proxy.request.method == "GET"
    assert proxy.request.host == "aiohttp.io"
    assert proxy.request.path_qs == "http://aiohttp.io/path"
    assert proxy.request.headers["Proxy-Authorization"] == auth.encode()


async def test_proxy_from_env_http_with_auth_from_netrc(
    proxy_test_server, get_request, tmpdir, mocker
):
    url = "http://aiohttp.io/path"
    proxy = await proxy_test_server()
    auth = aiohttp.BasicAuth("user", "pass")
    netrc_file = tmpdir.join("test_netrc")
    netrc_file_data = "machine 127.0.0.1 login {} password {}".format(
        auth.login,
        auth.password,
    )
    with open(str(netrc_file), "w") as f:
        f.write(netrc_file_data)
    mocker.patch.dict(
        os.environ, {"http_proxy": str(proxy.url), "NETRC": str(netrc_file)}
    )

    await get_request(url=url, trust_env=True)

    assert len(proxy.requests_list) == 1
    assert proxy.request.method == "GET"
    assert proxy.request.host == "aiohttp.io"
    assert proxy.request.path_qs == "http://aiohttp.io/path"
    assert proxy.request.headers["Proxy-Authorization"] == auth.encode()


async def test_proxy_from_env_http_without_auth_from_netrc(
    proxy_test_server, get_request, tmpdir, mocker
):
    url = "http://aiohttp.io/path"
    proxy = await proxy_test_server()
    auth = aiohttp.BasicAuth("user", "pass")
    netrc_file = tmpdir.join("test_netrc")
    netrc_file_data = "machine 127.0.0.2 login {} password {}".format(
        auth.login,
        auth.password,
    )
    with open(str(netrc_file), "w") as f:
        f.write(netrc_file_data)
    mocker.patch.dict(
        os.environ, {"http_proxy": str(proxy.url), "NETRC": str(netrc_file)}
    )

    await get_request(url=url, trust_env=True)

    assert len(proxy.requests_list) == 1
    assert proxy.request.method == "GET"
    assert proxy.request.host == "aiohttp.io"
    assert proxy.request.path_qs == "http://aiohttp.io/path"
    assert "Proxy-Authorization" not in proxy.request.headers


async def test_proxy_from_env_http_without_auth_from_wrong_netrc(
    proxy_test_server, get_request, tmpdir, mocker
):
    url = "http://aiohttp.io/path"
    proxy = await proxy_test_server()
    auth = aiohttp.BasicAuth("user", "pass")
    netrc_file = tmpdir.join("test_netrc")
    invalid_data = f"machine 127.0.0.1 {auth.login} pass {auth.password}"
    with open(str(netrc_file), "w") as f:
        f.write(invalid_data)

    mocker.patch.dict(
        os.environ, {"http_proxy": str(proxy.url), "NETRC": str(netrc_file)}
    )

    await get_request(url=url, trust_env=True)

    assert len(proxy.requests_list) == 1
    assert proxy.request.method == "GET"
    assert proxy.request.host == "aiohttp.io"
    assert proxy.request.path_qs == "http://aiohttp.io/path"
    assert "Proxy-Authorization" not in proxy.request.headers


@pytest.mark.xfail
async def xtest_proxy_from_env_https(proxy_test_server, get_request, mocker):
    url = "https://aiohttp.io/path"
    proxy = await proxy_test_server()
    mocker.patch.dict(os.environ, {"https_proxy": str(proxy.url)})
    mock.patch("pathlib.Path.is_file", mock_is_file)

    await get_request(url=url, trust_env=True)

    assert len(proxy.requests_list) == 2
    assert proxy.request.method == "GET"
    assert proxy.request.host == "aiohttp.io"
    assert proxy.request.path_qs == "https://aiohttp.io/path"
    assert "Proxy-Authorization" not in proxy.request.headers


@pytest.mark.xfail
async def xtest_proxy_from_env_https_with_auth(proxy_test_server, get_request, mocker):
    url = "https://aiohttp.io/path"
    proxy = await proxy_test_server()
    auth = aiohttp.BasicAuth("user", "pass")
    mocker.patch.dict(
        os.environ,
        {
            "https_proxy": str(
                proxy.url.with_user(auth.login).with_password(auth.password)
            )
        },
    )

    await get_request(url=url, trust_env=True)

    assert len(proxy.requests_list) == 2

    assert proxy.request.method == "GET"
    assert proxy.request.host == "aiohttp.io"
    assert proxy.request.path_qs == "/path"
    assert "Proxy-Authorization" not in proxy.request.headers

    r2 = proxy.requests_list[0]
    assert r2.method == "CONNECT"
    assert r2.host == "aiohttp.io"
    assert r2.path_qs == "/path"
    assert r2.headers["Proxy-Authorization"] == auth.encode()


async def test_proxy_auth() -> None:
    async with aiohttp.ClientSession() as session:
        with pytest.raises(
            ValueError, match=r"proxy_auth must be None or BasicAuth\(\) tuple"
        ):
            await session.get(
                "http://python.org",
                proxy="http://proxy.example.com",
                proxy_auth=("user", "pass"),
            )
