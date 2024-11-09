import asyncio
import os
import pathlib
import ssl
import sys
from re import match as match_regex
from unittest import mock
from uuid import uuid4

import proxy
import pytest
from yarl import URL

import aiohttp
from aiohttp import web
from aiohttp.client_exceptions import ClientConnectionError
from aiohttp.helpers import IS_MACOS, IS_WINDOWS

ASYNCIO_SUPPORTS_TLS_IN_TLS = sys.version_info >= (3, 11)


@pytest.fixture
def secure_proxy_url(tls_certificate_pem_path):
    """Return the URL of an instance of a running secure proxy.

    This fixture also spawns that instance and tears it down after the test.
    """
    proxypy_args = [
        # --threadless does not work on windows, see
        # https://github.com/abhinavsingh/proxy.py/issues/492
        "--threaded" if os.name == "nt" else "--threadless",
        "--num-workers",
        "1",  # the tests only send one query anyway
        "--hostname",
        "127.0.0.1",  # network interface to listen to
        "--port",
        0,  # ephemeral port, so that kernel allocates a free one
        "--cert-file",
        tls_certificate_pem_path,  # contains both key and cert
        "--key-file",
        tls_certificate_pem_path,  # contains both key and cert
    ]
    if not IS_MACOS and not IS_WINDOWS:
        proxypy_args.append("--threadless")  # use asyncio

    with proxy.Proxy(input_args=proxypy_args) as proxy_instance:
        yield URL.build(
            scheme="https",
            host=str(proxy_instance.flags.hostname),
            port=proxy_instance.flags.port,
        )


@pytest.fixture
def web_server_endpoint_payload():
    return str(uuid4())


@pytest.fixture(params=("http", "https"))
def web_server_endpoint_type(request):
    return request.param


@pytest.fixture
async def web_server_endpoint_url(
    aiohttp_server,
    ssl_ctx,
    web_server_endpoint_payload,
    web_server_endpoint_type,
):
    server_kwargs = (
        {
            "ssl": ssl_ctx,
        }
        if web_server_endpoint_type == "https"
        else {}
    )

    async def handler(*args, **kwargs):
        return web.Response(text=web_server_endpoint_payload)

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    server = await aiohttp_server(app, **server_kwargs)

    return URL.build(
        scheme=web_server_endpoint_type,
        host=server.host,
        port=server.port,
    )


@pytest.mark.skipif(
    not ASYNCIO_SUPPORTS_TLS_IN_TLS,
    reason="asyncio on this python does not support TLS in TLS",
)
@pytest.mark.parametrize("web_server_endpoint_type", ("http", "https"))
@pytest.mark.filterwarnings(r"ignore:.*ssl.OP_NO_SSL*")
# Filter out the warning from
# https://github.com/abhinavsingh/proxy.py/blob/30574fd0414005dfa8792a6e797023e862bdcf43/proxy/common/utils.py#L226
# otherwise this test will fail because the proxy will die with an error.
@pytest.mark.usefixtures("loop")
async def test_secure_https_proxy_absolute_path(
    client_ssl_ctx: ssl.SSLContext,
    secure_proxy_url: URL,
    web_server_endpoint_url: str,
    web_server_endpoint_payload: str,
) -> None:
    """Ensure HTTP(S) sites are accessible through a secure proxy."""
    conn = aiohttp.TCPConnector()
    sess = aiohttp.ClientSession(connector=conn)

    async with sess.get(
        web_server_endpoint_url,
        proxy=secure_proxy_url,
        ssl=client_ssl_ctx,  # used for both proxy and endpoint connections
    ) as response:
        assert response.status == 200
        assert await response.text() == web_server_endpoint_payload

    await sess.close()
    await conn.close()
    await asyncio.sleep(0.1)

    # https://docs.aiohttp.org/en/v3.8.0/client_advanced.html#graceful-shutdown
    await asyncio.sleep(0.1)


@pytest.mark.parametrize("web_server_endpoint_type", ("https",))
@pytest.mark.usefixtures("loop")
@pytest.mark.skipif(
    ASYNCIO_SUPPORTS_TLS_IN_TLS, reason="asyncio on this python supports TLS in TLS"
)
@pytest.mark.filterwarnings(r"ignore:.*ssl.OP_NO_SSL*")
# Filter out the warning from
# https://github.com/abhinavsingh/proxy.py/blob/30574fd0414005dfa8792a6e797023e862bdcf43/proxy/common/utils.py#L226
# otherwise this test will fail because the proxy will die with an error.
async def test_https_proxy_unsupported_tls_in_tls(
    client_ssl_ctx: ssl.SSLContext,
    secure_proxy_url: URL,
    web_server_endpoint_type: str,
) -> None:
    """Ensure connecting to TLS endpoints w/ HTTPS proxy needs patching.

    This also checks that a helpful warning on how to patch the env
    is displayed.
    """
    url = URL.build(scheme=web_server_endpoint_type, host="python.org")

    escaped_host_port = ":".join((url.host.replace(".", r"\."), str(url.port)))
    escaped_proxy_url = str(secure_proxy_url).replace(".", r"\.")

    conn = aiohttp.TCPConnector()
    sess = aiohttp.ClientSession(connector=conn)

    expected_warning_text = (
        r"^"
        r"An HTTPS request is being sent through an HTTPS proxy\. "
        "This support for TLS in TLS is known to be disabled "
        r"in the stdlib asyncio \(Python <3\.11\)\. This is why you'll probably see "
        r"an error in the log below\.\n\n"
        r"It is possible to enable it via monkeypatching\. "
        r"For more details, see:\n"
        r"\* https://bugs\.python\.org/issue37179\n"
        r"\* https://github\.com/python/cpython/pull/28073\n\n"
        r"You can temporarily patch this as follows:\n"
        r"\* https://docs\.aiohttp\.org/en/stable/client_advanced\.html#proxy-support\n"
        r"\* https://github\.com/aio-libs/aiohttp/discussions/6044\n$"
    )
    type_err = (
        r"transport <asyncio\.sslproto\._SSLProtocolTransport object at "
        r"0x[\d\w]+> is not supported by start_tls\(\)"
    )
    expected_exception_reason = (
        r"^"
        "Cannot initialize a TLS-in-TLS connection to host "
        f"{escaped_host_port!s} through an underlying connection "
        f"to an HTTPS proxy {escaped_proxy_url!s} ssl:{client_ssl_ctx!s} "
        f"[{type_err!s}]"
        r"$"
    )

    with pytest.warns(
        RuntimeWarning,
        match=expected_warning_text,
    ), pytest.raises(
        ClientConnectionError,
        match=expected_exception_reason,
    ) as conn_err:
        async with sess.get(url, proxy=secure_proxy_url, ssl=client_ssl_ctx):
            pass

    assert isinstance(conn_err.value.__cause__, TypeError)
    assert match_regex(f"^{type_err!s}$", str(conn_err.value.__cause__))

    await sess.close()
    await conn.close()

    await asyncio.sleep(0.1)


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
        async with aiohttp.ClientSession(
            connector=connector, trust_env=trust_env
        ) as client:
            async with client.request(method, url, **kwargs) as resp:
                return resp

    return _request


async def test_proxy_http_absolute_path(proxy_test_server, get_request) -> None:
    url = "http://aiohttp.io/path?query=yes"
    proxy = await proxy_test_server()

    await get_request(url=url, proxy=proxy.url)

    assert len(proxy.requests_list) == 1
    assert proxy.request.method == "GET"
    assert proxy.request.host == "aiohttp.io"
    assert proxy.request.path_qs == "/path?query=yes"


async def test_proxy_http_raw_path(proxy_test_server, get_request) -> None:
    url = "http://aiohttp.io:2561/space sheep?q=can:fly"
    raw_url = "/space%20sheep?q=can:fly"
    proxy = await proxy_test_server()

    await get_request(url=url, proxy=proxy.url)

    assert proxy.request.host == "aiohttp.io"
    assert proxy.request.path_qs == raw_url


async def test_proxy_http_idna_support(proxy_test_server, get_request) -> None:
    url = "http://éé.com/"
    proxy = await proxy_test_server()

    await get_request(url=url, proxy=proxy.url)

    assert proxy.request.host == "éé.com"
    assert proxy.request.path_qs == "/"


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

    async with sess.get(url, proxy=proxy.url) as resp:
        pass
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
        async with sess.get(url, proxy=proxy.url):
            assert 1 == len(conn._acquired)

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

        async with sess.get(url, proxy=proxy.url) as resp:
            current_pid = pid
            await asyncio.sleep(0.2, loop=loop)
            assert current_pid == pid

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
    proxy.return_value = {"status": 200, "body": b"1" * (2**20)}
    url = "https://www.google.com.ua/search?q=aiohttp proxy"

    async with sess.get(url, proxy=proxy.url) as resp:
        body = await resp.read()
    await sess.close()

    assert body == b"1" * (2**20)


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
        async with sess.get(url, proxy=proxy.url):
            assert 1 == len(conn._acquired)

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
        async with sess.get(url, proxy=proxy.url):
            assert 1 == len(conn._acquired)

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

        async with sess.get(url, proxy=proxy.url) as resp:
            current_pid = pid
            await asyncio.sleep(0.2, loop=loop)
            assert current_pid == pid

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
    assert proxy.request.path_qs == "/path"
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
    assert proxy.request.path_qs == "/path"
    assert proxy.request.headers["Proxy-Authorization"] == auth.encode()


async def test_proxy_from_env_http_with_auth_from_netrc(
    proxy_test_server, get_request, tmp_path, mocker
):
    url = "http://aiohttp.io/path"
    proxy = await proxy_test_server()
    auth = aiohttp.BasicAuth("user", "pass")
    netrc_file = tmp_path / "test_netrc"
    netrc_file_data = "machine 127.0.0.1 login {} password {}".format(
        auth.login,
        auth.password,
    )
    with netrc_file.open("w") as f:
        f.write(netrc_file_data)
    mocker.patch.dict(
        os.environ, {"http_proxy": str(proxy.url), "NETRC": str(netrc_file)}
    )

    await get_request(url=url, trust_env=True)

    assert len(proxy.requests_list) == 1
    assert proxy.request.method == "GET"
    assert proxy.request.host == "aiohttp.io"
    assert proxy.request.path_qs == "/path"
    assert proxy.request.headers["Proxy-Authorization"] == auth.encode()


async def test_proxy_from_env_http_without_auth_from_netrc(
    proxy_test_server, get_request, tmp_path, mocker
):
    url = "http://aiohttp.io/path"
    proxy = await proxy_test_server()
    auth = aiohttp.BasicAuth("user", "pass")
    netrc_file = tmp_path / "test_netrc"
    netrc_file_data = "machine 127.0.0.2 login {} password {}".format(
        auth.login,
        auth.password,
    )
    with netrc_file.open("w") as f:
        f.write(netrc_file_data)
    mocker.patch.dict(
        os.environ, {"http_proxy": str(proxy.url), "NETRC": str(netrc_file)}
    )

    await get_request(url=url, trust_env=True)

    assert len(proxy.requests_list) == 1
    assert proxy.request.method == "GET"
    assert proxy.request.host == "aiohttp.io"
    assert proxy.request.path_qs == "/path"
    assert "Proxy-Authorization" not in proxy.request.headers


async def test_proxy_from_env_http_without_auth_from_wrong_netrc(
    proxy_test_server, get_request, tmp_path, mocker
):
    url = "http://aiohttp.io/path"
    proxy = await proxy_test_server()
    auth = aiohttp.BasicAuth("user", "pass")
    netrc_file = tmp_path / "test_netrc"
    invalid_data = f"machine 127.0.0.1 {auth.login} pass {auth.password}"
    with netrc_file.open("w") as f:
        f.write(invalid_data)

    mocker.patch.dict(
        os.environ, {"http_proxy": str(proxy.url), "NETRC": str(netrc_file)}
    )

    await get_request(url=url, trust_env=True)

    assert len(proxy.requests_list) == 1
    assert proxy.request.method == "GET"
    assert proxy.request.host == "aiohttp.io"
    assert proxy.request.path_qs == "/path"
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
    assert proxy.request.path_qs == "/path"
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
            async with session.get(
                "http://python.org",
                proxy="http://proxy.example.com",
                proxy_auth=("user", "pass"),
            ):
                pass
