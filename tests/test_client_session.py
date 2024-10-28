import asyncio
import contextlib
import gc
import io
import json
from http.cookies import SimpleCookie
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterator,
    List,
    NoReturn,
    TypedDict,
    Union,
)
from unittest import mock
from uuid import uuid4

import pytest
from multidict import CIMultiDict, MultiDict
from pytest_mock import MockerFixture
from yarl import URL

import aiohttp
from aiohttp import client, hdrs, tracing, web
from aiohttp.client import ClientSession
from aiohttp.client_proto import ResponseHandler
from aiohttp.client_reqrep import ClientRequest, ConnectionKey
from aiohttp.connector import BaseConnector, Connection, TCPConnector, UnixConnector
from aiohttp.cookiejar import CookieJar
from aiohttp.http import RawResponseMessage
from aiohttp.pytest_plugin import AiohttpClient, AiohttpServer
from aiohttp.test_utils import make_mocked_coro
from aiohttp.tracing import Trace


class _Params(TypedDict):
    headers: Dict[str, str]
    max_redirects: int
    compress: str
    chunked: bool
    expect100: bool
    read_until_eof: bool


@pytest.fixture
def connector(
    loop: asyncio.AbstractEventLoop, create_mocked_conn: Callable[[], ResponseHandler]
) -> Iterator[BaseConnector]:
    async def make_conn() -> BaseConnector:
        return BaseConnector()

    key = ConnectionKey("localhost", 80, False, True, None, None, None)
    conn = loop.run_until_complete(make_conn())
    proto = create_mocked_conn()
    conn._conns[key] = [(proto, 123)]
    yield conn
    loop.run_until_complete(conn.close())


@pytest.fixture
def create_session(
    loop: asyncio.AbstractEventLoop,
) -> Iterator[Callable[..., Awaitable[ClientSession]]]:
    session = None

    async def maker(*args: Any, **kwargs: Any) -> ClientSession:
        nonlocal session
        session = ClientSession(*args, **kwargs)
        return session

    yield maker
    if session is not None:
        loop.run_until_complete(session.close())


@pytest.fixture
def session(
    create_session: Callable[..., Awaitable[ClientSession]],
    loop: asyncio.AbstractEventLoop,
) -> ClientSession:
    return loop.run_until_complete(create_session())


@pytest.fixture
def params() -> _Params:
    return dict(
        headers={"Authorization": "Basic ..."},
        max_redirects=2,
        compress="deflate",
        chunked=True,
        expect100=True,
        read_until_eof=False,
    )


async def test_close_coro(
    create_session: Callable[..., Awaitable[ClientSession]]
) -> None:
    session = await create_session()
    await session.close()


async def test_init_headers_simple_dict(
    create_session: Callable[..., Awaitable[ClientSession]]
) -> None:
    session = await create_session(headers={"h1": "header1", "h2": "header2"})
    assert sorted(session.headers.items()) == ([("h1", "header1"), ("h2", "header2")])


async def test_init_headers_list_of_tuples(
    create_session: Callable[..., Awaitable[ClientSession]]
) -> None:
    session = await create_session(
        headers=[("h1", "header1"), ("h2", "header2"), ("h3", "header3")]
    )
    assert session.headers == CIMultiDict(
        [("h1", "header1"), ("h2", "header2"), ("h3", "header3")]
    )


async def test_init_headers_MultiDict(
    create_session: Callable[..., Awaitable[ClientSession]]
) -> None:
    session = await create_session(
        headers=MultiDict([("h1", "header1"), ("h2", "header2"), ("h3", "header3")])
    )
    assert session.headers == CIMultiDict(
        [("H1", "header1"), ("H2", "header2"), ("H3", "header3")]
    )


async def test_init_headers_list_of_tuples_with_duplicates(
    create_session: Callable[..., Awaitable[ClientSession]]
) -> None:
    session = await create_session(
        headers=[("h1", "header11"), ("h2", "header21"), ("h1", "header12")]
    )
    assert session.headers == CIMultiDict(
        [("H1", "header11"), ("H2", "header21"), ("H1", "header12")]
    )


async def test_init_cookies_with_simple_dict(
    create_session: Callable[..., Awaitable[ClientSession]]
) -> None:
    session = await create_session(cookies={"c1": "cookie1", "c2": "cookie2"})
    cookies = session.cookie_jar.filter_cookies(URL())
    assert set(cookies) == {"c1", "c2"}
    assert cookies["c1"].value == "cookie1"
    assert cookies["c2"].value == "cookie2"


async def test_init_cookies_with_list_of_tuples(
    create_session: Callable[..., Awaitable[ClientSession]]
) -> None:
    session = await create_session(cookies=[("c1", "cookie1"), ("c2", "cookie2")])

    cookies = session.cookie_jar.filter_cookies(URL())
    assert set(cookies) == {"c1", "c2"}
    assert cookies["c1"].value == "cookie1"
    assert cookies["c2"].value == "cookie2"


async def test_merge_headers(
    create_session: Callable[..., Awaitable[ClientSession]]
) -> None:
    # Check incoming simple dict
    session = await create_session(headers={"h1": "header1", "h2": "header2"})
    headers = session._prepare_headers({"h1": "h1"})

    assert isinstance(headers, CIMultiDict)
    assert headers == {"h1": "h1", "h2": "header2"}


async def test_merge_headers_with_multi_dict(
    create_session: Callable[..., Awaitable[ClientSession]]
) -> None:
    session = await create_session(headers={"h1": "header1", "h2": "header2"})
    headers = session._prepare_headers(MultiDict([("h1", "h1")]))
    assert isinstance(headers, CIMultiDict)
    assert headers == {"h1": "h1", "h2": "header2"}


async def test_merge_headers_with_list_of_tuples(
    create_session: Callable[..., Awaitable[ClientSession]]
) -> None:
    session = await create_session(headers={"h1": "header1", "h2": "header2"})
    headers = session._prepare_headers([("h1", "h1")])
    assert isinstance(headers, CIMultiDict)
    assert headers == {"h1": "h1", "h2": "header2"}


async def test_merge_headers_with_list_of_tuples_duplicated_names(
    create_session: Callable[..., Awaitable[ClientSession]],
) -> None:
    session = await create_session(headers={"h1": "header1", "h2": "header2"})

    headers = session._prepare_headers([("h1", "v1"), ("h1", "v2")])

    assert isinstance(headers, CIMultiDict)
    assert list(sorted(headers.items())) == [
        ("h1", "v1"),
        ("h1", "v2"),
        ("h2", "header2"),
    ]


@pytest.mark.parametrize("obj", (object(), None))
async def test_invalid_data(session: ClientSession, obj: object) -> None:
    with pytest.raises(TypeError, match="expected str"):
        await session.post("http://example.test/", data={"some": obj})


async def test_http_GET(session: ClientSession, params: _Params) -> None:
    with mock.patch(
        "aiohttp.client.ClientSession._request", autospec=True, spec_set=True
    ) as patched:
        await session.get("http://test.example.com", params={"x": 1}, **params)
    assert patched.called, "`ClientSession._request` not called"
    assert list(patched.call_args) == [
        (session, "GET", "http://test.example.com"),
        dict(params={"x": 1}, allow_redirects=True, **params),
    ]


async def test_http_OPTIONS(session: ClientSession, params: _Params) -> None:
    with mock.patch(
        "aiohttp.client.ClientSession._request", autospec=True, spec_set=True
    ) as patched:
        await session.options("http://opt.example.com", params={"x": 2}, **params)
    assert patched.called, "`ClientSession._request` not called"
    assert list(patched.call_args) == [
        (session, "OPTIONS", "http://opt.example.com"),
        dict(params={"x": 2}, allow_redirects=True, **params),
    ]


async def test_http_HEAD(session: ClientSession, params: _Params) -> None:
    with mock.patch(
        "aiohttp.client.ClientSession._request", autospec=True, spec_set=True
    ) as patched:
        await session.head("http://head.example.com", params={"x": 2}, **params)
    assert patched.called, "`ClientSession._request` not called"
    assert list(patched.call_args) == [
        (session, "HEAD", "http://head.example.com"),
        dict(params={"x": 2}, allow_redirects=False, **params),
    ]


async def test_http_POST(session: ClientSession, params: _Params) -> None:
    with mock.patch(
        "aiohttp.client.ClientSession._request", autospec=True, spec_set=True
    ) as patched:
        await session.post(
            "http://post.example.com", params={"x": 2}, data="Some_data", **params
        )
    assert patched.called, "`ClientSession._request` not called"
    assert list(patched.call_args) == [
        (session, "POST", "http://post.example.com"),
        dict(params={"x": 2}, data="Some_data", **params),
    ]


async def test_http_PUT(session: ClientSession, params: _Params) -> None:
    with mock.patch(
        "aiohttp.client.ClientSession._request", autospec=True, spec_set=True
    ) as patched:
        await session.put(
            "http://put.example.com", params={"x": 2}, data="Some_data", **params
        )
    assert patched.called, "`ClientSession._request` not called"
    assert list(patched.call_args) == [
        (session, "PUT", "http://put.example.com"),
        dict(params={"x": 2}, data="Some_data", **params),
    ]


async def test_http_PATCH(session: ClientSession, params: _Params) -> None:
    with mock.patch(
        "aiohttp.client.ClientSession._request", autospec=True, spec_set=True
    ) as patched:
        await session.patch(
            "http://patch.example.com", params={"x": 2}, data="Some_data", **params
        )
    assert patched.called, "`ClientSession._request` not called"
    assert list(patched.call_args) == [
        (session, "PATCH", "http://patch.example.com"),
        dict(params={"x": 2}, data="Some_data", **params),
    ]


async def test_http_DELETE(session: ClientSession, params: _Params) -> None:
    with mock.patch(
        "aiohttp.client.ClientSession._request", autospec=True, spec_set=True
    ) as patched:
        await session.delete("http://delete.example.com", params={"x": 2}, **params)
    assert patched.called, "`ClientSession._request` not called"
    assert list(patched.call_args) == [
        (session, "DELETE", "http://delete.example.com"),
        dict(params={"x": 2}, **params),
    ]


async def test_close(
    create_session: Callable[..., Awaitable[ClientSession]], connector: BaseConnector
) -> None:
    session = await create_session(connector=connector)

    await session.close()
    assert session.connector is None
    assert connector.closed


async def test_closed(session: ClientSession) -> None:
    assert not session.closed
    await session.close()
    assert session.closed


async def test_connector(
    create_session: Callable[..., Awaitable[ClientSession]],
    loop: asyncio.AbstractEventLoop,
    mocker: MockerFixture,
) -> None:
    connector = TCPConnector()
    m = mocker.spy(connector, "close")
    session = await create_session(connector=connector)
    assert session.connector is connector

    await session.close()
    assert m.called
    await connector.close()


async def test_create_connector(
    create_session: Callable[..., Awaitable[ClientSession]],
    loop: asyncio.AbstractEventLoop,
    mocker: MockerFixture,
) -> None:
    session = await create_session()
    m = mocker.spy(session.connector, "close")

    await session.close()
    assert m.called


def test_connector_loop(loop: asyncio.AbstractEventLoop) -> None:
    with contextlib.ExitStack() as stack:
        another_loop = asyncio.new_event_loop()
        stack.enter_context(contextlib.closing(another_loop))

        async def make_connector() -> TCPConnector:
            return TCPConnector()

        connector = another_loop.run_until_complete(make_connector())

        with pytest.raises(RuntimeError) as ctx:

            async def make_sess() -> ClientSession:
                return ClientSession(connector=connector)

            loop.run_until_complete(make_sess())
        expected = "Session and connector have to use same event loop"
        assert str(ctx.value).startswith(expected)
        another_loop.run_until_complete(connector.close())


def test_detach(loop: asyncio.AbstractEventLoop, session: ClientSession) -> None:
    conn = session.connector
    assert conn is not None
    try:
        assert not conn.closed
        session.detach()
        assert session.connector is None
        assert session.closed
        assert not conn.closed
    finally:
        loop.run_until_complete(conn.close())


async def test_request_closed_session(session: ClientSession) -> None:
    await session.close()
    with pytest.raises(RuntimeError):
        await session.request("get", "/")


async def test_close_flag_for_closed_connector(session: ClientSession) -> None:
    conn = session.connector
    assert conn is not None
    assert not session.closed
    await conn.close()
    assert session.closed


async def test_double_close(
    connector: BaseConnector, create_session: Callable[..., Awaitable[ClientSession]]
) -> None:
    session = await create_session(connector=connector)

    await session.close()
    assert session.connector is None
    await session.close()
    assert session.closed
    assert connector.closed


async def test_del(connector: BaseConnector, loop: asyncio.AbstractEventLoop) -> None:
    loop.set_debug(False)
    # N.B. don't use session fixture, it stores extra reference internally
    session = ClientSession(connector=connector)
    logs = []
    loop.set_exception_handler(lambda loop, ctx: logs.append(ctx))

    with pytest.warns(ResourceWarning):
        del session
        gc.collect()

    assert len(logs) == 1
    expected = {"client_session": mock.ANY, "message": "Unclosed client session"}
    assert logs[0] == expected


async def test_del_debug(
    connector: BaseConnector, loop: asyncio.AbstractEventLoop
) -> None:
    loop.set_debug(True)
    # N.B. don't use session fixture, it stores extra reference internally
    session = ClientSession(connector=connector)
    logs = []
    loop.set_exception_handler(lambda loop, ctx: logs.append(ctx))

    with pytest.warns(ResourceWarning):
        del session
        gc.collect()

    assert len(logs) == 1
    expected = {
        "client_session": mock.ANY,
        "message": "Unclosed client session",
        "source_traceback": mock.ANY,
    }
    assert logs[0] == expected


async def test_borrow_connector_loop(
    connector: BaseConnector,
    create_session: Callable[..., Awaitable[ClientSession]],
    loop: asyncio.AbstractEventLoop,
) -> None:
    async with ClientSession(connector=connector) as session:
        assert session._loop is loop


async def test_reraise_os_error(
    create_session: Callable[..., Awaitable[ClientSession]],
    create_mocked_conn: Callable[[], ResponseHandler],
) -> None:
    err = OSError(1, "permission error")
    req = mock.Mock()
    req_factory = mock.Mock(return_value=req)
    req.send = mock.Mock(side_effect=err)
    session = await create_session(request_class=req_factory)

    async def create_connection(
        req: object, traces: object, timeout: object
    ) -> ResponseHandler:
        # return self.transport, self.protocol
        return create_mocked_conn()

    with mock.patch.object(session._connector, "_create_connection", create_connection):
        with mock.patch.object(
            session._connector, "_release", autospec=True, spec_set=True
        ):
            with pytest.raises(aiohttp.ClientOSError) as ctx:
                await session.request("get", "http://example.com")
            e = ctx.value
            assert e.errno == err.errno
            assert e.strerror == err.strerror


async def test_close_conn_on_error(
    create_session: Callable[..., Awaitable[ClientSession]],
    create_mocked_conn: Callable[[], ResponseHandler],
) -> None:
    class UnexpectedException(BaseException):
        pass

    err = UnexpectedException("permission error")
    req = mock.Mock()
    req_factory = mock.Mock(return_value=req)
    req.send = mock.Mock(side_effect=err)
    session = await create_session(request_class=req_factory)

    connections = []
    assert session._connector is not None
    original_connect = session._connector.connect

    async def connect(
        req: ClientRequest, traces: List[Trace], timeout: aiohttp.ClientTimeout
    ) -> Connection:
        conn = await original_connect(req, traces, timeout)
        connections.append(conn)
        return conn

    async def create_connection(
        req: object, traces: object, timeout: object
    ) -> ResponseHandler:
        # return self.transport, self.protocol
        conn = create_mocked_conn()
        return conn

    with mock.patch.object(session._connector, "connect", connect):
        with mock.patch.object(
            session._connector, "_create_connection", create_connection
        ):
            with mock.patch.object(
                session._connector, "_release", autospec=True, spec_set=True
            ):
                with pytest.raises(UnexpectedException):
                    async with session.request("get", "http://example.com") as resp:
                        await resp.text()

                # normally called during garbage collection.  triggers an exception
                # if the connection wasn't already closed
                for c in connections:
                    c.__del__()


@pytest.mark.parametrize("protocol", ["http", "https", "ws", "wss"])
async def test_ws_connect_allowed_protocols(
    create_session: Callable[..., Awaitable[ClientSession]],
    create_mocked_conn: Callable[[], ResponseHandler],
    protocol: str,
    ws_key: str,
    key_data: bytes,
) -> None:
    resp = mock.create_autospec(aiohttp.ClientResponse)
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: "websocket",
        hdrs.CONNECTION: "upgrade",
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
    }
    resp.url = URL(f"{protocol}://example")
    resp.cookies = SimpleCookie()
    resp.start = mock.AsyncMock()

    req = mock.create_autospec(aiohttp.ClientRequest, spec_set=True)
    req_factory = mock.Mock(return_value=req)
    req.send = mock.AsyncMock(return_value=resp)
    # BaseConnector allows all high level protocols by default
    connector = BaseConnector()

    session = await create_session(connector=connector, request_class=req_factory)

    connections = []
    assert session._connector is not None
    original_connect = session._connector.connect

    async def connect(
        req: ClientRequest, traces: List[Trace], timeout: aiohttp.ClientTimeout
    ) -> Connection:
        conn = await original_connect(req, traces, timeout)
        connections.append(conn)
        return conn

    async def create_connection(
        req: object, traces: object, timeout: object
    ) -> ResponseHandler:
        return create_mocked_conn()

    connector = session._connector
    with mock.patch.object(connector, "connect", connect), mock.patch.object(
        connector, "_create_connection", create_connection
    ), mock.patch.object(connector, "_release"), mock.patch(
        "aiohttp.client.os"
    ) as m_os:
        m_os.urandom.return_value = key_data
        await session.ws_connect(f"{protocol}://example")

    # normally called during garbage collection.  triggers an exception
    # if the connection wasn't already closed
    for c in connections:
        c.close()
        c.__del__()

    await session.close()


@pytest.mark.parametrize("protocol", ["http", "https", "ws", "wss", "unix"])
async def test_ws_connect_unix_socket_allowed_protocols(
    create_session: Callable[..., Awaitable[ClientSession]],
    create_mocked_conn: Callable[[], ResponseHandler],
    protocol: str,
    ws_key: str,
    key_data: bytes,
) -> None:
    resp = mock.create_autospec(aiohttp.ClientResponse)
    resp.status = 101
    resp.headers = {
        hdrs.UPGRADE: "websocket",
        hdrs.CONNECTION: "upgrade",
        hdrs.SEC_WEBSOCKET_ACCEPT: ws_key,
    }
    resp.url = URL(f"{protocol}://example")
    resp.cookies = SimpleCookie()
    resp.start = mock.AsyncMock()

    req = mock.create_autospec(aiohttp.ClientRequest, spec_set=True)
    req_factory = mock.Mock(return_value=req)
    req.send = mock.AsyncMock(return_value=resp)
    # UnixConnector allows all high level protocols by default and unix sockets
    session = await create_session(
        connector=UnixConnector(path=""), request_class=req_factory
    )

    connections = []
    assert session._connector is not None
    original_connect = session._connector.connect

    async def connect(
        req: ClientRequest, traces: List[Trace], timeout: aiohttp.ClientTimeout
    ) -> Connection:
        conn = await original_connect(req, traces, timeout)
        connections.append(conn)
        return conn

    async def create_connection(
        req: object, traces: object, timeout: object
    ) -> ResponseHandler:
        return create_mocked_conn()

    connector = session._connector
    with mock.patch.object(connector, "connect", connect), mock.patch.object(
        connector, "_create_connection", create_connection
    ), mock.patch.object(connector, "_release"), mock.patch(
        "aiohttp.client.os"
    ) as m_os:
        m_os.urandom.return_value = key_data
        await session.ws_connect(f"{protocol}://example")

    # normally called during garbage collection.  triggers an exception
    # if the connection wasn't already closed
    for c in connections:
        c.close()
        c.__del__()

    await session.close()


async def test_cookie_jar_usage(
    loop: asyncio.AbstractEventLoop, aiohttp_client: AiohttpClient
) -> None:
    req_url = None

    jar = mock.Mock()
    jar.filter_cookies.return_value = None

    async def handler(request: web.Request) -> web.Response:
        nonlocal req_url
        req_url = "http://%s/" % request.host

        resp = web.Response()
        resp.set_cookie("response", "resp_value")
        return resp

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    session = await aiohttp_client(
        app, cookies={"request": "req_value"}, cookie_jar=jar
    )

    # Updating the cookie jar with initial user defined cookies
    jar.update_cookies.assert_called_with({"request": "req_value"})

    jar.update_cookies.reset_mock()
    resp = await session.get("/")
    resp.release()
    assert req_url is not None

    # Filtering the cookie jar before sending the request,
    # getting the request URL as only parameter
    jar.filter_cookies.assert_called_with(URL(req_url))

    # Updating the cookie jar with the response cookies
    assert jar.update_cookies.called
    resp_cookies = jar.update_cookies.call_args[0][0]
    assert isinstance(resp_cookies, SimpleCookie)
    assert "response" in resp_cookies
    assert resp_cookies["response"].value == "resp_value"


@pytest.mark.xfail(reason="Reproducer for #9336")
async def test_cookies_with_not_quoted_cookie_jar(
    aiohttp_server: AiohttpServer,
) -> None:
    async def handler(_: web.Request) -> web.Response:
        return web.Response()

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    server = await aiohttp_server(app)
    jar = CookieJar(quote_cookie=False)
    cookies = {"name": "val=foobar"}
    async with aiohttp.ClientSession(cookie_jar=jar) as sess:
        resp = await sess.request("GET", server.make_url("/"), cookies=cookies)
    assert resp.request_info.headers.get("Cookie", "") == "name=val=foobar"


async def test_session_default_version(loop: asyncio.AbstractEventLoop) -> None:
    session = aiohttp.ClientSession()
    assert session.version == aiohttp.HttpVersion11
    await session.close()


async def test_proxy_str(session: ClientSession, params: _Params) -> None:
    with mock.patch(
        "aiohttp.client.ClientSession._request", autospec=True, spec_set=True
    ) as patched:
        await session.get("http://test.example.com", proxy="http://proxy.com", **params)
    assert patched.called, "`ClientSession._request` not called"
    assert list(patched.call_args) == [
        (session, "GET", "http://test.example.com"),
        dict(allow_redirects=True, proxy="http://proxy.com", **params),
    ]


async def test_default_proxy(loop: asyncio.AbstractEventLoop) -> None:
    proxy_url = URL("http://proxy.example.com")
    proxy_auth = mock.Mock()
    proxy_url2 = URL("http://proxy.example2.com")
    proxy_auth2 = mock.Mock()

    class OnCall(Exception):
        pass

    request_class_mock = mock.Mock(side_effect=OnCall())
    session = ClientSession(
        proxy=proxy_url, proxy_auth=proxy_auth, request_class=request_class_mock
    )

    assert session._default_proxy == proxy_url, "`ClientSession._default_proxy` not set"
    assert (
        session._default_proxy_auth == proxy_auth
    ), "`ClientSession._default_proxy_auth` not set"

    with pytest.raises(OnCall):
        await session.get(
            "http://example.com",
        )

    assert request_class_mock.called, "request class not called"
    assert (
        request_class_mock.call_args[1].get("proxy") == proxy_url
    ), "`ClientSession._request` uses default proxy not one used in ClientSession.get"
    assert (
        request_class_mock.call_args[1].get("proxy_auth") == proxy_auth
    ), "`ClientSession._request` uses default proxy_auth not one used in ClientSession.get"

    request_class_mock.reset_mock()
    with pytest.raises(OnCall):
        await session.get(
            "http://example.com", proxy=proxy_url2, proxy_auth=proxy_auth2
        )

    assert request_class_mock.called, "request class not called"
    assert (
        request_class_mock.call_args[1].get("proxy") == proxy_url2
    ), "`ClientSession._request` uses default proxy not one used in ClientSession.get"
    assert (
        request_class_mock.call_args[1].get("proxy_auth") == proxy_auth2
    ), "`ClientSession._request` uses default proxy_auth not one used in ClientSession.get"

    await session.close()


async def test_request_tracing(
    loop: asyncio.AbstractEventLoop, aiohttp_client: AiohttpClient
) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.json_response({"ok": True})

    app = web.Application()
    app.router.add_post("/", handler)

    trace_config_ctx = mock.Mock()
    body = "This is request body"
    gathered_req_headers: CIMultiDict[str] = CIMultiDict()
    on_request_start = mock.Mock(side_effect=make_mocked_coro(mock.Mock()))
    on_request_redirect = mock.Mock(side_effect=make_mocked_coro(mock.Mock()))
    on_request_end = mock.Mock(side_effect=make_mocked_coro(mock.Mock()))

    with io.BytesIO() as gathered_req_body, io.BytesIO() as gathered_res_body:

        async def on_request_chunk_sent(
            session: object,
            context: object,
            params: tracing.TraceRequestChunkSentParams,
        ) -> None:
            gathered_req_body.write(params.chunk)

        async def on_response_chunk_received(
            session: object,
            context: object,
            params: tracing.TraceResponseChunkReceivedParams,
        ) -> None:
            gathered_res_body.write(params.chunk)

        async def on_request_headers_sent(
            session: object,
            context: object,
            params: tracing.TraceRequestHeadersSentParams,
        ) -> None:
            gathered_req_headers.extend(**params.headers)

        trace_config = aiohttp.TraceConfig(
            trace_config_ctx_factory=mock.Mock(return_value=trace_config_ctx)
        )
        trace_config.on_request_start.append(on_request_start)
        trace_config.on_request_end.append(on_request_end)
        trace_config.on_request_chunk_sent.append(on_request_chunk_sent)
        trace_config.on_response_chunk_received.append(on_response_chunk_received)
        trace_config.on_request_redirect.append(on_request_redirect)
        trace_config.on_request_headers_sent.append(on_request_headers_sent)

        headers = CIMultiDict({"Custom-Header": "Custom value"})
        session = await aiohttp_client(
            app, trace_configs=[trace_config], headers=headers
        )

        async with session.post("/", data=body, trace_request_ctx={}) as resp:
            await resp.json()

            on_request_start.assert_called_once_with(
                session.session,
                trace_config_ctx,
                aiohttp.TraceRequestStartParams(
                    hdrs.METH_POST, session.make_url("/"), headers
                ),
            )

            on_request_end.assert_called_once_with(
                session.session,
                trace_config_ctx,
                aiohttp.TraceRequestEndParams(
                    hdrs.METH_POST, session.make_url("/"), headers, resp
                ),
            )
            assert not on_request_redirect.called
            assert gathered_req_body.getvalue() == body.encode("utf8")
            assert gathered_res_body.getvalue() == json.dumps({"ok": True}).encode(
                "utf8"
            )
            assert gathered_req_headers["Custom-Header"] == "Custom value"


async def test_request_tracing_url_params(
    loop: asyncio.AbstractEventLoop, aiohttp_client: AiohttpClient
) -> None:
    async def root_handler(request: web.Request) -> web.Response:
        return web.Response()

    async def redirect_handler(request: web.Request) -> NoReturn:
        raise web.HTTPFound("/")

    app = web.Application()
    app.router.add_get("/", root_handler)
    app.router.add_get("/redirect", redirect_handler)

    mocks = [mock.Mock(side_effect=make_mocked_coro(mock.Mock())) for _ in range(7)]
    (
        on_request_start,
        on_request_redirect,
        on_request_end,
        on_request_exception,
        on_request_chunk_sent,
        on_response_chunk_received,
        on_request_headers_sent,
    ) = mocks

    trace_config = aiohttp.TraceConfig(
        trace_config_ctx_factory=mock.Mock(return_value=mock.Mock())
    )
    trace_config.on_request_start.append(on_request_start)
    trace_config.on_request_redirect.append(on_request_redirect)
    trace_config.on_request_end.append(on_request_end)
    trace_config.on_request_exception.append(on_request_exception)
    trace_config.on_request_chunk_sent.append(on_request_chunk_sent)
    trace_config.on_response_chunk_received.append(on_response_chunk_received)
    trace_config.on_request_headers_sent.append(on_request_headers_sent)

    session = await aiohttp_client(app, trace_configs=[trace_config])

    def reset_mocks() -> None:
        for m in mocks:
            m.reset_mock()

    def to_trace_urls(mock_func: mock.Mock) -> List[URL]:
        return [call_args[0][-1].url for call_args in mock_func.call_args_list]

    def to_url(path: str) -> URL:
        return session.make_url(path)

    # Standard
    req: Callable[[], Awaitable[aiohttp.ClientResponse]]
    for req in (
        lambda: session.get("/?x=0"),
        lambda: session.get("/", params=dict(x=0)),
    ):
        reset_mocks()
        async with req() as resp:
            await resp.text()
            assert to_trace_urls(on_request_start) == [to_url("/?x=0")]
            assert to_trace_urls(on_request_redirect) == []
            assert to_trace_urls(on_request_end) == [to_url("/?x=0")]
            assert to_trace_urls(on_request_exception) == []
            assert to_trace_urls(on_request_chunk_sent) == [to_url("/?x=0")]
            assert to_trace_urls(on_response_chunk_received) == [to_url("/?x=0")]
            assert to_trace_urls(on_request_headers_sent) == [to_url("/?x=0")]

    # Redirect
    for req in (
        lambda: session.get("/redirect?x=0"),
        lambda: session.get("/redirect", params=dict(x=0)),
    ):
        reset_mocks()
        async with req() as resp:
            await resp.text()
            assert to_trace_urls(on_request_start) == [to_url("/redirect?x=0")]
            assert to_trace_urls(on_request_redirect) == [to_url("/redirect?x=0")]
            assert to_trace_urls(on_request_end) == [to_url("/")]
            assert to_trace_urls(on_request_exception) == []
            assert to_trace_urls(on_request_chunk_sent) == [
                to_url("/redirect?x=0"),
                to_url("/"),
            ]
            assert to_trace_urls(on_response_chunk_received) == [to_url("/")]
            assert to_trace_urls(on_request_headers_sent) == [
                to_url("/redirect?x=0"),
                to_url("/"),
            ]

    # Exception
    with mock.patch("aiohttp.client.TCPConnector.connect") as connect_patched:
        connect_patched.side_effect = Exception()

        for req in (
            lambda: session.get("/?x=0"),
            lambda: session.get("/", params=dict(x=0)),
        ):
            reset_mocks()
            with contextlib.suppress(Exception):
                await req()
            assert to_trace_urls(on_request_start) == [to_url("/?x=0")]
            assert to_trace_urls(on_request_redirect) == []
            assert to_trace_urls(on_request_end) == []
            assert to_trace_urls(on_request_exception) == [to_url("?x=0")]
            assert to_trace_urls(on_request_chunk_sent) == []
            assert to_trace_urls(on_response_chunk_received) == []
            assert to_trace_urls(on_request_headers_sent) == []


async def test_request_tracing_exception() -> None:
    on_request_end = mock.Mock(side_effect=make_mocked_coro(mock.Mock()))
    on_request_exception = mock.Mock(side_effect=make_mocked_coro(mock.Mock()))

    trace_config = aiohttp.TraceConfig()
    trace_config.on_request_end.append(on_request_end)
    trace_config.on_request_exception.append(on_request_exception)

    with mock.patch("aiohttp.client.TCPConnector.connect") as connect_patched:
        error = Exception()
        connect_patched.side_effect = error

        session = aiohttp.ClientSession(trace_configs=[trace_config])

        try:
            await session.get("http://example.com")
        except Exception:
            pass

        on_request_exception.assert_called_once_with(
            session,
            mock.ANY,
            aiohttp.TraceRequestExceptionParams(
                hdrs.METH_GET, URL("http://example.com"), CIMultiDict(), error
            ),
        )
        assert not on_request_end.called

    await session.close()


async def test_request_tracing_interpose_headers(
    loop: asyncio.AbstractEventLoop, aiohttp_client: AiohttpClient
) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response()

    app = web.Application()
    app.router.add_get("/", handler)

    headers: CIMultiDict[str] = CIMultiDict()

    class MyClientRequest(ClientRequest):
        def __init__(self, *args: Any, **kwargs: Any):
            nonlocal headers
            super().__init__(*args, **kwargs)
            headers = self.headers

    async def new_headers(
        session: object, trace_config_ctx: object, data: tracing.TraceRequestStartParams
    ) -> None:
        data.headers["foo"] = "bar"

    trace_config = aiohttp.TraceConfig()
    trace_config.on_request_start.append(new_headers)

    session = await aiohttp_client(
        app, request_class=MyClientRequest, trace_configs=[trace_config]
    )

    await session.get("/")
    assert headers["foo"] == "bar"


def test_client_session_inheritance() -> None:
    with pytest.raises(TypeError):

        class A(ClientSession):  # type: ignore[misc]
            pass


async def test_client_session_custom_attr() -> None:
    session = ClientSession()
    with pytest.raises(AttributeError):
        session.custom = None  # type: ignore[attr-defined]
    await session.close()


async def test_client_session_timeout_default_args(
    loop: asyncio.AbstractEventLoop,
) -> None:
    session1 = ClientSession()
    assert session1.timeout == client.DEFAULT_TIMEOUT
    await session1.close()


async def test_client_session_timeout_zero(
    create_mocked_conn: Callable[[], ResponseHandler]
) -> None:
    async def create_connection(
        req: object, traces: object, timeout: object
    ) -> ResponseHandler:
        await asyncio.sleep(0.01)
        conn = create_mocked_conn()
        conn.connected = True  # type: ignore[misc]
        assert conn.transport is not None
        conn.transport.is_closing.return_value = False  # type: ignore[attr-defined]
        msg = mock.create_autospec(RawResponseMessage, spec_set=True, code=200)
        conn.read.return_value = (msg, mock.Mock())  # type: ignore[attr-defined]
        return conn

    timeout = client.ClientTimeout(total=10, connect=0, sock_connect=0, sock_read=0)
    async with ClientSession(timeout=timeout) as session:
        with mock.patch.object(
            session._connector, "_create_connection", create_connection
        ):
            try:
                resp = await session.get("http://example.com")
            except asyncio.TimeoutError:  # pragma: no cover
                pytest.fail("0 should disable timeout.")
            resp.close()


async def test_client_session_timeout_bad_argument() -> None:
    with pytest.raises(ValueError):
        ClientSession(timeout="test_bad_argumnet")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        ClientSession(timeout=100)  # type: ignore[arg-type]


async def test_requote_redirect_url_default() -> None:
    session = ClientSession()
    assert session.requote_redirect_url
    await session.close()


async def test_requote_redirect_url_default_disable() -> None:
    session = ClientSession(requote_redirect_url=False)
    assert not session.requote_redirect_url
    await session.close()


@pytest.mark.parametrize(
    ("base_url", "url", "expected_url"),
    [
        pytest.param(
            None,
            "http://example.com/test",
            URL("http://example.com/test"),
            id="base_url=None url='http://example.com/test'",
        ),
        pytest.param(
            None,
            URL("http://example.com/test"),
            URL("http://example.com/test"),
            id="base_url=None url=URL('http://example.com/test')",
        ),
        pytest.param(
            "http://example.com",
            "/test",
            URL("http://example.com/test"),
            id="base_url='http://example.com' url='/test'",
        ),
        pytest.param(
            URL("http://example.com"),
            "/test",
            URL("http://example.com/test"),
            id="base_url=URL('http://example.com') url='/test'",
        ),
        pytest.param(
            URL("http://example.com/test1/"),
            "test2",
            URL("http://example.com/test1/test2"),
            id="base_url=URL('http://example.com/test1/') url='test2'",
        ),
        pytest.param(
            URL("http://example.com/test1/"),
            "/test2",
            URL("http://example.com/test2"),
            id="base_url=URL('http://example.com/test1/') url='/test2'",
        ),
        pytest.param(
            URL("http://example.com/test1/"),
            "test2?q=foo#bar",
            URL("http://example.com/test1/test2?q=foo#bar"),
            id="base_url=URL('http://example.com/test1/') url='test2?q=foo#bar'",
        )
    ],
)
async def test_build_url_returns_expected_url(
    create_session: Callable[..., Awaitable[ClientSession]],
    base_url: Union[URL, str, None],
    url: Union[URL, str],
    expected_url: URL,
) -> None:
    session = await create_session(base_url)
    assert session._build_url(url) == expected_url


async def test_base_url_without_trailing_slash() -> None:
    with pytest.raises(ValueError, match="base_url must have a trailing '/'"):
        ClientSession(base_url="http://example.com/test")


async def test_instantiation_with_invalid_timeout_value(
    loop: asyncio.AbstractEventLoop,
) -> None:
    loop.set_debug(False)
    logs = []
    loop.set_exception_handler(lambda loop, ctx: logs.append(ctx))
    with pytest.raises(ValueError, match="timeout parameter cannot be .*"):
        ClientSession(timeout=1)  # type: ignore[arg-type]
    # should not have "Unclosed client session" warning
    assert not logs


@pytest.mark.parametrize(
    ("outer_name", "inner_name"),
    [
        ("skip_auto_headers", "_skip_auto_headers"),
        ("auth", "_default_auth"),
        ("json_serialize", "_json_serialize"),
        ("connector_owner", "_connector_owner"),
        ("raise_for_status", "_raise_for_status"),
        ("trust_env", "_trust_env"),
        ("trace_configs", "_trace_configs"),
    ],
)
async def test_properties(
    session: ClientSession, outer_name: str, inner_name: str
) -> None:
    value = uuid4()
    setattr(session, inner_name, value)
    assert value == getattr(session, outer_name)
