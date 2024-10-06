import asyncio
import gzip
import sys
from socket import socket
from typing import Any, Iterator
from unittest import mock

import pytest
from multidict import CIMultiDict, CIMultiDictProxy
from yarl import URL

import aiohttp
from aiohttp import web
from aiohttp.pytest_plugin import AiohttpClient
from aiohttp.test_utils import (
    AioHTTPTestCase,
    RawTestServer as _RawTestServer,
    TestClient,
    TestServer,
    get_port_socket,
    loop_context,
    make_mocked_request,
    unittest_run_loop,
)

if sys.version_info >= (3, 11):
    from typing import assert_type

_TestClient = TestClient[web.Request, web.Application]

_hello_world_str = "Hello, world"
_hello_world_bytes = _hello_world_str.encode("utf-8")
_hello_world_gz = gzip.compress(_hello_world_bytes)


def _create_example_app():
    async def hello(request):
        return web.Response(body=_hello_world_bytes)

    async def websocket_handler(request):

        ws = web.WebSocketResponse()
        await ws.prepare(request)
        msg = await ws.receive()
        if msg.type == aiohttp.WSMsgType.TEXT:
            if msg.data == "close":
                await ws.close()
            else:
                await ws.send_str(msg.data + "/answer")

        return ws

    async def cookie_handler(request):
        resp = web.Response(body=_hello_world_bytes)
        resp.set_cookie("cookie", "val")
        return resp

    app = web.Application()
    app.router.add_route("*", "/", hello)
    app.router.add_route("*", "/websocket", websocket_handler)
    app.router.add_route("*", "/cookie", cookie_handler)
    return app


# these exist to test the pytest scenario
@pytest.fixture
def loop():
    with loop_context() as loop:
        yield loop


@pytest.fixture
def app():
    return _create_example_app()


@pytest.fixture
def test_client(
    loop: asyncio.AbstractEventLoop, app: web.Application
) -> Iterator[_TestClient]:
    async def make_client() -> TestClient[web.Request, web.Application]:
        return TestClient(TestServer(app))

    client = loop.run_until_complete(make_client())

    loop.run_until_complete(client.start_server())
    yield client
    loop.run_until_complete(client.close())


def test_with_test_server_fails(loop) -> None:
    app = _create_example_app()
    with pytest.raises(TypeError):
        with TestServer(app, loop=loop):
            pass


async def test_with_client_fails(loop) -> None:
    app = _create_example_app()
    with pytest.raises(TypeError):
        with _TestClient(TestServer(app, loop=loop), loop=loop):
            pass


async def test_aiohttp_client_close_is_idempotent() -> None:
    # a test client, called multiple times, should
    # not attempt to close the server again.
    app = _create_example_app()
    client = _TestClient(TestServer(app))
    await client.close()
    await client.close()


class TestAioHTTPTestCase(AioHTTPTestCase):
    def get_app(self):
        return _create_example_app()

    async def test_example_with_loop(self) -> None:
        request = await self.client.request("GET", "/")
        assert request.status == 200
        text = await request.text()
        assert _hello_world_str == text

    def test_inner_example(self) -> None:
        async def test_get_route() -> None:
            resp = await self.client.request("GET", "/")
            assert resp.status == 200
            text = await resp.text()
            assert _hello_world_str == text

        self.loop.run_until_complete(test_get_route())

    async def test_example_without_explicit_loop(self) -> None:
        request = await self.client.request("GET", "/")
        assert request.status == 200
        text = await request.text()
        assert _hello_world_str == text

    async def test_inner_example_without_explicit_loop(self) -> None:
        async def test_get_route() -> None:
            resp = await self.client.request("GET", "/")
            assert resp.status == 200
            text = await resp.text()
            assert _hello_world_str == text

        await test_get_route()


def test_unittest_run_loop() -> None:
    with pytest.warns(
        DeprecationWarning,
        match=r"Decorator `@unittest_run_loop` is no longer needed in aiohttp 3\.8\+",
    ):

        @unittest_run_loop
        def foo():
            pass


def test_get_route(loop, test_client) -> None:
    async def test_get_route() -> None:
        resp = await test_client.request("GET", "/")
        assert resp.status == 200
        text = await resp.text()
        assert _hello_world_str == text

    loop.run_until_complete(test_get_route())


async def test_client_websocket(loop, test_client) -> None:
    resp = await test_client.ws_connect("/websocket")
    await resp.send_str("foo")
    msg = await resp.receive()
    assert msg.type == aiohttp.WSMsgType.TEXT
    assert "foo" in msg.data
    await resp.send_str("close")
    msg = await resp.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE


async def test_client_cookie(loop, test_client) -> None:
    assert not test_client.session.cookie_jar
    await test_client.get("/cookie")
    cookies = list(test_client.session.cookie_jar)
    assert cookies[0].key == "cookie"
    assert cookies[0].value == "val"


@pytest.mark.parametrize(
    "method", ["get", "post", "options", "post", "put", "patch", "delete"]
)
async def test_test_client_methods(method, loop, test_client) -> None:
    resp = await getattr(test_client, method)("/")
    assert resp.status == 200
    text = await resp.text()
    assert _hello_world_str == text


async def test_test_client_head(loop, test_client) -> None:
    resp = await test_client.head("/")
    assert resp.status == 200


@pytest.mark.parametrize("headers", [{"token": "x"}, CIMultiDict({"token": "x"}), {}])
def test_make_mocked_request(headers) -> None:
    req = make_mocked_request("GET", "/", headers=headers)
    assert req.method == "GET"
    assert req.path == "/"
    assert isinstance(req, web.Request)
    assert isinstance(req.headers, CIMultiDictProxy)


def test_make_mocked_request_sslcontext() -> None:
    req = make_mocked_request("GET", "/")
    assert req.transport.get_extra_info("sslcontext") is None


def test_make_mocked_request_unknown_extra_info() -> None:
    req = make_mocked_request("GET", "/")
    assert req.transport.get_extra_info("unknown_extra_info") is None


def test_make_mocked_request_app() -> None:
    app = mock.Mock()
    req = make_mocked_request("GET", "/", app=app)
    assert req.app is app


def test_make_mocked_request_app_can_store_values() -> None:
    req = make_mocked_request("GET", "/")
    req.app["a_field"] = "a_value"
    assert req.app["a_field"] == "a_value"


def test_make_mocked_request_app_access_non_existing() -> None:
    req = make_mocked_request("GET", "/")
    with pytest.raises(AttributeError):
        req.app.foo


def test_make_mocked_request_match_info() -> None:
    req = make_mocked_request("GET", "/", match_info={"a": "1", "b": "2"})
    assert req.match_info == {"a": "1", "b": "2"}


def test_make_mocked_request_content() -> None:
    payload = mock.Mock()
    req = make_mocked_request("GET", "/", payload=payload)
    assert req.content is payload


async def test_make_mocked_request_empty_payload() -> None:
    req = make_mocked_request("GET", "/")
    assert await req.read() == b""


def test_make_mocked_request_transport() -> None:
    transport = mock.Mock()
    req = make_mocked_request("GET", "/", transport=transport)
    assert req.transport is transport


async def test_test_client_props(loop) -> None:
    app = _create_example_app()
    client = _TestClient(TestServer(app, host="127.0.0.1", loop=loop), loop=loop)
    assert client.host == "127.0.0.1"
    assert client.port is None
    async with client:
        assert isinstance(client.port, int)
        assert client.server is not None
        if sys.version_info >= (3, 11):
            assert_type(client.app, web.Application)
        assert client.app is not None
    assert client.port is None


async def test_test_client_raw_server_props(loop) -> None:
    async def hello(request):
        return web.Response()  # pragma: no cover

    client = _TestClient(_RawTestServer(hello, host="127.0.0.1", loop=loop), loop=loop)
    assert client.host == "127.0.0.1"
    assert client.port is None
    async with client:
        assert isinstance(client.port, int)
        assert client.server is not None
        if sys.version_info >= (3, 11):
            assert_type(client.app, None)
        assert client.app is None
    assert client.port is None


async def test_test_server_context_manager(loop) -> None:
    app = _create_example_app()
    async with TestServer(app, loop=loop) as server:
        client = aiohttp.ClientSession(loop=loop)
        resp = await client.head(server.make_url("/"))
        assert resp.status == 200
        resp.close()
        await client.close()


def test_client_unsupported_arg() -> None:
    with pytest.raises(TypeError) as e:
        TestClient("string")  # type: ignore[call-overload]

    assert (
        str(e.value) == "server must be TestServer instance, found type: <class 'str'>"
    )


async def test_server_make_url_yarl_compatibility(loop) -> None:
    app = _create_example_app()
    async with TestServer(app, loop=loop) as server:
        make_url = server.make_url
        assert make_url(URL("/foo")) == make_url("/foo")
        with pytest.raises(AssertionError):
            make_url("http://foo.com")
        with pytest.raises(AssertionError):
            make_url(URL("http://foo.com"))


def test_testcase_no_app(testdir, loop) -> None:
    testdir.makepyfile(
        """
        from aiohttp.test_utils import AioHTTPTestCase


        class InvalidTestCase(AioHTTPTestCase):
            def test_noop(self) -> None:
                pass
        """
    )
    result = testdir.runpytest()
    result.stdout.fnmatch_lines(["*RuntimeError*"])


async def test_disable_retry_persistent_connection(
    aiohttp_client: AiohttpClient,
) -> None:
    num_requests = 0

    async def handler(request: web.Request) -> web.Response:
        nonlocal num_requests

        num_requests += 1
        request.protocol.force_close()
        return web.Response()

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)
    with pytest.raises(aiohttp.ServerDisconnectedError):
        await client.get("/")

    assert num_requests == 1


async def test_server_context_manager(app, loop) -> None:
    async with TestServer(app, loop=loop) as server:
        async with aiohttp.ClientSession(loop=loop) as client:
            async with client.head(server.make_url("/")) as resp:
                assert resp.status == 200


@pytest.mark.parametrize(
    "method", ["head", "get", "post", "options", "post", "put", "patch", "delete"]
)
async def test_client_context_manager_response(method, app, loop) -> None:
    async with _TestClient(TestServer(app), loop=loop) as client:
        async with getattr(client, method)("/") as resp:
            assert resp.status == 200
            if method != "head":
                text = await resp.text()
                assert "Hello, world" in text


async def test_custom_port(loop, app, aiohttp_unused_port) -> None:
    port = aiohttp_unused_port()
    client = _TestClient(TestServer(app, loop=loop, port=port), loop=loop)
    await client.start_server()

    assert client.server.port == port

    resp = await client.get("/")
    assert resp.status == 200
    text = await resp.text()
    assert _hello_world_str == text

    await client.close()


@pytest.mark.parametrize("test_server_cls", [TestServer, _RawTestServer])
async def test_base_test_server_socket_factory(
    test_server_cls: type, app: Any, loop: Any
) -> None:
    factory_called = False

    def factory(*args, **kwargs) -> socket:
        nonlocal factory_called
        factory_called = True
        return get_port_socket(*args, **kwargs)

    server = test_server_cls(app, loop=loop, socket_factory=factory)
    async with server:
        pass

    assert factory_called


@pytest.mark.parametrize(
    ("hostname", "expected_host"),
    [("127.0.0.1", "127.0.0.1"), ("localhost", "127.0.0.1"), ("::1", "::1")],
)
async def test_test_server_hostnames(hostname, expected_host, loop) -> None:
    app = _create_example_app()
    server = TestServer(app, host=hostname, loop=loop)
    async with server:
        pass
    assert server.host == expected_host
