import asyncio
from collections.abc import Callable
from unittest import mock

import pytest
from pytest_aiohttp import AiohttpClient, AiohttpRawServer, AiohttpServer

from aiohttp import web
from aiohttp.test_utils import TestClient
from aiohttp.web_protocol import RequestHandler


@pytest.fixture
async def advance_time(monkeypatch: pytest.MonkeyPatch) -> Callable[[float], None]:
    loop = asyncio.get_running_loop()
    original_time = loop.time
    offset = 0.0

    def time() -> float:
        return original_time() + offset

    def advance(seconds: float) -> None:
        nonlocal offset
        offset += seconds

    monkeypatch.setattr(loop, "time", time)
    return advance


@pytest.mark.parametrize("keepalive_time", [None, 5.0])
@pytest.mark.asyncio(loop_factories=("uvloop", "selector"))
async def test_keepalive_time_is_not_reset_by_requests(
    aiohttp_client: AiohttpClient,
    advance_time: Callable[[float], None],
    keepalive_time: float | None,
) -> None:
    transports: list[asyncio.Transport | None] = []

    async def handler(request: web.Request) -> web.Response:
        transports.append(request.transport)
        advance_time(2)
        return web.Response(text="ok")

    app = web.Application(
        handler_args={"keepalive_time": keepalive_time, "keepalive_timeout": 10}
    )
    app.router.add_get("/", handler)
    cli = await aiohttp_client(app)
    for index in range(4):
        response = await cli.get("/")
        assert await response.text() == "ok"
        if index == 2 and keepalive_time is not None:
            assert response.headers["Connection"] == "close"
    assert transports[0] is transports[1] is transports[2]
    if keepalive_time is None:
        assert transports[3] is transports[0]
    else:
        assert transports[3] is not transports[0]


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.asyncio(loop_factories=("uvloop", "selector"))
async def test_keepalive_time_finishes_active_response(
    aiohttp_raw_server: AiohttpRawServer,
    aiohttp_client: AiohttpClient,
    advance_time: Callable[[float], None],
    streaming: bool,
) -> None:
    async def handler(request: web.BaseRequest) -> web.StreamResponse:
        response = web.StreamResponse() if streaming else web.Response(text="done")
        if streaming:
            await response.prepare(request)
            await response.write(b"start")
        advance_time(10)
        request.protocol._process_keepalive()
        assert request.transport is not None
        assert not request.transport.is_closing()
        if streaming:
            await response.write(b"done")
        return response

    server = await aiohttp_raw_server(handler, keepalive_time=5)
    cli: TestClient[web.BaseRequest, None] = await aiohttp_client(server)
    response = await cli.get("/")
    assert await response.text() == ("startdone" if streaming else "done")
    if streaming:
        assert "Connection" not in response.headers
    else:
        assert response.headers["Connection"] == "close"
    assert response.closed
    assert not server.handler.connections


@pytest.mark.parametrize("version", ["1.0", "1.1"])
@pytest.mark.asyncio(loop_factories=("uvloop", "selector"))
async def test_keepalive_time_stops_pipelining(
    aiohttp_raw_server: AiohttpRawServer,
    advance_time: Callable[[float], None],
    version: str,
) -> None:
    paths = []

    async def handler(request: web.BaseRequest) -> web.Response:
        paths.append(request.path)
        advance_time(10)
        return web.Response(text="done", headers={"Connection": "keep-alive"})

    server = await aiohttp_raw_server(handler, keepalive_time=5)
    reader, writer = await asyncio.open_connection(server.host, server.port)
    try:
        writer.write(
            (
                f"GET /first HTTP/{version}\r\nHost: localhost\r\n"
                "Connection: keep-alive\r\n\r\n"
                f"GET /second HTTP/{version}\r\nHost: localhost\r\n"
                "Connection: keep-alive\r\n\r\n"
            ).encode()
        )
        await writer.drain()
        data = await asyncio.wait_for(reader.read(), 60)
        assert data.count(b"HTTP/") == 1
        assert b"Connection: close\r\n" in data
        assert data.endswith(b"done")
        assert paths == ["/first"]
    finally:
        writer.close()
        await writer.wait_closed()


@pytest.mark.parametrize("expire_before_upgrade", [False, True])
@pytest.mark.asyncio(loop_factories=("uvloop", "selector"))
async def test_keepalive_time_does_not_interrupt_websocket(
    aiohttp_client: AiohttpClient,
    advance_time: Callable[[float], None],
    expire_before_upgrade: bool,
) -> None:
    async def handler(request: web.Request) -> web.WebSocketResponse:
        if expire_before_upgrade:
            advance_time(10)
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        advance_time(10)
        request.protocol._process_keepalive()
        await ws.send_str("still open")
        await ws.receive()
        return ws

    app = web.Application(handler_args={"keepalive_time": 5})
    app.router.add_get("/", handler)
    cli = await aiohttp_client(app)
    ws = await cli.ws_connect("/")
    assert await ws.receive_str() == "still open"
    assert not ws.closed
    await ws.close()


@pytest.mark.parametrize("keepalive_time", [0, -1, float("inf"), float("nan")])
def test_keepalive_time_requires_positive_finite_value(
    event_loop: asyncio.AbstractEventLoop, keepalive_time: float
) -> None:
    with pytest.raises(ValueError, match="keepalive_time"):
        RequestHandler(mock.Mock(), loop=event_loop, keepalive_time=keepalive_time)


@pytest.mark.parametrize(
    ("idle_timeout", "lifetime", "expected"),
    [(10, None, 1010), (10, 5, 1005), (3, 5, 1003), (0, 5, 1005)],
)
async def test_keepalive_time_uses_earliest_deadline(
    idle_timeout: float,
    lifetime: float | None,
    expected: float,
) -> None:
    event_loop = asyncio.get_running_loop()
    with mock.patch.object(event_loop, "time", return_value=1000):
        protocol: RequestHandler[web.BaseRequest] = RequestHandler(
            mock.Mock(),
            loop=event_loop,
            tcp_keepalive=False,
            keepalive_timeout=idle_timeout,
            keepalive_time=lifetime,
        )
        protocol.connection_made(mock.Mock())
        handle = protocol._keepalive_handle
        assert isinstance(handle, asyncio.TimerHandle)
        assert handle.when() == expected
        protocol.connection_lost(None)
        assert handle.cancelled()
    await asyncio.sleep(0)


@pytest.mark.parametrize("cleanup", ["connection_lost", "shutdown"])
async def test_keepalive_time_cancels_deadline(cleanup: str) -> None:
    loop = asyncio.get_running_loop()
    server = web.Server(mock.AsyncMock(), keepalive_time=5, tcp_keepalive=False)
    protocol = server()
    protocol.connection_made(mock.Mock())
    handle = protocol._keepalive_handle
    assert handle is not None
    if cleanup == "shutdown":
        protocol.close()
        await protocol.shutdown()
    else:
        protocol.connection_lost(None)
    assert handle.cancelled()
    await asyncio.sleep(0)
    assert not [t for t in asyncio.all_tasks(loop) if t is protocol._task_handler]


@pytest.mark.parametrize(("lifetime", "idle", "elapsed"), [(5, 30, 10), (30, 3, 4)])
async def test_keepalive_time_closes_idle_connection(
    aiohttp_raw_server: AiohttpRawServer,
    aiohttp_client: AiohttpClient,
    advance_time: Callable[[float], None],
    lifetime: float,
    idle: float,
    elapsed: float,
) -> None:
    async def handler(request: web.BaseRequest) -> web.Response:
        return web.Response(text="ok")

    server = await aiohttp_raw_server(
        handler, keepalive_time=lifetime, keepalive_timeout=idle
    )
    cli: TestClient[web.BaseRequest, None] = await aiohttp_client(server)
    response = await cli.get("/")
    assert await response.text() == "ok"
    protocol = server.handler.connections[0]
    advance_time(elapsed)
    protocol._process_keepalive()
    assert protocol.transport is None


async def test_keepalive_time_expires_during_prepare_hook(
    aiohttp_client: AiohttpClient,
    aiohttp_server: AiohttpServer,
    advance_time: Callable[[float], None],
) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(text="ok", headers={"Connection": "keep-alive"})

    async def prepare(request: web.Request, response: web.StreamResponse) -> None:
        advance_time(10)

    app = web.Application()
    app.router.add_get("/", handler)
    app.on_response_prepare.append(prepare)
    server = await aiohttp_server(app, keepalive_time=5)
    cli: TestClient[web.Request, None] = await aiohttp_client(server)
    response = await cli.get("/")
    assert await response.text() == "ok"
    assert response.headers["Connection"] == "close"


async def test_keepalive_time_closes_before_first_request(
    aiohttp_raw_server: AiohttpRawServer,
    advance_time: Callable[[float], None],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def handler(request: web.BaseRequest) -> web.Response:
        pytest.fail("An idle connection should not call the handler")

    server = await aiohttp_raw_server(handler, keepalive_time=5, keepalive_timeout=0)
    connected = asyncio.Event()
    original = server.handler.connection_made

    def connection_made(
        protocol: RequestHandler[web.BaseRequest], transport: asyncio.Transport
    ) -> None:
        original(protocol, transport)
        connected.set()

    monkeypatch.setattr(server.handler, "connection_made", connection_made)
    reader, writer = await asyncio.open_connection(server.host, server.port)
    try:
        await connected.wait()
        protocol = server.handler.connections[0]
        advance_time(10)
        protocol._process_keepalive()
        assert await asyncio.wait_for(reader.read(), 5) == b""
        assert server.handler.requests_count == 0
    finally:
        writer.close()
        await writer.wait_closed()


async def test_keepalive_time_request_arrives_before_timeout_callback(
    aiohttp_raw_server: AiohttpRawServer,
    aiohttp_client: AiohttpClient,
    advance_time: Callable[[float], None],
) -> None:
    handler = mock.AsyncMock(return_value=web.Response(text="ok"))
    server = await aiohttp_raw_server(handler, keepalive_time=5)
    cli: TestClient[web.BaseRequest, None] = await aiohttp_client(server)
    response = await cli.get("/")
    assert await response.text() == "ok"
    protocol = server.handler.connections[0]
    advance_time(10)
    # Deliver a complete request before the overdue callback gets its turn.
    protocol.data_received(b"GET /late HTTP/1.1\r\nHost: localhost\r\n\r\n")
    protocol._process_keepalive()
    task = protocol._task_handler
    assert task is not None
    await task
    assert handler.call_count == 1
