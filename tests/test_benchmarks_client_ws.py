"""codspeed benchmarks for websocket client."""

import asyncio
import ssl
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Iterator, TypedDict

import pytest

from aiohttp import web
from aiohttp._websocket.helpers import MSG_SIZE
from aiohttp.pytest_plugin import AiohttpClient, ConnectionType
from aiohttp.test_utils import TestClient, TestServer

if TYPE_CHECKING:
    from pytest_codspeed import BenchmarkFixture
else:
    pytest_codspeed = pytest.importorskip("pytest_codspeed")
    BenchmarkFixture = pytest_codspeed.BenchmarkFixture


class _ConnArgs(TypedDict, total=False):
    ssl: ssl.SSLContext


@pytest.fixture(params=("tcp", "ssl"), ids=("tcp", "ssl"))
def conn_type(
    request: pytest.FixtureRequest,
    ssl_ctx: ssl.SSLContext,
    client_ssl_ctx: ssl.SSLContext,
) -> ConnectionType:
    if request.param == "ssl":
        return ConnectionType(
            s_kwargs={"ssl": ssl_ctx},
            c_kwargs={"ssl": client_ssl_ctx},
        )
    return ConnectionType(s_kwargs={}, c_kwargs={})


def test_one_thousand_round_trip_websocket_text_messages(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark round trip of 1000 WebSocket text messages."""
    message_count = 1000

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        for _ in range(message_count):
            await ws.send_str("answer")
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    async def run_websocket_benchmark() -> None:
        client = await aiohttp_client(app)
        resp = await client.ws_connect("/")
        for _ in range(message_count):
            await resp.receive()
        await resp.close()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_websocket_benchmark())


@pytest.mark.parametrize("msg_size", [6, MSG_SIZE * 4], ids=["small", "large"])
def test_one_thousand_round_trip_websocket_binary_messages(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
    conn_type: ConnectionType,
    msg_size: int,
) -> None:
    """Benchmark round trip of 1000 WebSocket binary messages."""
    message_count = 1000
    raw_message = b"x" * msg_size

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        for _ in range(message_count):
            await ws.send_bytes(raw_message)
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    async def run_websocket_benchmark() -> None:
        client = await aiohttp_client(app, server_kwargs=conn_type.s_kwargs)
        resp = await client.ws_connect("/", **conn_type.c_kwargs)
        for _ in range(message_count):
            await resp.receive()
        await resp.close()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_websocket_benchmark())


def test_one_thousand_large_round_trip_websocket_text_messages(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark round trip of 100 large WebSocket text messages."""
    message_count = 100
    raw_message = "x" * MSG_SIZE * 4

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        for _ in range(message_count):
            await ws.send_str(raw_message)
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    async def run_websocket_benchmark() -> None:
        client = await aiohttp_client(app)
        resp = await client.ws_connect("/")
        for _ in range(message_count):
            await resp.receive()
        await resp.close()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_websocket_benchmark())


@pytest.mark.usefixtures("parametrize_zlib_backend")
def test_client_send_large_websocket_compressed_messages(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark send of compressed WebSocket binary messages."""
    message_count = 10
    raw_message = b"x" * 2**19  # 512 KiB

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        for _ in range(message_count):
            await ws.receive()
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    async def run_websocket_benchmark() -> None:
        client = await aiohttp_client(app)
        resp = await client.ws_connect("/", compress=15)
        for _ in range(message_count):
            await resp.send_bytes(raw_message)
        await resp.close()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_websocket_benchmark())


@pytest.mark.usefixtures("parametrize_zlib_backend")
def test_client_receive_large_websocket_compressed_messages(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark receive of compressed WebSocket binary messages."""
    message_count = 10
    raw_message = b"x" * 2**19  # 512 KiB

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        for _ in range(message_count):
            await ws.send_bytes(raw_message)
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    async def run_websocket_benchmark() -> None:
        client = await aiohttp_client(app)
        resp = await client.ws_connect("/", compress=15)
        for _ in range(message_count):
            await resp.receive()
        await resp.close()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_websocket_benchmark())
