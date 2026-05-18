"""codspeed benchmarks for websocket client."""

import asyncio
from collections.abc import Awaitable, Callable, Iterator
from typing import Any

import pytest
from pytest_aiohttp import AiohttpClient
from pytest_codspeed import BenchmarkFixture

from aiohttp import web
from aiohttp._websocket.helpers import MSG_SIZE
from aiohttp.test_utils import TestClient, TestServer


@pytest.fixture
def aiohttp_client_sync(
    event_loop: asyncio.AbstractEventLoop,
    aiohttp_client_cls: type[TestClient[web.Request, web.Application]],
) -> Iterator[
    Callable[[web.Application], Awaitable[TestClient[web.Request, web.Application]]]
]:
    # TODO: Remove this fixture when async benchmarks are working.
    clients = []

    async def go(
        __param: web.Application,
        *,
        server_kwargs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> TestClient[web.Request, web.Application]:
        server_kwargs = server_kwargs or {}
        server = TestServer(__param, **server_kwargs)
        client = aiohttp_client_cls(server, **kwargs)

        await client.start_server()
        clients.append(client)
        return client

    yield go

    while clients:
        event_loop.run_until_complete(clients.pop().close())


def test_one_thousand_round_trip_websocket_text_messages(
    event_loop: asyncio.AbstractEventLoop,
    aiohttp_client_sync: AiohttpClient,
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
        client = await aiohttp_client_sync(app)
        resp = await client.ws_connect("/")
        for _ in range(message_count):
            await resp.receive()
        await resp.close()

    @benchmark
    def _run() -> None:
        event_loop.run_until_complete(run_websocket_benchmark())


@pytest.mark.parametrize("msg_size", [6, MSG_SIZE * 4], ids=["small", "large"])
def test_one_thousand_round_trip_websocket_binary_messages(
    event_loop: asyncio.AbstractEventLoop,
    aiohttp_client_sync: AiohttpClient,
    benchmark: BenchmarkFixture,
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
        client = await aiohttp_client_sync(app)
        resp = await client.ws_connect("/")
        for _ in range(message_count):
            await resp.receive()
        await resp.close()

    @benchmark
    def _run() -> None:
        event_loop.run_until_complete(run_websocket_benchmark())


def test_one_thousand_large_round_trip_websocket_text_messages(
    event_loop: asyncio.AbstractEventLoop,
    aiohttp_client_sync: AiohttpClient,
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
        client = await aiohttp_client_sync(app)
        resp = await client.ws_connect("/")
        for _ in range(message_count):
            await resp.receive()
        await resp.close()

    @benchmark
    def _run() -> None:
        event_loop.run_until_complete(run_websocket_benchmark())


@pytest.mark.usefixtures("parametrize_zlib_backend")
def test_client_send_large_websocket_compressed_messages(
    event_loop: asyncio.AbstractEventLoop,
    aiohttp_client_sync: AiohttpClient,
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
        client = await aiohttp_client_sync(app)
        resp = await client.ws_connect("/", compress=15)
        for _ in range(message_count):
            await resp.send_bytes(raw_message)
        await resp.close()

    @benchmark
    def _run() -> None:
        event_loop.run_until_complete(run_websocket_benchmark())


@pytest.mark.usefixtures("parametrize_zlib_backend")
def test_client_receive_large_websocket_compressed_messages(
    event_loop: asyncio.AbstractEventLoop,
    aiohttp_client_sync: AiohttpClient,
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
        client = await aiohttp_client_sync(app)
        resp = await client.ws_connect("/", compress=15)
        for _ in range(message_count):
            await resp.receive()
        await resp.close()

    @benchmark
    def _run() -> None:
        event_loop.run_until_complete(run_websocket_benchmark())
