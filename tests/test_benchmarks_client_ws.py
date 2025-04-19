"""codspeed benchmarks for websocket client."""

import asyncio

import pytest
from pytest_codspeed import BenchmarkFixture

from aiohttp import web
from aiohttp._websocket.helpers import MSG_SIZE
from aiohttp.pytest_plugin import AiohttpClient


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
        client = await aiohttp_client(app)
        resp = await client.ws_connect("/")
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
