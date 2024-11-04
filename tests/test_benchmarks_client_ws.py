"""codspeed benchmarks for websocket client."""

import asyncio

from pytest_codspeed import BenchmarkFixture

from aiohttp import web
from aiohttp.http_websocket import MSG_SIZE
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


def test_one_thousand_round_trip_websocket_binary_messages(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark round trip of 1000 WebSocket binary messages."""
    message_count = 1000

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        for _ in range(message_count):
            await ws.send_bytes(b"answer")
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
