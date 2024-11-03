"""codspeed benchmarks for websocket client."""

import asyncio
from typing import NoReturn

from pytest_codspeed import BenchmarkFixture

from aiohttp import web
from aiohttp.pytest_plugin import AiohttpClient
from aiohttp.test_utils import _WSRequestContextManager


def test_one_thousand_round_trip_websocket_text_messages(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark round trip of 1000 WebSocket text messages."""
    message_count = 1000

    async def handler(request: web.Request) -> NoReturn:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        for _ in range(message_count):
            await ws.send_str("answer")
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    async def run_websocket_benchmark() -> _WSRequestContextManager:
        client = await aiohttp_client(app)
        resp = await client.ws_connect("/")
        for _ in range(message_count):
            await resp.receive()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_websocket_benchmark())
