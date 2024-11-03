"""codspeed benchmarks for websocket client."""

import asyncio
from typing import NoReturn

from pytest_codspeed import BenchmarkFixture

from aiohttp import web
from aiohttp.pytest_plugin import AiohttpClient
from aiohttp.test_utils import _WSRequestContextManager


def test_one_hundred_round_trip_websocket_text_messages(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark round trip of 100 WebSocket text messages."""

    async def run_websocket_benchmark() -> _WSRequestContextManager:
        async def handler(request: web.Request) -> NoReturn:
            ws = web.WebSocketResponse()
            await ws.prepare(request)
            for _ in range(100):
                await ws.send_str("answer")
            await ws.close()
            return ws

        app = web.Application()
        app.router.add_route("GET", "/", handler)
        client = await aiohttp_client(app)
        resp = await client.ws_connect("/")
        for _ in range(100):
            await resp.receive()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_websocket_benchmark())
