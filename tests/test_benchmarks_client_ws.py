"""codspeed benchmarks for http websocket."""

import asyncio
import threading
from typing import NoReturn

from pytest_codspeed import BenchmarkFixture

from aiohttp import web
from aiohttp.pytest_plugin import AiohttpClient
from aiohttp.test_utils import _WSRequestContextManager


def test_read_one_hundred_round_trip_websocket_text_messages(
    aiohttp_client: AiohttpClient, benchmark: BenchmarkFixture
) -> None:
    """Benchmark round trip of 100 WebSocket text messages."""
    loop = asyncio.new_event_loop()

    def start_background_loop() -> None:
        asyncio.set_event_loop(loop)
        loop.run_forever()

    async def background_server() -> tuple[web.Application, _WSRequestContextManager]:
        nonlocal resp

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
        return app, await client.ws_connect("/")

    thread = threading.Thread(target=start_background_loop, daemon=True)

    thread.start()
    app, resp = asyncio.run_coroutine_threadsafe(background_server(), loop).result()

    async def _receive_one_hundred_websocket_text_messages() -> None:
        for _ in range(100):
            await resp.receive()

    benchmark(
        asyncio.run_coroutine_threadsafe(
            _receive_one_hundred_websocket_text_messages(), loop
        ).result
    )
    asyncio.run_coroutine_threadsafe(resp.close(), loop).result()
    loop.stop()
    thread.join()
    loop.close()
