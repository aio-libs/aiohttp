"""codspeed benchmarks for web middlewares."""

import asyncio

from pytest_codspeed import BenchmarkFixture

from aiohttp import web
from aiohttp.pytest_plugin import AiohttpClient
from aiohttp.typedefs import Handler


def test_ten_web_middlewares(
    benchmark: BenchmarkFixture,
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
) -> None:
    """Benchmark 100 requests with 10 middlewares."""
    message_count = 100

    async def handler(request: web.Request) -> web.Response:
        return web.Response()

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    class MiddlewareClass:
        @web.middleware
        async def call(
            self, request: web.Request, handler: Handler
        ) -> web.StreamResponse:
            return await handler(request)

    for _ in range(10):
        app.middlewares.append(MiddlewareClass().call)

    async def run_client_benchmark() -> None:
        client = await aiohttp_client(app)
        for _ in range(message_count):
            await client.get("/")
        await client.close()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_client_benchmark())
