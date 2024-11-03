"""codspeed benchmarks for HTTP client."""

import asyncio

from pytest_codspeed import BenchmarkFixture

from aiohttp import web
from aiohttp.pytest_plugin import AiohttpClient


def test_one_hundred_simple_get_requests(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark 100 simple GET requests."""
    message_count = 100

    async def handler(request: web.Request) -> web.WebSocketResponse:
        return web.Response()

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    async def run_client_benchmark() -> None:
        client = await aiohttp_client(app)
        for _ in range(message_count):
            await client.get("/")
        await client.close()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_client_benchmark())
