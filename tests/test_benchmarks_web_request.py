"""codspeed benchmarks for web request reading."""

import asyncio
import zlib

import pytest
from pytest_aiohttp import AiohttpClient
from pytest_codspeed import BenchmarkFixture

from aiohttp import web


@pytest.mark.usefixtures("parametrize_zlib_backend")
def test_read_compressed_post_body(
    event_loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark server Request.read() with a compressed POST body."""
    original = b"B" * (5 * 2**20)
    compressed = zlib.compress(original)

    async def handler(request: web.Request) -> web.Response:
        body = await request.read()
        return web.Response(text=str(len(body)))

    app = web.Application(client_max_size=10 * 2**20)
    app.router.add_post("/", handler)

    async def run_benchmark() -> None:
        client = await aiohttp_client(app)
        resp = await client.post(
            "/",
            data=compressed,
            headers={"Content-Encoding": "deflate"},
        )
        assert int(await resp.read()) == len(original)
        await client.close()

    @benchmark
    def _run() -> None:
        event_loop.run_until_complete(run_benchmark())
