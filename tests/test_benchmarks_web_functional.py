import asyncio
from collections.abc import Iterator
from unittest import mock

from pytest_codspeed import BenchmarkFixture

from aiohttp import web
from aiohttp.pytest_plugin import AiohttpClient


async def test_read_many_chunks(
    aiohttp_client: AiohttpClient, benchmark: BenchmarkFixture
) -> None:
    """Benchmark blocking time when receiving many small chunks."""

    async def sender() -> Iterator[bytes]:
        for _ in range(200000):
            yield b"x"

    async def handle(request: web.Request) -> web.Response:
        # Wait until buffer is full and reading gets paused.
        while not request.protocol._reading_paused:
            await asyncio.sleep(0.01)

        # We want to measure the initial blocking time in this call.
        # Mocking out the ._wait() call forces the method to return at the first wait,
        # without waiting for more data or processing the rest of the body.
        with mock.patch.object(request.content, "_wait", autospec=True):
            chunk = await benchmark(request.read)

        return web.Response(text=str(len(chunk)))

    app = web.Application()
    app.router.add_post("/", handle)
    client = await aiohttp_client(app)

    async with client.post("/", chunked=True, data=sender()) as resp:
        assert resp.status == 200
        assert int(await resp.text()) > 100
