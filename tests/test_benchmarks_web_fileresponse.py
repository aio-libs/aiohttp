"""codspeed benchmarks for the web file responses."""

import asyncio
import pathlib

from multidict import CIMultiDict
from pytest_codspeed import BenchmarkFixture

import aiohttp
from aiohttp import web
from aiohttp.pytest_plugin import AiohttpClient


def test_simple_web_file_response(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark creating 100 simple web.FileResponse."""
    response_count = 100
    filepath = pathlib.Path(__file__).parent / "sample.txt"

    async def handler(request: web.Request) -> web.FileResponse:
        return web.FileResponse(path=filepath)

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    async def run_file_response_benchmark() -> None:
        client = await aiohttp_client(app)
        for _ in range(response_count):
            await client.get("/")
        await client.close()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_file_response_benchmark())


def test_simple_web_file_sendfile_fallback_response(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark creating 100 simple web.FileResponse without sendfile."""
    response_count = 100
    filepath = pathlib.Path(__file__).parent / "sample.txt"

    async def handler(request: web.Request) -> web.FileResponse:
        transport = request.transport
        assert transport is not None
        transport._sendfile_compatible = False  # type: ignore[attr-defined]
        return web.FileResponse(path=filepath)

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    async def run_file_response_benchmark() -> None:
        client = await aiohttp_client(app)
        for _ in range(response_count):
            await client.get("/")
        await client.close()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_file_response_benchmark())


def test_simple_web_file_response_not_modified(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark creating 100 simple web.FileResponse."""
    response_count = 100
    filepath = pathlib.Path(__file__).parent / "sample.txt"

    async def handler(request: web.Request) -> web.FileResponse:
        return web.FileResponse(path=filepath)

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    async def make_last_modified_header() -> CIMultiDict:
        client = await aiohttp_client(app)
        resp = await client.get("/")
        last_modified = resp.headers["Last-Modified"]
        headers = CIMultiDict({"If-Modified-Since": last_modified})
        return headers

    async def run_file_response_benchmark(
        headers: CIMultiDict,
    ) -> aiohttp.ClientResponse:
        client = await aiohttp_client(app)
        for _ in range(response_count):
            resp = await client.get("/", headers=headers)

        await client.close()
        return resp

    headers = loop.run_until_complete(make_last_modified_header())

    @benchmark
    def _run() -> None:
        resp = loop.run_until_complete(run_file_response_benchmark(headers))
        assert resp.status == 304
