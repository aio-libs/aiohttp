"""codspeed benchmarks for the web file responses."""

import asyncio
import pathlib
from collections.abc import Awaitable, Callable, Iterator
from typing import Any

import pytest
from multidict import CIMultiDict
from pytest_aiohttp import AiohttpClient
from pytest_codspeed import BenchmarkFixture

from aiohttp import ClientResponse, web
from aiohttp.test_utils import TestClient, TestServer


@pytest.fixture
def aiohttp_client_sync(
    event_loop: asyncio.AbstractEventLoop,
    aiohttp_client_cls: type[TestClient[web.Request, web.Application]],
) -> Iterator[
    Callable[[web.Application], Awaitable[TestClient[web.Request, web.Application]]]
]:
    # TODO: Remove this fixture when async benchmarks are working.
    clients = []

    async def go(
        __param: web.Application,
        *,
        server_kwargs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> TestClient[web.Request, web.Application]:
        server_kwargs = server_kwargs or {}
        server = TestServer(__param, **server_kwargs)
        client = aiohttp_client_cls(server, **kwargs)

        await client.start_server()
        clients.append(client)
        return client

    yield go

    while clients:
        event_loop.run_until_complete(clients.pop().close())


def test_simple_web_file_response(
    event_loop: asyncio.AbstractEventLoop,
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
        event_loop.run_until_complete(run_file_response_benchmark())


def test_simple_web_file_sendfile_fallback_response(
    event_loop: asyncio.AbstractEventLoop,
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
        event_loop.run_until_complete(run_file_response_benchmark())


def test_simple_web_file_response_not_modified(
    event_loop: asyncio.AbstractEventLoop,
    aiohttp_client_sync: AiohttpClient,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark web.FileResponse that return a 304."""
    response_count = 100
    filepath = pathlib.Path(__file__).parent / "sample.txt"

    async def handler(request: web.Request) -> web.FileResponse:
        return web.FileResponse(path=filepath)

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    async def make_last_modified_header() -> CIMultiDict[str]:
        client = await aiohttp_client_sync(app)
        resp = await client.get("/")
        last_modified = resp.headers["Last-Modified"]
        headers = CIMultiDict({"If-Modified-Since": last_modified})
        return headers

    async def run_file_response_benchmark(
        headers: CIMultiDict[str],
    ) -> ClientResponse:
        client = await aiohttp_client_sync(app)
        for _ in range(response_count):
            resp = await client.get("/", headers=headers)

        await client.close()
        return resp  # type: ignore[possibly-undefined]

    headers = event_loop.run_until_complete(make_last_modified_header())

    @benchmark
    def _run() -> None:
        resp = event_loop.run_until_complete(run_file_response_benchmark(headers))
        assert resp.status == 304
