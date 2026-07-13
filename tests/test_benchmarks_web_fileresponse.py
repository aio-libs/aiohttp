"""codspeed benchmarks for the web file responses."""

import asyncio
import os
import pathlib
import ssl
import sys
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, TypedDict

import pytest
from multidict import CIMultiDict

from aiohttp import ClientResponse, web
from aiohttp.pytest_plugin import AiohttpClient, ConnectionType
from aiohttp.test_utils import TestClient, TestServer

if TYPE_CHECKING:
    from pytest_codspeed import BenchmarkFixture
else:
    pytest_codspeed = pytest.importorskip("pytest_codspeed")
    BenchmarkFixture = pytest_codspeed.BenchmarkFixture


class _ConnArgs(TypedDict, total=False):
    ssl: ssl.SSLContext


@pytest.fixture(params=("tcp", "ssl"), ids=("tcp", "ssl"))
def conn_type(
    request: pytest.FixtureRequest,
    ssl_ctx: ssl.SSLContext,
    client_ssl_ctx: ssl.SSLContext,
) -> ConnectionType:
    if request.param == "ssl":
        return ConnectionType(
            s_kwargs={"ssl": ssl_ctx},
            c_kwargs={"ssl": client_ssl_ctx},
        )
    return ConnectionType(s_kwargs={}, c_kwargs={})


@dataclass(frozen=True)
class BenchmarkFile:
    path: pathlib.Path
    response_count: int


@pytest.fixture(
    params=((10 * 1024, 100), (1024 * 1024, 10)),
    ids=("small", "large"),
)
def benchmark_file(
    request: pytest.FixtureRequest, tmp_path: pathlib.Path
) -> BenchmarkFile:
    size, response_count = request.param
    filepath = tmp_path / "sample.txt"
    filepath.touch()
    os.truncate(filepath, size)
    return BenchmarkFile(filepath, response_count)


def test_simple_web_file_response(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
    conn_type: ConnectionType,
    benchmark_file: BenchmarkFile,
    pytestconfig: pytest.Config,
) -> None:
    """Benchmark creating 100 simple web.FileResponse."""
    server_ssl_context = conn_type.s_kwargs.get("ssl")
    if server_ssl_context is not None:
        if sys.version_info >= (3, 12):
            server_ssl_context.options |= ssl.OP_ENABLE_KTLS

    server_transport: asyncio.Transport | None = None

    async def handler(request: web.Request) -> web.FileResponse:
        nonlocal server_transport
        server_transport = request.transport
        return web.FileResponse(path=benchmark_file.path)

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    async def run_file_response_benchmark() -> None:
        client = await aiohttp_client(app, server_kwargs=conn_type.s_kwargs)
        for _ in range(benchmark_file.response_count):
            response = await client.get("/", **conn_type.c_kwargs)
            # Consume response.
            # Large responses may leave transport unclosed on at least python 3.10.
            await response.read()
        await client.close()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_file_response_benchmark())


def test_simple_web_file_sendfile_fallback_response(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
    conn_type: ConnectionType,
    benchmark_file: BenchmarkFile,
) -> None:
    """Benchmark simple web.FileResponse without sendfile."""

    async def handler(request: web.Request) -> web.FileResponse:
        transport = request.transport
        assert transport is not None
        transport._sendfile_compatible = False  # type: ignore[attr-defined]
        return web.FileResponse(path=benchmark_file.path)

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    async def run_file_response_benchmark() -> None:
        client = await aiohttp_client(app, server_kwargs=conn_type.s_kwargs)

        for _ in range(benchmark_file.response_count):
            response = await client.get("/", **conn_type.c_kwargs)
            await response.read()
        await client.close()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_file_response_benchmark())


def test_simple_web_file_response_not_modified(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
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
        client = await aiohttp_client(app)
        resp = await client.get("/")
        last_modified = resp.headers["Last-Modified"]
        headers = CIMultiDict({"If-Modified-Since": last_modified})
        return headers

    async def run_file_response_benchmark(
        headers: CIMultiDict[str],
    ) -> ClientResponse:
        client = await aiohttp_client(app)
        for _ in range(response_count):
            resp = await client.get("/", headers=headers)

        await client.close()
        return resp  # type: ignore[possibly-undefined]

    headers = loop.run_until_complete(make_last_modified_header())

    @benchmark
    def _run() -> None:
        resp = loop.run_until_complete(run_file_response_benchmark(headers))
        assert resp.status == 304
