"""codspeed benchmarks for the web file responses."""

import asyncio
import os
import pathlib
import ssl
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, TypedDict

import pytest
from multidict import CIMultiDict
from pytest_aiohttp import AiohttpClient

from aiohttp import ClientResponse, web
from aiohttp.test_utils import TestClient, TestServer

if TYPE_CHECKING:
    from pytest_codspeed import BenchmarkFixture
else:
    pytest_codspeed = pytest.importorskip("pytest_codspeed")
    BenchmarkFixture = pytest_codspeed.BenchmarkFixture


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
        server_kwargs = dict(server_kwargs or {})
        server_ssl_context = server_kwargs.pop("ssl", None)
        server = TestServer(__param, **server_kwargs)
        client = aiohttp_client_cls(server, **kwargs)

        await server.start_server(ssl=server_ssl_context)
        await client.start_server()
        clients.append(client)
        return client

    yield go

    while clients:
        event_loop.run_until_complete(clients.pop().close())


class _ConnArgs(TypedDict, total=False):
    ssl: ssl.SSLContext


@dataclass(frozen=True)
class ConnectionType:
    s_kwargs: _ConnArgs
    c_kwargs: _ConnArgs


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
    event_loop: asyncio.AbstractEventLoop,
    aiohttp_client_sync: AiohttpClient,
    benchmark: BenchmarkFixture,
    conn_type: ConnectionType,
    benchmark_file: BenchmarkFile,
) -> None:
    """Benchmark simple web.FileResponse."""

    async def handler(request: web.Request) -> web.FileResponse:
        return web.FileResponse(path=benchmark_file.path)

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    async def run_file_response_benchmark() -> None:
        client = await aiohttp_client_sync(app, server_kwargs=conn_type.s_kwargs)
        for _ in range(benchmark_file.response_count):
            response = await client.get("/", **conn_type.c_kwargs)
            # Consume response.
            # Large responses may leave transport unclosed on at least python 3.10.
            await response.read()
        await client.close()

    @benchmark
    def _run() -> None:
        event_loop.run_until_complete(run_file_response_benchmark())


def test_simple_web_file_sendfile_fallback_response(
    event_loop: asyncio.AbstractEventLoop,
    aiohttp_client_sync: AiohttpClient,
    benchmark: BenchmarkFixture,
    conn_type: ConnectionType,
    benchmark_file: BenchmarkFile,
) -> None:
    """Benchmark simple web.FileResponse without sendfile."""

    async def handler(request: web.Request) -> web.FileResponse:
        transport = request.transport
        assert transport is not None
        transport._sendfile_compatible = asyncio.constants._SendfileMode.UNSUPPORTED  # type: ignore[attr-defined]
        return web.FileResponse(path=benchmark_file.path)

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    async def run_file_response_benchmark() -> None:
        client = await aiohttp_client_sync(app, server_kwargs=conn_type.s_kwargs)
        for _ in range(benchmark_file.response_count):
            response = await client.get("/", **conn_type.c_kwargs)
            await response.read()
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
