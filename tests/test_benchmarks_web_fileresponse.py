"""codspeed benchmarks for the web file responses."""

import asyncio
import pathlib
import ssl
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, TypedDict

import pytest
from multidict import CIMultiDict

from aiohttp import ClientResponse, web
from aiohttp.pytest_plugin import AiohttpClient
from aiohttp.test_utils import TestClient, TestServer

if TYPE_CHECKING:
    from pytest_codspeed import BenchmarkFixture
else:
    pytest_codspeed = pytest.importorskip("pytest_codspeed")
    BenchmarkFixture = pytest_codspeed.BenchmarkFixture


@pytest.fixture
def aiohttp_client_sync(
    loop: asyncio.AbstractEventLoop,
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
        loop.run_until_complete(clients.pop().close())


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


def test_simple_web_file_response(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client_sync: AiohttpClient,
    benchmark: BenchmarkFixture,
    conn_type: ConnectionType,
) -> None:
    """Benchmark creating 100 simple web.FileResponse."""
    response_count = 100
    filepath = pathlib.Path(__file__).parent / "sample.txt"

    async def handler(request: web.Request) -> web.FileResponse:
        return web.FileResponse(path=filepath)

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    async def run_file_response_benchmark() -> None:
        client = await aiohttp_client_sync(app, server_kwargs=conn_type.s_kwargs)
        for _ in range(response_count):
            await client.get("/", **conn_type.c_kwargs)
        await client.close()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_file_response_benchmark())


def test_simple_web_file_sendfile_fallback_response(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client_sync: AiohttpClient,
    benchmark: BenchmarkFixture,
    conn_type: ConnectionType,
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
        client = await aiohttp_client_sync(app, server_kwargs=conn_type.s_kwargs)
        for _ in range(response_count):
            await client.get("/", **conn_type.c_kwargs)
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
