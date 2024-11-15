"""codspeed benchmarks for the URL dispatcher."""

import asyncio
import pathlib
from typing import NoReturn
from unittest import mock

from multidict import CIMultiDict, CIMultiDictProxy
from pytest_codspeed import BenchmarkFixture
from yarl import URL

import aiohttp
from aiohttp import web
from aiohttp.http import HttpVersion, RawRequestMessage


def _mock_request(method: str, path: str) -> web.Request:
    message = RawRequestMessage(
        method,
        path,
        HttpVersion(1, 1),
        CIMultiDictProxy(CIMultiDict()),
        (),
        False,
        None,
        False,
        False,
        URL(path),
    )

    return web.Request(
        message, mock.Mock(), mock.Mock(), mock.Mock(), mock.Mock(), mock.Mock()
    )


def test_resolve_root_route(
    loop: asyncio.AbstractEventLoop,
    benchmark: BenchmarkFixture,
) -> None:
    """Resolve top level PlainResources route 100 times."""
    resolve_count = 100

    async def handler(request: web.Request) -> NoReturn:
        assert False

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    request = _mock_request(method="GET", path="/")

    async def run_url_dispatcher_benchmark() -> None:
        for _ in range(resolve_count):
            await app._router.resolve(request)

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_url_dispatcher_benchmark())


def test_resolve_static_root_route(
    loop: asyncio.AbstractEventLoop,
    benchmark: BenchmarkFixture,
) -> None:
    """Resolve top level StaticResource route 100 times."""
    resolve_count = 100

    async def handler(request: web.Request) -> NoReturn:
        assert False

    app = web.Application()
    app.router.add_static("/", pathlib.Path(aiohttp.__file__).parent)
    request = _mock_request(method="GET", path="/")

    async def run_url_dispatcher_benchmark() -> None:
        for _ in range(resolve_count):
            await app._router.resolve(request)

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_url_dispatcher_benchmark())


def test_resolve_single_fixed_url_with_many_routes(
    loop: asyncio.AbstractEventLoop,
    benchmark: BenchmarkFixture,
) -> None:
    """Resolve PlainResources route 100 times."""
    resolve_count = 100

    async def handler(request: web.Request) -> NoReturn:
        assert False

    app = web.Application()
    for count in range(250):
        app.router.add_route("GET", f"/api/server/dispatch/{count}/update", handler)
    request = _mock_request(method="GET", path="/api/server/dispatch/1/update")

    async def run_url_dispatcher_benchmark() -> None:
        for _ in range(resolve_count):
            await app._router.resolve(request)

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_url_dispatcher_benchmark())


def test_resolve_multiple_fixed_url_with_many_routes(
    loop: asyncio.AbstractEventLoop,
    benchmark: BenchmarkFixture,
) -> None:
    """Resolve 250 different PlainResources routes."""

    async def handler(request: web.Request) -> NoReturn:
        assert False

    app = web.Application()
    for count in range(250):
        app.router.add_route("GET", f"/api/server/dispatch/{count}/update", handler)

    requests = [
        _mock_request(method="GET", path=f"/api/server/dispatch/{count}/update")
        for count in range(250)
    ]

    async def run_url_dispatcher_benchmark() -> None:
        for request in requests:
            await app._router.resolve(request)

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_url_dispatcher_benchmark())


def test_resolve_multiple_level_fixed_url_with_many_routes(
    loop: asyncio.AbstractEventLoop,
    benchmark: BenchmarkFixture,
) -> None:
    """Resolve 1024 different PlainResources routes."""

    async def handler(request: web.Request) -> NoReturn:
        assert False

    app = web.Application()
    urls = [
        f"/api/{a}/{b}/{c}/{d}/{e}/update"
        for a in ("a", "b", "c", "d")
        for b in ("e", "f", "g", "h")
        for c in ("i", "j", "k", "l")
        for d in ("m", "n", "o", "p")
        for e in ("n", "o", "p", "q")
    ]
    for url in urls:
        app.router.add_route("GET", url, handler)

    requests = [_mock_request(method="GET", path=url) for url in urls]

    async def run_url_dispatcher_benchmark() -> None:
        for request in requests:
            await app._router.resolve(request)

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_url_dispatcher_benchmark())


def test_resolve_dynamic_resource_url_with_many_routes(
    loop: asyncio.AbstractEventLoop,
    benchmark: BenchmarkFixture,
) -> None:
    """Resolve different a DynamicResource when there are 250 PlainResources registered."""

    async def handler(request: web.Request) -> NoReturn:
        assert False

    app = web.Application()
    for count in range(250):
        app.router.add_route("GET", f"/api/server/other/{count}/update", handler)
    app.router.add_route("GET", "/api/server/dispatch/{customer}/update", handler)

    requests = [
        _mock_request(method="GET", path=f"/api/server/dispatch/{customer}/update")
        for customer in range(250)
    ]

    async def run_url_dispatcher_benchmark() -> None:
        for request in requests:
            await app._router.resolve(request)

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_url_dispatcher_benchmark())
