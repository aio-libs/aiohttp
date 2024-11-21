"""codspeed benchmarks for the URL dispatcher."""

import asyncio
import json
import pathlib
import random
import string
from pathlib import Path
from typing import NoReturn, Optional, cast
from unittest import mock

import pytest
from multidict import CIMultiDict, CIMultiDictProxy
from pytest_codspeed import BenchmarkFixture
from yarl import URL

import aiohttp
from aiohttp import web
from aiohttp.http import HttpVersion, RawRequestMessage


@pytest.fixture
def github_urls() -> list[str]:
    """GitHub api urls."""
    # The fixture provides OpenAPI generated info for github.
    # To update the local data file please run the following command:
    # $ curl https://raw.githubusercontent.com/github/rest-api-description/refs/heads/main/descriptions/api.github.com/api.github.com.json | jq ".paths | keys" > github-urls.json

    here = Path(__file__).parent
    with (here / "github-urls.json").open() as f:
        urls = json.load(f)

    return cast(list[str], urls)


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
    app.freeze()
    router = app.router
    request = _mock_request(method="GET", path="/")

    async def run_url_dispatcher_benchmark() -> Optional[web.UrlMappingMatchInfo]:
        ret = None
        for _ in range(resolve_count):
            ret = await router.resolve(request)

        return ret

    ret = loop.run_until_complete(run_url_dispatcher_benchmark())
    assert ret is not None
    assert ret.get_info()["path"] == "/", ret.get_info()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_url_dispatcher_benchmark())


def test_resolve_root_route_with_many_fixed_routes(
    loop: asyncio.AbstractEventLoop,
    benchmark: BenchmarkFixture,
) -> None:
    """Resolve top level PlainResources route 100 times."""
    resolve_count = 100

    async def handler(request: web.Request) -> NoReturn:
        assert False

    app = web.Application()
    app.router.add_route("GET", "/", handler)
    for count in range(250):
        app.router.add_route("GET", f"/api/server/dispatch/{count}/update", handler)
        app.router.add_route("GET", f"/api/server/dispatch/{count}", handler)
    app.router.add_route("GET", "/api/server/dispatch", handler)
    app.router.add_route("GET", "/api/server", handler)
    app.router.add_route("GET", "/api", handler)
    app.freeze()
    router = app.router
    request = _mock_request(method="GET", path="/")

    async def run_url_dispatcher_benchmark() -> Optional[web.UrlMappingMatchInfo]:
        ret = None
        for _ in range(resolve_count):
            ret = await router.resolve(request)

        return ret

    ret = loop.run_until_complete(run_url_dispatcher_benchmark())
    assert ret is not None
    assert ret.get_info()["path"] == "/", ret.get_info()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_url_dispatcher_benchmark())


def test_resolve_static_root_route(
    loop: asyncio.AbstractEventLoop,
    benchmark: BenchmarkFixture,
) -> None:
    """Resolve top level StaticResource route 100 times."""
    resolve_count = 100

    app = web.Application()
    here = pathlib.Path(aiohttp.__file__).parent
    app.router.add_static("/", here)
    app.freeze()
    router = app.router
    request = _mock_request(method="GET", path="/")

    async def run_url_dispatcher_benchmark() -> Optional[web.UrlMappingMatchInfo]:
        ret = None
        for _ in range(resolve_count):
            ret = await router.resolve(request)

        return ret

    ret = loop.run_until_complete(run_url_dispatcher_benchmark())
    assert ret is not None
    assert ret.get_info()["directory"] == here, ret.get_info()

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
    app.freeze()
    router = app.router
    request = _mock_request(method="GET", path="/api/server/dispatch/1/update")

    async def run_url_dispatcher_benchmark() -> Optional[web.UrlMappingMatchInfo]:
        ret = None
        for _ in range(resolve_count):
            ret = await router.resolve(request)

        return ret

    ret = loop.run_until_complete(run_url_dispatcher_benchmark())
    assert ret is not None
    assert ret.get_info()["path"] == "/api/server/dispatch/1/update", ret.get_info()

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
    app.freeze()
    router = app.router

    requests = [
        _mock_request(method="GET", path=f"/api/server/dispatch/{count}/update")
        for count in range(250)
    ]

    async def run_url_dispatcher_benchmark() -> Optional[web.UrlMappingMatchInfo]:
        ret = None
        for request in requests:
            ret = await router.resolve(request)
        return ret

    ret = loop.run_until_complete(run_url_dispatcher_benchmark())
    assert ret is not None
    assert ret.get_info()["path"] == "/api/server/dispatch/249/update", ret.get_info()

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
    app.freeze()
    router = app.router

    requests = [(_mock_request(method="GET", path=url), url) for url in urls]

    async def run_url_dispatcher_benchmark() -> Optional[web.UrlMappingMatchInfo]:
        ret = None
        for request, path in requests:
            ret = await router.resolve(request)

        return ret

    ret = loop.run_until_complete(run_url_dispatcher_benchmark())
    assert ret is not None
    assert ret.get_info()["path"] == url, ret.get_info()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_url_dispatcher_benchmark())


def test_resolve_dynamic_resource_url_with_many_static_routes(
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
    app.freeze()
    router = app.router

    requests = [
        _mock_request(method="GET", path=f"/api/server/dispatch/{customer}/update")
        for customer in range(250)
    ]

    async def run_url_dispatcher_benchmark() -> Optional[web.UrlMappingMatchInfo]:
        ret = None
        for request in requests:
            ret = await router.resolve(request)

        return ret

    ret = loop.run_until_complete(run_url_dispatcher_benchmark())
    assert ret is not None
    assert (
        ret.get_info()["formatter"] == "/api/server/dispatch/{customer}/update"
    ), ret.get_info()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_url_dispatcher_benchmark())


def test_resolve_dynamic_resource_url_with_many_dynamic_routes(
    loop: asyncio.AbstractEventLoop,
    benchmark: BenchmarkFixture,
) -> None:
    """Resolve different a DynamicResource when there are 250 DynamicResources registered."""

    async def handler(request: web.Request) -> NoReturn:
        assert False

    app = web.Application()
    for count in range(250):
        app.router.add_route(
            "GET", f"/api/server/other/{{customer}}/update{count}", handler
        )
    app.router.add_route("GET", "/api/server/dispatch/{customer}/update", handler)
    app.freeze()
    router = app.router

    requests = [
        _mock_request(method="GET", path=f"/api/server/dispatch/{customer}/update")
        for customer in range(250)
    ]

    async def run_url_dispatcher_benchmark() -> Optional[web.UrlMappingMatchInfo]:
        ret = None
        for request in requests:
            ret = await router.resolve(request)

        return ret

    ret = loop.run_until_complete(run_url_dispatcher_benchmark())
    assert ret is not None
    assert (
        ret.get_info()["formatter"] == "/api/server/dispatch/{customer}/update"
    ), ret.get_info()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_url_dispatcher_benchmark())


def test_resolve_dynamic_resource_url_with_many_dynamic_routes_with_common_prefix(
    loop: asyncio.AbstractEventLoop,
    benchmark: BenchmarkFixture,
) -> None:
    """Resolve different a DynamicResource when there are 250 DynamicResources registered with the same common prefix."""

    async def handler(request: web.Request) -> NoReturn:
        assert False

    app = web.Application()
    for count in range(250):
        app.router.add_route("GET", f"/api/{{customer}}/show_{count}", handler)
    app.router.add_route("GET", "/api/{customer}/update", handler)
    app.freeze()
    router = app.router

    requests = [
        _mock_request(method="GET", path=f"/api/{customer}/update")
        for customer in range(250)
    ]

    async def run_url_dispatcher_benchmark() -> Optional[web.UrlMappingMatchInfo]:
        ret = None
        for request in requests:
            ret = await router.resolve(request)

        return ret

    ret = loop.run_until_complete(run_url_dispatcher_benchmark())
    assert ret is not None
    assert ret.get_info()["formatter"] == "/api/{customer}/update", ret.get_info()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_url_dispatcher_benchmark())


def test_resolve_gitapi(
    loop: asyncio.AbstractEventLoop,
    benchmark: BenchmarkFixture,
    github_urls: list[str],
) -> None:
    """Resolve DynamicResource for simulated github API."""

    async def handler(request: web.Request) -> NoReturn:
        assert False

    app = web.Application()
    for url in github_urls:
        app.router.add_get(url, handler)
    app.freeze()
    router = app.router

    # PR reviews API was selected absolutely voluntary.
    # It is not any special but sits somewhere in the middle of the urls list.
    # If anybody has better idea please suggest.

    alnums = string.ascii_letters + string.digits

    requests = []
    for i in range(250):
        owner = "".join(random.sample(alnums, 10))
        repo = "".join(random.sample(alnums, 10))
        pull_number = random.randint(0, 250)
        requests.append(
            _mock_request(
                method="GET", path=f"/repos/{owner}/{repo}/pulls/{pull_number}/reviews"
            )
        )

    async def run_url_dispatcher_benchmark() -> Optional[web.UrlMappingMatchInfo]:
        ret = None
        for request in requests:
            ret = await router.resolve(request)
        return ret

    ret = loop.run_until_complete(run_url_dispatcher_benchmark())
    assert ret is not None
    assert (
        ret.get_info()["formatter"]
        == "/repos/{owner}/{repo}/pulls/{pull_number}/reviews"
    ), ret.get_info()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_url_dispatcher_benchmark())


def test_resolve_gitapi_subapps(
    loop: asyncio.AbstractEventLoop,
    benchmark: BenchmarkFixture,
    github_urls: list[str],
) -> None:
    """Resolve DynamicResource for simulated github API, grouped in subapps."""

    async def handler(request: web.Request) -> NoReturn:
        assert False

    subapps = {
        "gists": web.Application(),
        "orgs": web.Application(),
        "projects": web.Application(),
        "repos": web.Application(),
        "teams": web.Application(),
        "user": web.Application(),
        "users": web.Application(),
    }

    app = web.Application()
    for url in github_urls:
        parts = url.split("/")
        subapp = subapps.get(parts[1])
        if subapp is not None:
            sub_url = "/".join([""] + parts[2:])
            if not sub_url:
                sub_url = "/"
            subapp.router.add_get(sub_url, handler)
        else:
            app.router.add_get(url, handler)
    for key, subapp in subapps.items():
        app.add_subapp("/" + key, subapp)
    app.freeze()
    router = app.router

    # PR reviews API was selected absolutely voluntary.
    # It is not any special but sits somewhere in the middle of the urls list.
    # If anybody has better idea please suggest.

    alnums = string.ascii_letters + string.digits

    requests = []
    for i in range(250):
        owner = "".join(random.sample(alnums, 10))
        repo = "".join(random.sample(alnums, 10))
        pull_number = random.randint(0, 250)
        requests.append(
            _mock_request(
                method="GET", path=f"/repos/{owner}/{repo}/pulls/{pull_number}/reviews"
            )
        )

    async def run_url_dispatcher_benchmark() -> Optional[web.UrlMappingMatchInfo]:
        ret = None
        for request in requests:
            ret = await router.resolve(request)
        return ret

    ret = loop.run_until_complete(run_url_dispatcher_benchmark())
    assert ret is not None
    assert (
        ret.get_info()["formatter"]
        == "/repos/{owner}/{repo}/pulls/{pull_number}/reviews"
    ), ret.get_info()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_url_dispatcher_benchmark())


def test_resolve_gitapi_root(
    loop: asyncio.AbstractEventLoop,
    benchmark: BenchmarkFixture,
    github_urls: list[str],
) -> None:
    """Resolve the plain root for simulated github API."""

    async def handler(request: web.Request) -> NoReturn:
        assert False

    app = web.Application()
    for url in github_urls:
        app.router.add_get(url, handler)
    app.freeze()
    router = app.router

    request = _mock_request(method="GET", path="/")

    async def run_url_dispatcher_benchmark() -> Optional[web.UrlMappingMatchInfo]:
        ret = None
        for i in range(250):
            ret = await router.resolve(request)
        return ret

    ret = loop.run_until_complete(run_url_dispatcher_benchmark())
    assert ret is not None
    assert ret.get_info()["path"] == "/", ret.get_info()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_url_dispatcher_benchmark())


def test_resolve_prefix_resources_many_prefix_many_plain(
    loop: asyncio.AbstractEventLoop,
    benchmark: BenchmarkFixture,
) -> None:
    """Resolve prefix resource (sub_app) whene 250 PlainResources registered and there are 250 subapps that shares the same sub_app path prefix."""

    async def handler(request: web.Request) -> NoReturn:
        assert False

    app = web.Application()
    for count in range(250):
        app.router.add_get(f"/api/server/other/{count}/update", handler)
    for count in range(250):
        subapp = web.Application()
        # sub_apps exists for handling deep enough nested route trees
        subapp.router.add_get("/deep/enough/sub/path", handler)
        app.add_subapp(f"/api/path/to/plugin/{count}", subapp)
    app.freeze()
    router = app.router

    requests = [
        _mock_request(method="GET", path="/api/path/to/plugin/249/deep/enough/sub/path")
        for customer in range(250)
    ]

    async def run_url_dispatcher_benchmark() -> Optional[web.UrlMappingMatchInfo]:
        ret = None
        for request in requests:
            ret = await router.resolve(request)
        return ret

    ret = loop.run_until_complete(run_url_dispatcher_benchmark())
    assert ret is not None
    assert (
        ret.get_info()["path"] == "/api/path/to/plugin/249/deep/enough/sub/path"
    ), ret.get_info()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_url_dispatcher_benchmark())
