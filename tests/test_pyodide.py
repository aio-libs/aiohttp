import shutil
import sys
from asyncio import Future
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from pytest import fixture

try:
    from pytest_pyodide import run_in_pyodide  # noqa: I900
except ImportError:
    run_in_pyodide = pytest.mark.skip("pytest-pyodide not installed")

from aiohttp import ClientSession, client, client_reqrep, connector
from aiohttp.connector import PyodideConnector


class JsAbortController:
    @staticmethod
    def new() -> "JsAbortController":
        return JsAbortController()

    def abort(self) -> None:
        pass

    @property
    def signal(self) -> str:
        return "AbortSignal"


class JsHeaders:
    def __init__(self, items: Mapping):
        self.items = dict(items)

    @staticmethod
    def new(items: Mapping) -> "JsHeaders":
        return JsHeaders(items)


class JsRequest:
    def __init__(self, path: str, **kwargs: Any):
        self.path = path
        self.kwargs = kwargs

    @staticmethod
    def new(path, **kwargs) -> "JsRequest":
        return JsRequest(path, **kwargs)


class JsBuffer:
    def __init__(self, content: bytes):
        self.content = content

    def to_bytes(self) -> bytes:
        return self.content


class JsResponse:
    def __init__(
        self, status: int, statusText: str, headers: JsHeaders, body: bytes | None
    ):
        self.status = status
        self.statusText = statusText
        self.headers = headers
        self.body = body

    def arrayBuffer(self):
        fut = Future()
        fut.set_result(self.body)
        return fut


@fixture
def mock_pyodide_env(monkeypatch: Any):
    monkeypatch.setattr(client, "IS_PYODIDE", True)
    monkeypatch.setattr(connector, "IS_PYODIDE", True)
    monkeypatch.setattr(client_reqrep, "IS_PYODIDE", True)
    jsmod = ModuleType("js")
    jsmod.AbortController = JsAbortController
    jsmod.Headers = JsHeaders
    jsmod.Request = JsRequest

    monkeypatch.setitem(sys.modules, "js", jsmod)


async def test_pyodide_mock(mock_pyodide_env: Any) -> None:
    def fetch_handler(request: JsRequest) -> Future[JsResponse]:
        assert request.path == "http://example.com"
        assert request.kwargs["method"] == "GET"
        assert request.kwargs["headers"].items == {
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Host": "example.com",
            "User-Agent": "Python/3.11 aiohttp/4.0.0a2.dev0",
        }
        assert request.kwargs["signal"] == "AbortSignal"
        assert request.kwargs["body"] is None
        fut = Future()
        resp = JsResponse(
            200, "OK", [["Content-type", "text/html; charset=utf-8"]], JsBuffer(b"abc")
        )
        fut.set_result(resp)
        return fut

    c = PyodideConnector(fetch_handler=fetch_handler)
    async with ClientSession(connector=c) as session:
        async with session.get("http://example.com") as response:
            assert response.status == 200
            assert response.headers["content-type"] == "text/html; charset=utf-8"
            html = await response.text()
            assert html == "abc"


@fixture
def install_aiohttp(selenium, request):
    wheel = next(Path("dist").glob("*.whl"))
    dist_dir = request.config.option.dist_dir
    dist_wheel = dist_dir / wheel.name
    shutil.copyfile(wheel, dist_wheel)
    selenium.load_package(["multidict", "yarl", "aiosignal"])
    selenium.load_package(wheel.name)
    try:
        yield
    finally:
        dist_wheel.unlink()


@fixture
async def url_to_fetch(request, web_server_main):
    target_file = Path(request.config.option.dist_dir) / "test.txt"
    target_file.write_text("hello there!")
    server_host, server_port, _ = web_server_main
    try:
        yield f"http://{server_host}:{server_port}/{target_file.name}"
    finally:
        target_file.unlink()


@fixture
async def loop_wrapper(loop):
    return None


@run_in_pyodide
async def test_pyodide(selenium, install_aiohttp, url_to_fetch, loop_wrapper) -> None:
    from aiohttp import ClientSession

    async with ClientSession() as session:
        async with session.get(url_to_fetch) as response:
            assert response.status == 200
            assert response.headers["content-type"] == "text/plain"
            html = await response.text()
            assert html == "hello there!"
