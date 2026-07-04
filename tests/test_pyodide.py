"""Integration tests running aiohttp inside a real Pyodide runtime.

These tests require a Pyodide distribution and the pytest-pyodide plugin;
they are run from the dedicated ``test-pyodide`` CI job::

    pytest tests/test_pyodide.py --rt node --dist-dir=./pyodide-dist

The aiohttp wheel under test must be placed in ``dist/`` first (the CI job
builds it with cibuildwheel).  Unit tests for the fetch()-based connector
that do not need a WebAssembly runtime live in
``tests/test_fetch_connector.py``.
"""

import shutil
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

pytest_pyodide = pytest.importorskip("pytest_pyodide")
run_in_pyodide = pytest_pyodide.run_in_pyodide

# Wheels for aiohttp's runtime dependencies that are part of the Pyodide
# distribution; loaded into the runtime before the aiohttp wheel itself.
DEPENDENCIES = [
    "aiohappyeyeballs",
    "aiosignal",
    "frozenlist",
    "multidict",
    "propcache",
    "yarl",
]


class _EchoHandler(BaseHTTPRequestHandler):
    """A tiny HTTP server exercising the client from the outside."""

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    def _respond(
        self,
        body: bytes,
        content_type: str = "text/plain",
        status: int = 200,
        extra_headers: tuple[tuple[str, str], ...] = (),
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in extra_headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/json":
            self._respond(b'{"hello": "world"}', "application/json")
        elif self.path == "/cookies":
            self._respond(
                b"ok",
                extra_headers=(
                    ("Set-Cookie", "first=1; Path=/"),
                    ("Set-Cookie", "second=2; Path=/"),
                ),
            )
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/json")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self._respond(b"not found", status=404)

    def do_POST(self) -> None:
        body = self._read_body()
        self._respond(
            body,
            self.headers.get("Content-Type", "application/octet-stream"),
            extra_headers=(("X-Request-Method", "POST"),),
        )

    def do_PUT(self) -> None:
        self._respond(self._read_body(), extra_headers=(("X-Request-Method", "PUT"),))

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass  # Silence per-request stderr noise.


@pytest.fixture(scope="module")
def echo_server_url() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


@pytest.fixture
def selenium_with_aiohttp(
    selenium_standalone: Any, request: pytest.FixtureRequest
) -> Iterator[Any]:
    """Load the locally built aiohttp wheel and its dependencies."""
    wheels = sorted(Path("dist").glob("aiohttp-*.whl"))
    if not wheels:
        pytest.fail("no aiohttp wheel in dist/; build one with cibuildwheel first")
    wheel = wheels[-1]
    dist_dir = Path(request.config.option.dist_dir)
    dist_wheel = dist_dir / wheel.name
    shutil.copyfile(wheel, dist_wheel)
    try:
        selenium_standalone.load_package(DEPENDENCIES)
        selenium_standalone.load_package(wheel.name)
        yield selenium_standalone
    finally:
        dist_wheel.unlink()


@run_in_pyodide
async def _get_json(selenium: Any, base_url: str) -> None:
    import aiohttp
    from aiohttp.pyodide import FetchConnector

    async with aiohttp.ClientSession() as session:
        assert isinstance(session.connector, FetchConnector)
        async with session.get(base_url + "/json") as resp:
            assert resp.status == 200
            assert resp.headers["Content-Type"] == "application/json"
            assert await resp.json() == {"hello": "world"}


@run_in_pyodide
async def _post_bodies(selenium: Any, base_url: str) -> None:
    from collections.abc import AsyncIterator

    import aiohttp

    async with aiohttp.ClientSession() as session:
        async with session.post(base_url + "/echo", data=b"raw-bytes") as resp:
            assert await resp.read() == b"raw-bytes"
            assert resp.headers["X-Request-Method"] == "POST"

        async with session.post(base_url + "/echo", json={"a": [1, 2]}) as resp:
            assert await resp.json() == {"a": [1, 2]}

        async def gen() -> AsyncIterator[bytes]:
            yield b"chunk1-"
            yield b"chunk2"

        async with session.post(base_url + "/echo", data=gen()) as resp:
            assert await resp.read() == b"chunk1-chunk2"

        async with session.put(base_url + "/echo", data=b"put-data") as resp:
            assert await resp.read() == b"put-data"
            assert resp.headers["X-Request-Method"] == "PUT"


@run_in_pyodide
async def _redirects_cookies_errors(selenium: Any, base_url: str) -> None:
    import asyncio

    import aiohttp

    async with aiohttp.ClientSession() as session:
        # fetch() follows the redirect transparently.
        async with session.get(base_url + "/redirect") as resp:
            assert resp.status == 200
            assert await resp.json() == {"hello": "world"}

        async with session.get(base_url + "/cookies") as resp:
            assert list(resp.headers.getall("Set-Cookie")) == [
                "first=1; Path=/",
                "second=2; Path=/",
            ]

        async with session.get(base_url + "/missing") as resp:
            assert resp.status == 404
        try:
            await session.get(base_url + "/missing", raise_for_status=True)
        except aiohttp.ClientResponseError as e:
            assert e.status == 404
        else:
            raise AssertionError("expected ClientResponseError")

        results = await asyncio.gather(
            *(session.get(base_url + "/json") for _ in range(5))
        )
        for r in results:
            assert await r.json() == {"hello": "world"}
            r.release()

        try:
            await session.get("http://127.0.0.1:2/")
        except aiohttp.ClientConnectionError:
            pass
        else:
            raise AssertionError("expected ClientConnectionError")


def test_get_json(selenium_with_aiohttp: Any, echo_server_url: str) -> None:
    _get_json(selenium_with_aiohttp, echo_server_url)


def test_post_bodies(selenium_with_aiohttp: Any, echo_server_url: str) -> None:
    _post_bodies(selenium_with_aiohttp, echo_server_url)


def test_redirects_cookies_errors(
    selenium_with_aiohttp: Any, echo_server_url: str
) -> None:
    _redirects_cookies_errors(selenium_with_aiohttp, echo_server_url)
