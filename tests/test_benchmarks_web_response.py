"""codspeed benchmarks for the web responses."""

import asyncio
from typing import TYPE_CHECKING

import pytest

from aiohttp import web
from aiohttp.test_utils import make_mocked_request

if TYPE_CHECKING:
    from pytest_codspeed import BenchmarkFixture
else:
    pytest_codspeed = pytest.importorskip("pytest_codspeed")
    BenchmarkFixture = pytest_codspeed.BenchmarkFixture


def test_simple_web_response(benchmark: BenchmarkFixture) -> None:
    """Benchmark creating 100 simple web.Response."""
    response_count = 100

    @benchmark
    def _run() -> None:
        for _ in range(response_count):
            web.Response()


def test_web_response_with_headers(benchmark: BenchmarkFixture) -> None:
    """Benchmark creating 100 web.Response with headers."""
    response_count = 100
    headers = {
        "Content-Type": "text/plain",
        "Server": "aiohttp",
        "Date": "Sun, 01 Aug 2021 12:00:00 GMT",
    }

    @benchmark
    def _run() -> None:
        for _ in range(response_count):
            web.Response(headers=headers)


@pytest.mark.parametrize(
    "date_header",
    (None, "Sun, 01 Aug 2021 12:00:00 GMT"),
    ids=("generated-date", "explicit-date"),
)
def test_prepare_web_response_headers(
    benchmark: BenchmarkFixture,
    event_loop: asyncio.AbstractEventLoop,
    date_header: str | None,
) -> None:
    """Benchmark preparing 100 response headers with and without a Date header."""
    response_count = 100
    headers = {
        "Content-Length": "0",
        "Content-Type": "text/plain",
        "Server": "aiohttp",
    }
    if date_header is not None:
        headers["Date"] = date_header
    request = make_mocked_request("GET", "/")

    async def prepare_responses() -> None:
        for _ in range(response_count):
            response = web.Response(headers=headers)
            response._req = request
            response._payload_writer = request._payload_writer
            await response._prepare_headers()

    @benchmark
    def _run() -> None:
        event_loop.run_until_complete(prepare_responses())


def test_web_response_with_bytes_body(
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark creating 100 web.Response with bytes."""
    response_count = 100

    @benchmark
    def _run() -> None:
        for _ in range(response_count):
            web.Response(body=b"Hello, World!")


def test_web_response_with_text_body(benchmark: BenchmarkFixture) -> None:
    """Benchmark creating 100 web.Response with text."""
    response_count = 100

    @benchmark
    def _run() -> None:
        for _ in range(response_count):
            web.Response(text="Hello, World!")


def test_simple_web_stream_response(benchmark: BenchmarkFixture) -> None:
    """Benchmark creating 100 simple web.StreamResponse."""
    response_count = 100

    @benchmark
    def _run() -> None:
        for _ in range(response_count):
            web.StreamResponse()
