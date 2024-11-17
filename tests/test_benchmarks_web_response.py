"""codspeed benchmarks for the web responses."""

import asyncio

from pytest_codspeed import BenchmarkFixture

from aiohttp import web


def test_simple_web_response(
    loop: asyncio.AbstractEventLoop,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark creating 100 simple web.Response."""
    response_count = 100

    async def run_web_response_benchmark() -> None:
        for _ in range(response_count):
            web.Response()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_web_response_benchmark())


def test_web_response_with_headers(
    loop: asyncio.AbstractEventLoop,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark creating 100 web.Response with headers."""
    response_count = 100
    headers = {
        "Content-Type": "text/plain",
        "Server": "aiohttp",
        "Date": "Sun, 01 Aug 2021 12:00:00 GMT",
    }

    async def run_web_response_benchmark() -> None:
        for _ in range(response_count):
            web.Response(headers=headers)

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_web_response_benchmark())


def test_web_response_with_bytes_body(
    loop: asyncio.AbstractEventLoop,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark creating 100 web.Response with bytes."""
    response_count = 100

    async def run_web_response_benchmark() -> None:
        for _ in range(response_count):
            web.Response(body=b"Hello, World!")

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_web_response_benchmark())


def test_web_response_with_text_body(
    loop: asyncio.AbstractEventLoop,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark creating 100 web.Response with text."""
    response_count = 100

    async def run_web_response_benchmark() -> None:
        for _ in range(response_count):
            web.Response(text="Hello, World!")

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_web_response_benchmark())


def test_simple_web_stream_response(
    loop: asyncio.AbstractEventLoop,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark creating 100 simple web.StreamResponse."""
    response_count = 100

    async def run_web_response_benchmark() -> None:
        for _ in range(response_count):
            web.StreamResponse()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_web_response_benchmark())
