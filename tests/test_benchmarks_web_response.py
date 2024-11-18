"""codspeed benchmarks for the web responses."""

from pytest_codspeed import BenchmarkFixture

from aiohttp import web


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
