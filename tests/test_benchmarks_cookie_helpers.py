"""codspeed benchmarks for cookie helpers."""

from typing import TYPE_CHECKING

import pytest

from aiohttp._cookie_helpers import parse_set_cookie_headers

if TYPE_CHECKING:
    from pytest_codspeed import BenchmarkFixture
else:
    pytest_codspeed = pytest.importorskip("pytest_codspeed")
    BenchmarkFixture = pytest_codspeed.BenchmarkFixture


def test_parse_set_cookie_headers(benchmark: BenchmarkFixture) -> None:
    """Benchmark parsing typical Set-Cookie fields, including a quoted value."""
    headers = [
        f"cookie{i}=value{i}; Path=/; Domain=example.com; Max-Age=3600; "
        "Secure; HttpOnly; SameSite=Lax"
        for i in range(19)
    ]
    headers.append('quoted="a;b"; Path=/; Expires=Wed, 21 Oct 2037 07:28:00 GMT')
    assert len(parse_set_cookie_headers(headers)) == 20

    @benchmark
    def _run() -> None:
        parse_set_cookie_headers(headers)
