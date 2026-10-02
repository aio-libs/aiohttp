"""codspeed benchmarks for cookie helpers."""

from typing import TYPE_CHECKING

import pytest

from aiohttp._cookie_helpers import _COOKIE_PATTERN

if TYPE_CHECKING:
    from pytest_codspeed import BenchmarkFixture
else:
    pytest_codspeed = pytest.importorskip("pytest_codspeed")
    BenchmarkFixture = pytest_codspeed.BenchmarkFixture


def test_cookie_pattern_redos_payload(benchmark: BenchmarkFixture) -> None:
    """Benchmark ``_COOKIE_PATTERN`` against a ReDoS payload.

    A regression that reintroduces catastrophic backtracking shows up here as
    a large, deterministic slowdown instead of a flaky wall-clock assertion.
    """
    value = "a" + "=" * 21651 + "\x00"
    # This payload must not match.
    assert _COOKIE_PATTERN.match(value) is None

    @benchmark
    def _run() -> None:
        _COOKIE_PATTERN.match(value)
