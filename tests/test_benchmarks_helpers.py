"""codspeed benchmarks for aiohttp.helpers."""

from typing import TYPE_CHECKING

import pytest

from aiohttp.helpers import _LIST_ELEMENT_RE

if TYPE_CHECKING:
    from pytest_codspeed import BenchmarkFixture
else:
    pytest_codspeed = pytest.importorskip("pytest_codspeed")
    BenchmarkFixture = pytest_codspeed.BenchmarkFixture


@pytest.mark.parametrize(
    "value",
    (
        pytest.param(
            "a" + (" " * 16000) + "x",
            id="whitespace_run_after_content",
        ),
        pytest.param(
            r'\="(' * 16309,
            id="interleaved_quote_paren_triggers",
        ),
    ),
)
def test_list_element_pattern_redos_payload(
    value: str, benchmark: "BenchmarkFixture"
) -> None:
    assert len(list(_LIST_ELEMENT_RE.finditer(value))) == 1

    @benchmark
    def _run() -> None:
        list(_LIST_ELEMENT_RE.finditer(value))
