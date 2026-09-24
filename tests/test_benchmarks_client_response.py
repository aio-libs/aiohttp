"""codspeed benchmarks for ClientResponse."""

from typing import TYPE_CHECKING

import pytest

from aiohttp.client_reqrep import _LINK_PARAM_RE

if TYPE_CHECKING:
    from pytest_codspeed import BenchmarkFixture
else:
    pytest_codspeed = pytest.importorskip("pytest_codspeed")
    BenchmarkFixture = pytest_codspeed.BenchmarkFixture


@pytest.mark.parametrize(
    "value",
    (
        pytest.param("\n\t" * 13367 + "\x00", id="embedded_newlines"),
        pytest.param('\x00="' + "\t" * 14436 + "\x00", id="null_key_quote"),
        pytest.param(
            ("a=" * 6000) + "'" + ("b" * 6000) + " " + "b",
            id="key_swallows_equals",
        ),
        pytest.param(
            "key=" + (" " * 16000) + "'" + ("x" * 16000) + " " + "x",
            id="whitespace_run_after_equals",
        ),
    ),
)
def test_link_param_pattern_redos_payload(
    value: str, benchmark: "BenchmarkFixture"
) -> None:
    # None of these payloads describe a valid link param; they must not match.
    assert _LINK_PARAM_RE.match(value) is None

    @benchmark
    def _run() -> None:
        _LINK_PARAM_RE.match(value)
