"""codspeed benchmarks for ClientResponse."""

import asyncio
from typing import TYPE_CHECKING

import pytest

from aiohttp.client_proto import ResponseHandler
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


def test_buffered_streamed_reads_skip_empty_parser_resumes(
    event_loop: asyncio.AbstractEventLoop, benchmark: "BenchmarkFixture"
) -> None:
    """Benchmark parser work across repeated reads from an already-buffered body."""

    class RecordingResponseHandler(ResponseHandler):
        def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
            super().__init__(loop=loop)
            self.empty_inputs = 0

        def data_received(self, data: bytes) -> None:
            if not data:
                self.empty_inputs += 1
            super().data_received(data)

    class PreviousResponseHandler(RecordingResponseHandler):
        def resume_reading(self, resume_parser: bool = True) -> None:
            # Match BaseProtocol.resume_reading before the optimization.
            self._reading_paused = False
            if not self._upgraded and resume_parser:
                self.data_received(b"")
            self._resume_transport_reading()

    async def read_buffered_body(
        handler_type: type[RecordingResponseHandler],
    ) -> int:
        proto = handler_type(loop=event_loop)
        proto.set_response_params()
        proto.data_received(
            b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\n" + b"x" * 64
        )
        _, payload = await proto.read()
        for _ in range(64):
            assert await payload.read(1) == b"x"
        return proto.empty_inputs

    assert (
        event_loop.run_until_complete(read_buffered_body(PreviousResponseHandler)) == 64
    )

    @benchmark
    def _run() -> None:
        assert (
            event_loop.run_until_complete(read_buffered_body(RecordingResponseHandler))
            == 0
        )
