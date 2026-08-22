"""codspeed benchmarks for multipart body part reading."""

import asyncio
import base64
from typing import TYPE_CHECKING

import pytest
from multidict import CIMultiDict

from aiohttp.base_protocol import BaseProtocol
from aiohttp.hdrs import CONTENT_TRANSFER_ENCODING
from aiohttp.helpers import DEFAULT_CHUNK_SIZE
from aiohttp.multipart import BodyPartReader
from aiohttp.streams import StreamReader

if TYPE_CHECKING:
    from pytest_codspeed import BenchmarkFixture
else:
    pytest_codspeed = pytest.importorskip("pytest_codspeed")
    BenchmarkFixture = pytest_codspeed.BenchmarkFixture

BOUNDARY = b"--:"
BASE64_HEADERS: CIMultiDict[str] = CIMultiDict({CONTENT_TRANSFER_ENCODING: "base64"})


class _NoFlowControlProtocol(BaseProtocol):
    """The whole body is fed up front, so there is nothing to pause or resume."""

    def pause_reading(self) -> None:
        """Swallow pause."""

    def resume_reading(self, resume_parser: bool = True) -> None:
        """Swallow resume."""


def _part(body: bytes, loop: asyncio.AbstractEventLoop) -> BodyPartReader:
    stream = StreamReader(_NoFlowControlProtocol(loop), DEFAULT_CHUNK_SIZE, loop=loop)
    stream.feed_data(body)
    stream.feed_eof()
    return BodyPartReader(
        BOUNDARY,
        CIMultiDict(BASE64_HEADERS),
        stream,
        client_max_size=10 * 1024**2,
    )


def test_read_base64_part(
    loop: asyncio.AbstractEventLoop, benchmark: BenchmarkFixture
) -> None:
    """Read a line-wrapped base64 part to completion.

    Every 8 KiB chunk lands mid-quartet, so this covers the common cost of
    the base64 realignment in ``read_chunk`` on well-formed input.
    """
    body = base64.encodebytes(b"x" * (256 * 1024)).replace(b"\n", b"\r\n")
    body += b"\r\n--:--"

    @benchmark
    def _run() -> None:
        loop.run_until_complete(_part(body, loop).read())


def test_read_chunk_base64_realignment(
    loop: asyncio.AbstractEventLoop, benchmark: BenchmarkFixture
) -> None:
    """Complete a base64 quartet across the longest run it will tolerate.

    ``read_chunk`` extends a chunk until its significant-character count is a
    multiple of 4. Insignificant bytes never advance that count, so this walks
    close to the whole allowance in one call -- the worst legitimate case, and
    the shape that used to cost quadratic time.
    """
    body = b"A" + b" " * (12 * 1024) + b"BBB\r\n--:--"

    @benchmark
    def _run() -> None:
        loop.run_until_complete(_part(body, loop).read_chunk(BodyPartReader.chunk_size))
