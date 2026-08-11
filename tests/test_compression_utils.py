"""Tests for compression utils."""

import gzip
import sys
import zlib
from typing import Any

import pytest

from aiohttp.compression_utils import (
    MAX_DECOMPRESS_MEMBERS,
    MEMBER_WINDOW_MAX,
    TooManyMembersError,
    ZLibBackend,
    ZLibCompressor,
    ZLibDecompressObjProtocol,
    ZLibDecompressor,
    ZSTDDecompressor,
)

try:
    if sys.version_info >= (3, 14):
        import compression.zstd as zstandard  # noqa: I900
    else:
        import backports.zstd as zstandard
except ImportError:  # pragma: no cover
    zstandard = None  # type: ignore[assignment]


class _RecordingDecompressObj:
    """decompressobj proxy recording the size of every buffer fed to it."""

    def __init__(self, obj: ZLibDecompressObjProtocol, feeds: list[int]) -> None:
        self._obj = obj
        self._feeds = feeds

    def __getattr__(self, name: str) -> Any:
        return getattr(self._obj, name)

    def decompress(self, data: Any, max_length: int = 0) -> bytes:
        self._feeds.append(len(data))
        return self._obj.decompress(data, max_length)


@pytest.mark.usefixtures("parametrize_zlib_backend")
async def test_compression_round_trip_in_executor() -> None:
    """Ensure that compression and decompression work correctly in the executor."""
    compressor = ZLibCompressor(
        strategy=ZLibBackend.Z_DEFAULT_STRATEGY, max_sync_chunk_size=1
    )
    assert type(compressor._compressor) is type(ZLibBackend.compressobj())
    decompressor = ZLibDecompressor(max_sync_chunk_size=1)
    assert type(decompressor._decompressor) is type(ZLibBackend.decompressobj())
    data = b"Hi" * 100
    compressed_data = await compressor.compress(data) + compressor.flush()
    decompressed_data = await decompressor.decompress(compressed_data)
    assert data == decompressed_data


@pytest.mark.usefixtures("parametrize_zlib_backend")
async def test_compression_round_trip_in_event_loop() -> None:
    """Ensure that compression and decompression work correctly in the event loop."""
    compressor = ZLibCompressor(
        strategy=ZLibBackend.Z_DEFAULT_STRATEGY, max_sync_chunk_size=10000
    )
    assert type(compressor._compressor) is type(ZLibBackend.compressobj())
    decompressor = ZLibDecompressor(max_sync_chunk_size=10000)
    assert type(decompressor._decompressor) is type(ZLibBackend.decompressobj())
    data = b"Hi" * 100
    compressed_data = await compressor.compress(data) + compressor.flush()
    decompressed_data = await decompressor.decompress(compressed_data)
    assert data == decompressed_data


@pytest.mark.skipif(zstandard is None, reason="zstandard is not installed")
def test_zstd_multi_frame_unlimited() -> None:
    d = ZSTDDecompressor()
    frame1 = zstandard.compress(b"AAAA")
    frame2 = zstandard.compress(b"BBBB")
    result = d.decompress_sync(frame1 + frame2)
    assert result == b"AAAABBBB"


@pytest.mark.skipif(zstandard is None, reason="zstandard is not installed")
def test_zstd_multi_frame_max_length_partial() -> None:
    d = ZSTDDecompressor()
    frame1 = zstandard.compress(b"AAAA")
    frame2 = zstandard.compress(b"BBBB")
    result = d.decompress_sync(frame1 + frame2, max_length=6)
    assert result == b"AAAABB"


@pytest.mark.skipif(zstandard is None, reason="zstandard is not installed")
def test_zstd_multi_frame_max_length_exhausted() -> None:
    d = ZSTDDecompressor()
    frame1 = zstandard.compress(b"AAAA")
    frame2 = zstandard.compress(b"BBBB")
    result = d.decompress_sync(frame1 + frame2, max_length=4)
    assert result == b"AAAA"


@pytest.mark.skipif(zstandard is None, reason="zstandard is not installed")
def test_zstd_multi_frame_max_length_exhausted_preserves_unused_data() -> None:
    d = ZSTDDecompressor()
    frame1 = zstandard.compress(b"AAAA")
    frame2 = zstandard.compress(b"BBBB")
    frame3 = zstandard.compress(b"CCCC")
    result1 = d.decompress_sync(frame1 + frame2, max_length=4)
    assert result1 == b"AAAA"
    result2 = d.decompress_sync(frame3)
    assert result2 == b"BBBBCCCC"


def test_zlib_gzip_multi_member_unlimited() -> None:
    d = ZLibDecompressor(encoding="gzip")
    member1 = gzip.compress(b"AAAA")
    member2 = gzip.compress(b"BBBB")
    result = d.decompress_sync(member1 + member2)
    assert result == b"AAAABBBB"


def test_zlib_gzip_multi_member_max_length_partial() -> None:
    d = ZLibDecompressor(encoding="gzip")
    member1 = gzip.compress(b"AAAA")
    member2 = gzip.compress(b"BBBB")
    result = d.decompress_sync(member1 + member2, max_length=6)
    assert result == b"AAAABB"


def test_zlib_gzip_multi_member_max_length_exhausted() -> None:
    d = ZLibDecompressor(encoding="gzip")
    member1 = gzip.compress(b"AAAA")
    member2 = gzip.compress(b"BBBB")
    result = d.decompress_sync(member1 + member2, max_length=4)
    assert result == b"AAAA"


def test_zlib_gzip_multi_member_max_length_exhausted_preserves_unused_data() -> None:
    d = ZLibDecompressor(encoding="gzip")
    member1 = gzip.compress(b"AAAA")
    member2 = gzip.compress(b"BBBB")
    member3 = gzip.compress(b"CCCC")
    result1 = d.decompress_sync(member1 + member2, max_length=4)
    assert result1 == b"AAAA"
    result2 = d.decompress_sync(member3)
    assert result2 == b"BBBBCCCC"


def test_zlib_gzip_multi_member_walks_input_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every member is decoded from a bounded window, not from the whole tail.

    A fresh decompressor copies everything past the member it decodes into
    unused_data, so handing it the rest of the buffer at each boundary is
    quadratic: this blob would push ~6GiB through unused_data.
    """
    blob = gzip.compress(b"") * (MAX_DECOMPRESS_MEMBERS - 1)
    d = ZLibDecompressor(encoding="gzip")
    feeds: list[int] = []
    decompressobj = d._zlib_backend.decompressobj

    def recording(*, wbits: int) -> _RecordingDecompressObj:
        return _RecordingDecompressObj(decompressobj(wbits=wbits), feeds)

    monkeypatch.setattr(d._zlib_backend, "decompressobj", recording)
    assert d.decompress_sync(blob) == b""
    assert max(feeds) <= MEMBER_WINDOW_MAX
    assert sum(feeds) < 8 * len(blob)


def test_zlib_deflate_member_flood_rejected() -> None:
    """Zero-output members never decrement max_length, cap must stop them."""
    co = zlib.compressobj(wbits=-15)
    empty_member = co.compress(b"") + co.flush()  # 2-byte empty raw-deflate member
    d = ZLibDecompressor(encoding="deflate", suppress_deflate_header=True)
    with pytest.raises(TooManyMembersError):
        d.decompress_sync(empty_member * 5000, max_length=262144)


def test_zlib_deflate_members_at_limit() -> None:
    """The limit counts the member decoded before the walk started."""
    co = zlib.compressobj(wbits=-15)
    empty_member = co.compress(b"") + co.flush()
    d = ZLibDecompressor(encoding="deflate", suppress_deflate_header=True)
    assert d.decompress_sync(empty_member * MAX_DECOMPRESS_MEMBERS) == b""


def test_zlib_deflate_members_one_over_limit() -> None:
    co = zlib.compressobj(wbits=-15)
    empty_member = co.compress(b"") + co.flush()
    d = ZLibDecompressor(encoding="deflate", suppress_deflate_header=True)
    with pytest.raises(TooManyMembersError):
        d.decompress_sync(empty_member * (MAX_DECOMPRESS_MEMBERS + 1))


@pytest.mark.parametrize("max_length", (0, 262144), ids=("unlimited", "capped"))
def test_zlib_gzip_many_members(max_length: int) -> None:
    """A call may decode up to the member limit, resuming across calls."""
    member = gzip.compress(b"A" * 64)
    count = MAX_DECOMPRESS_MEMBERS
    d = ZLibDecompressor(encoding="gzip")
    out = d.decompress_sync(member * count, max_length=max_length)
    while d.data_available:
        out += d.decompress_sync(b"", max_length=max_length)
    assert out == b"A" * 64 * count


def test_zlib_gzip_empty_members_interleaved_with_output() -> None:
    blob = (gzip.compress(b"") + gzip.compress(b"DATA")) * 20
    d = ZLibDecompressor(encoding="gzip")
    assert d.decompress_sync(blob) == b"DATA" * 20


@pytest.mark.skipif(zstandard is None, reason="zstandard is not installed")
def test_zstd_frame_flood_rejected() -> None:
    """Multi-frame zstd shares the walk, so it shares the limit."""
    d = ZSTDDecompressor()
    with pytest.raises(TooManyMembersError):
        d.decompress_sync(zstandard.compress(b"") * 5000)


@pytest.mark.skipif(zstandard is None, reason="zstandard is not installed")
def test_zstd_many_frames() -> None:
    frame = zstandard.compress(b"B" * 64)
    count = MAX_DECOMPRESS_MEMBERS
    d = ZSTDDecompressor()
    assert d.decompress_sync(frame * count) == b"B" * 64 * count
