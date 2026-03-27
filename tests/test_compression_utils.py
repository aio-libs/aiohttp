"""Tests for compression utils."""

import sys

import pytest

from aiohttp.compression_utils import (
    ZLibBackend,
    ZLibCompressor,
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
