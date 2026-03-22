"""Tests for compression utils."""

import pytest

import aiohttp.compression_utils as compression_utils
from aiohttp.compression_utils import ZLibBackend, ZLibCompressor, ZLibDecompressor


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


def test_zstd_decompressor_stalled_unused_data_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class StallingZstdDecompressor:
        def __init__(self) -> None:
            self.unused_data = b""

        def decompress(self, data: bytes, max_length: int) -> bytes:
            self.unused_data = data
            return b""

    monkeypatch.setattr(compression_utils, "HAS_ZSTD", True)
    monkeypatch.setattr(compression_utils, "ZstdDecompressor", StallingZstdDecompressor)

    decompressor = compression_utils.ZSTDDecompressor()
    with pytest.raises(EOFError, match="unused_data did not shrink"):
        decompressor.decompress_sync(b"malformed")
