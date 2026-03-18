"""Tests for compression utils."""

import pytest

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
