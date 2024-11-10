"""Tests for compression utils."""

from aiohttp.compression_utils import ZLibCompressor, ZLibDecompressor


async def test_compression_round_trip_in_executor():
    """Ensure that compression and decompression work correctly in the executor."""
    compressor = ZLibCompressor(max_sync_chunk_size=1)
    decompressor = ZLibDecompressor(max_sync_chunk_size=1)
    data = b"Hi" * 100
    compressed_data = await compressor.compress(data) + compressor.flush()
    decompressed_data = await decompressor.decompress(compressed_data)
    assert data == decompressed_data


async def test_compression_round_trip_in_event_loop():
    """Ensure that compression and decompression work correctly in the event loop."""
    compressor = ZLibCompressor(max_sync_chunk_size=10000)
    decompressor = ZLibDecompressor(max_sync_chunk_size=10000)
    data = b"Hi" * 100
    compressed_data = await compressor.compress(data) + compressor.flush()
    decompressed_data = await decompressor.decompress(compressed_data)
    assert data == decompressed_data
