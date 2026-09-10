import zlib
from typing import Any
from unittest.mock import MagicMock

from aiohttp.helpers import DEFAULT_CHUNK_SIZE
from aiohttp.http2 import stream as h2_stream
from aiohttp.http2.errors import ErrorCode
from aiohttp.http2.settings import Setting
from aiohttp.http2.stream import StreamState
from aiohttp.http_exceptions import ContentEncodingError


async def test_deflate_buffer_assertion_on_unflushed_data(connection: Any) -> None:
    conn, _ = connection

    # Set the stream's low_water to a value below DEFAULT_CHUNK_SIZE.
    # This makes DeflateBuffer.max_length equal to DEFAULT_CHUNK_SIZE.
    conn.local_settings[Setting.INITIAL_WINDOW_SIZE] = 1024

    stream = await conn.create_stream()
    stream.state = StreamState.OPEN

    # Simulate server HEADERS with gzip content encoding.
    stream.receive_headers(
        [(":status", "200"), ("content-encoding", "deflate")],
        end_stream=False,
    )

    # Create compressed data that will expand to more than DEFAULT_CHUNK_SIZE.
    raw = b"a" * (DEFAULT_CHUNK_SIZE + 100)
    compressed = zlib.compress(raw)

    # END_STREAM=True triggers Stream.close() immediately after feed_data(),
    # which calls DeflateBuffer.feed_eof(). Because the decompressor still
    # holds unconsumed output, flush() returns non-empty bytes and the
    # assertion inside feed_eof() fails.
    stream.receive_data(compressed, end_stream=True)


def test_zip_bomb_protection(connection: Any, event_loop: Any) -> None:
    conn, _ = connection
    # Mock connection and protocol
    conn = MagicMock()
    conn.remote_settings = {Setting.INITIAL_WINDOW_SIZE: 65535}
    conn.local_settings = {Setting.INITIAL_WINDOW_SIZE: 65535}

    protocol = MagicMock()
    protocol._auto_decompress = True

    # Create the stream
    stream = h2_stream.Stream(
        stream_id=1, conn=conn, loop=event_loop, protocol=protocol
    )
    stream.state = StreamState.OPEN

    # Send headers indicating gzip compression
    headers = [
        (":status", "200"),
        ("content-encoding", "deflate"),
    ]
    stream.receive_headers(headers, end_stream=False, limit=65535)  # type: ignore[arg-type]

    # Generate a small zip bomb
    bomb = zlib.compress(b"\x00" * (1024 * 1024 * 3))

    # Feed the bomb as a DATA frame
    stream.receive_data(bomb, end_stream=False)

    # The stream should have sent an RST_STREAM with INTERNAL_ERROR
    conn._send_rst_stream.assert_called_once_with(1, ErrorCode.INTERNAL_ERROR)

    # The body reader should have received a ContentEncodingError
    exc = stream.body_reader.exception()
    assert isinstance(exc, ContentEncodingError)
