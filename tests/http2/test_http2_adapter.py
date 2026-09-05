import asyncio
from typing import Any, Generator, List, Tuple
from unittest.mock import AsyncMock, MagicMock

import pytest

from aiohttp.http2.adapter import Http2StreamWriter


@pytest.fixture
def writer() -> Generator[Any, None, None]:
    """Create an Http2StreamWriter with mocked dependencies."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    protocol = MagicMock()
    protocol.transport = MagicMock()
    protocol._connection = MagicMock()
    protocol._connection.send_headers = MagicMock()
    protocol._connection.send_data = AsyncMock()

    req = MagicMock()
    req.stream_id = 123
    req.method = "POST"
    req.url = "https://example.com/path"

    writer = Http2StreamWriter(protocol, loop, req)

    yield writer, protocol, req, loop
    loop.close()


# ----------------------------------------------------------------------
# Helper to check send_headers call arguments
# ----------------------------------------------------------------------
def assert_send_headers_called(
    protocol: Any,
    stream_id: int,
    method: str,
    url: Any,
    headers: List[Tuple[str, str]],
    end_stream: bool,
) -> None:
    protocol._connection.send_headers.assert_called_once_with(
        stream_id, method, url, headers, end_stream=end_stream
    )


# ======================================================================
# write_headers
# ======================================================================
class TestWriteHeaders:
    def test_buffers_headers(self, writer: Any) -> None:
        w, protocol, req, loop = writer
        headers = {"content-type": "application/json", "x-test": "value"}
        asyncio.run(w.write_headers("HTTP/2.0 200", headers))

        assert w._headers == [("content-type", "application/json"), ("x-test", "value")]
        assert w._headers_sent is False
        protocol._connection.send_headers.assert_not_called()


# ======================================================================
# write
# ======================================================================
class TestWrite:
    def test_write_after_eof_raises(self, writer: Any) -> None:
        w, protocol, req, loop = writer
        w._eof = True
        with pytest.raises(RuntimeError, match="Cannot write after EOF"):
            asyncio.run(w.write(b"data"))

    def test_write_without_headers_raises(self, writer: Any) -> None:
        w, protocol, req, loop = writer
        # _headers is None and _headers_sent is False
        with pytest.raises(RuntimeError, match="Headers must be written before body"):
            asyncio.run(w.write(b"data"))

    def test_write_sends_headers_and_data(self, writer: Any) -> None:
        w, protocol, req, loop = writer
        headers = [("content-type", "text/plain")]
        w._headers = headers
        data = b"hello"

        asyncio.run(w.write(data))

        # Headers sent first
        assert_send_headers_called(
            protocol, 123, "POST", req.url, headers, end_stream=False
        )
        # Data sent
        protocol._connection.send_data.assert_called_once_with(
            123, data, end_stream=False
        )
        assert w.output_size == len(data)
        assert w._headers_sent is True
        assert w._headers is None

    def test_write_empty_chunk_after_headers(self, writer: Any) -> None:
        w, protocol, req, loop = writer
        w._headers = [("x", "y")]
        w._headers_sent = True  # simulate already sent
        w._headers = None

        asyncio.run(w.write(b""))

        protocol._connection.send_data.assert_not_called()
        assert w.output_size == 0

    def test_write_after_headers_sent(self, writer: Any) -> None:
        w, protocol, req, loop = writer
        w._headers_sent = True
        data = b"more"

        asyncio.run(w.write(data))

        protocol._connection.send_headers.assert_not_called()
        protocol._connection.send_data.assert_called_once_with(
            123, data, end_stream=False
        )
        assert w.output_size == len(data)


# ======================================================================
# write_eof
# ======================================================================
class TestWriteEof:
    def test_write_eof_twice_noop(self, writer: Any) -> None:
        w, protocol, req, loop = writer
        w._eof = True
        asyncio.run(w.write_eof(b""))
        protocol._connection.send_headers.assert_not_called()
        protocol._connection.send_data.assert_not_called()

    def test_write_eof_without_headers_raises(self, writer: Any) -> None:
        w, protocol, req, loop = writer
        with pytest.raises(RuntimeError, match="Headers must be written before body"):
            asyncio.run(w.write_eof(b""))

    def test_write_eof_headers_not_sent_with_chunk(self, writer: Any) -> None:
        w, protocol, req, loop = writer
        headers = [("content-type", "text/plain")]
        w._headers = headers
        chunk = b"final-data"

        asyncio.run(w.write_eof(chunk))

        # Headers sent without END_STREAM
        assert_send_headers_called(
            protocol, 123, "POST", req.url, headers, end_stream=False
        )
        # Data with END_STREAM
        protocol._connection.send_data.assert_called_once_with(
            123, chunk, end_stream=True
        )
        assert w.output_size == len(chunk)
        assert w._eof is True

    def test_write_eof_headers_not_sent_no_chunk(self, writer: Any) -> None:
        w, protocol, req, loop = writer
        headers = [("content-type", "text/plain")]
        w._headers = headers

        asyncio.run(w.write_eof(b""))

        # Headers with END_STREAM
        assert_send_headers_called(
            protocol, 123, "POST", req.url, headers, end_stream=True
        )
        protocol._connection.send_data.assert_not_called()
        assert w.output_size == 0
        assert w._eof is True

    def test_write_eof_headers_already_sent(self, writer: Any) -> None:
        w, protocol, req, loop = writer
        w._headers_sent = True
        chunk = b"final"

        asyncio.run(w.write_eof(chunk))

        protocol._connection.send_headers.assert_not_called()
        protocol._connection.send_data.assert_called_once_with(
            123, chunk, end_stream=True
        )
        assert w.output_size == len(chunk)
        assert w._eof is True

    def test_write_eof_headers_already_sent_empty_chunk(self, writer: Any) -> None:
        w, protocol, req, loop = writer
        w._headers_sent = True

        asyncio.run(w.write_eof(b""))

        protocol._connection.send_headers.assert_not_called()
        protocol._connection.send_data.assert_called_once_with(
            123, b"", end_stream=True
        )
        assert w.output_size == 0
        assert w._eof is True


# ======================================================================
# set_eof
# ======================================================================
class TestSetEof:
    def test_set_eof_twice_noop(self, writer: Any) -> None:
        w, protocol, req, loop = writer
        w._eof = True
        w.set_eof()
        protocol._connection.send_headers.assert_not_called()

    def test_set_eof_without_headers_raises(self, writer: Any) -> None:
        w, protocol, req, loop = writer
        with pytest.raises(RuntimeError, match="Headers must be written before EOF"):
            w.set_eof()

    def test_set_eof_headers_not_sent(self, writer: Any) -> None:
        w, protocol, req, loop = writer
        headers = [("content-type", "text/plain")]
        w._headers = headers

        w.set_eof()

        assert_send_headers_called(
            protocol, 123, "POST", req.url, headers, end_stream=True
        )
        assert w._eof is True
        assert w._headers is None
        assert w._headers_sent is True

    def test_set_eof_headers_already_sent(self, writer: Any) -> None:
        w, protocol, req, loop = writer
        w._headers_sent = True

        w.set_eof()

        protocol._connection.send_headers.assert_not_called()
        assert w._eof is True
