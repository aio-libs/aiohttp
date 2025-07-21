import array
import asyncio
import io
import json
import unittest.mock
from io import StringIO
from pathlib import Path
from typing import AsyncIterator, Iterator, List, Optional, TextIO, Union

import pytest
from multidict import CIMultiDict

from aiohttp import payload
from aiohttp.abc import AbstractStreamWriter
from aiohttp.payload import READ_SIZE


class BufferWriter(AbstractStreamWriter):
    """Test writer that captures written bytes in a buffer."""

    def __init__(self) -> None:
        self.buffer = bytearray()

    async def write(
        self, chunk: Union[bytes, bytearray, "memoryview[int]", "memoryview[bytes]"]
    ) -> None:
        self.buffer.extend(bytes(chunk))

    async def write_eof(self, chunk: bytes = b"") -> None:
        """No-op for test writer."""

    async def drain(self) -> None:
        """No-op for test writer."""

    def enable_compression(
        self, encoding: str = "deflate", strategy: Optional[int] = None
    ) -> None:
        """Compression not implemented for test writer."""

    def enable_chunking(self) -> None:
        """Chunking not implemented for test writer."""

    async def write_headers(self, status_line: str, headers: CIMultiDict[str]) -> None:
        """Headers not captured for payload tests."""


@pytest.fixture(autouse=True)
def cleanup(
    cleanup_payload_pending_file_closes: None,
) -> None:
    """Ensure all pending file close operations complete during test teardown."""


@pytest.fixture
def registry() -> Iterator[payload.PayloadRegistry]:
    old = payload.PAYLOAD_REGISTRY
    reg = payload.PAYLOAD_REGISTRY = payload.PayloadRegistry()
    yield reg
    payload.PAYLOAD_REGISTRY = old


class Payload(payload.Payload):
    def decode(self, encoding: str = "utf-8", errors: str = "strict") -> str:
        assert False

    async def write(self, writer: AbstractStreamWriter) -> None:
        pass


def test_register_type(registry: payload.PayloadRegistry) -> None:
    class TestProvider:
        pass

    payload.register_payload(Payload, TestProvider)
    p = payload.get_payload(TestProvider())
    assert isinstance(p, Payload)


def test_register_unsupported_order(registry: payload.PayloadRegistry) -> None:
    class TestProvider:
        pass

    with pytest.raises(ValueError):
        payload.register_payload(
            Payload, TestProvider, order=object()  # type: ignore[arg-type]
        )


def test_payload_ctor() -> None:
    p = Payload("test", encoding="utf-8", filename="test.txt")
    assert p._value == "test"
    assert p._encoding == "utf-8"
    assert p.size is None
    assert p.filename == "test.txt"
    assert p.content_type == "text/plain"


def test_payload_content_type() -> None:
    p = Payload("test", headers={"content-type": "application/json"})
    assert p.content_type == "application/json"


def test_bytes_payload_default_content_type() -> None:
    p = payload.BytesPayload(b"data")
    assert p.content_type == "application/octet-stream"


def test_bytes_payload_explicit_content_type() -> None:
    p = payload.BytesPayload(b"data", content_type="application/custom")
    assert p.content_type == "application/custom"


def test_bytes_payload_bad_type() -> None:
    with pytest.raises(TypeError):
        payload.BytesPayload(object())  # type: ignore[arg-type]


def test_bytes_payload_memoryview_correct_size() -> None:
    mv = memoryview(array.array("H", [1, 2, 3]))
    p = payload.BytesPayload(mv)
    assert p.size == 6


def test_string_payload() -> None:
    p = payload.StringPayload("test")
    assert p.encoding == "utf-8"
    assert p.content_type == "text/plain; charset=utf-8"

    p = payload.StringPayload("test", encoding="koi8-r")
    assert p.encoding == "koi8-r"
    assert p.content_type == "text/plain; charset=koi8-r"

    p = payload.StringPayload("test", content_type="text/plain; charset=koi8-r")
    assert p.encoding == "koi8-r"
    assert p.content_type == "text/plain; charset=koi8-r"


def test_string_io_payload() -> None:
    s = StringIO("ű" * 5000)
    p = payload.StringIOPayload(s)
    assert p.encoding == "utf-8"
    assert p.content_type == "text/plain; charset=utf-8"
    assert p.size == 10000


def test_async_iterable_payload_default_content_type() -> None:
    async def gen() -> AsyncIterator[bytes]:
        return
        yield b"abc"  # type: ignore[unreachable]  # pragma: no cover

    p = payload.AsyncIterablePayload(gen())
    assert p.content_type == "application/octet-stream"


def test_async_iterable_payload_explicit_content_type() -> None:
    async def gen() -> AsyncIterator[bytes]:
        return
        yield b"abc"  # type: ignore[unreachable]  # pragma: no cover

    p = payload.AsyncIterablePayload(gen(), content_type="application/custom")
    assert p.content_type == "application/custom"


def test_async_iterable_payload_not_async_iterable() -> None:
    with pytest.raises(TypeError):
        payload.AsyncIterablePayload(object())  # type: ignore[arg-type]


class MockStreamWriter(AbstractStreamWriter):
    """Mock stream writer for testing payload writes."""

    def __init__(self) -> None:
        self.written: List[bytes] = []

    async def write(
        self, chunk: Union[bytes, bytearray, "memoryview[int]", "memoryview[bytes]"]
    ) -> None:
        """Store the chunk in the written list."""
        self.written.append(bytes(chunk))

    async def write_eof(self, chunk: Optional[bytes] = None) -> None:
        """write_eof implementation - no-op for tests."""

    async def drain(self) -> None:
        """Drain implementation - no-op for tests."""

    def enable_compression(
        self, encoding: str = "deflate", strategy: Optional[int] = None
    ) -> None:
        """Enable compression - no-op for tests."""

    def enable_chunking(self) -> None:
        """Enable chunking - no-op for tests."""

    async def write_headers(self, status_line: str, headers: CIMultiDict[str]) -> None:
        """Write headers - no-op for tests."""

    def get_written_bytes(self) -> bytes:
        """Return all written bytes as a single bytes object."""
        return b"".join(self.written)


async def test_bytes_payload_write_with_length_no_limit() -> None:
    """Test BytesPayload writing with no content length limit."""
    data = b"0123456789"
    p = payload.BytesPayload(data)
    writer = MockStreamWriter()

    await p.write_with_length(writer, None)
    assert writer.get_written_bytes() == data
    assert len(writer.get_written_bytes()) == 10


async def test_bytes_payload_write_with_length_exact() -> None:
    """Test BytesPayload writing with exact content length."""
    data = b"0123456789"
    p = payload.BytesPayload(data)
    writer = MockStreamWriter()

    await p.write_with_length(writer, 10)
    assert writer.get_written_bytes() == data
    assert len(writer.get_written_bytes()) == 10


async def test_bytes_payload_write_with_length_truncated() -> None:
    """Test BytesPayload writing with truncated content length."""
    data = b"0123456789"
    p = payload.BytesPayload(data)
    writer = MockStreamWriter()

    await p.write_with_length(writer, 5)
    assert writer.get_written_bytes() == b"01234"
    assert len(writer.get_written_bytes()) == 5


async def test_iobase_payload_write_with_length_no_limit() -> None:
    """Test IOBasePayload writing with no content length limit."""
    data = b"0123456789"
    p = payload.IOBasePayload(io.BytesIO(data))
    writer = MockStreamWriter()

    await p.write_with_length(writer, None)
    assert writer.get_written_bytes() == data
    assert len(writer.get_written_bytes()) == 10


async def test_iobase_payload_write_with_length_exact() -> None:
    """Test IOBasePayload writing with exact content length."""
    data = b"0123456789"
    p = payload.IOBasePayload(io.BytesIO(data))
    writer = MockStreamWriter()

    await p.write_with_length(writer, 10)
    assert writer.get_written_bytes() == data
    assert len(writer.get_written_bytes()) == 10


async def test_iobase_payload_write_with_length_truncated() -> None:
    """Test IOBasePayload writing with truncated content length."""
    data = b"0123456789"
    p = payload.IOBasePayload(io.BytesIO(data))
    writer = MockStreamWriter()

    await p.write_with_length(writer, 5)
    assert writer.get_written_bytes() == b"01234"
    assert len(writer.get_written_bytes()) == 5


async def test_bytesio_payload_write_with_length_no_limit() -> None:
    """Test BytesIOPayload writing with no content length limit."""
    data = b"0123456789"
    p = payload.BytesIOPayload(io.BytesIO(data))
    writer = MockStreamWriter()

    await p.write_with_length(writer, None)
    assert writer.get_written_bytes() == data
    assert len(writer.get_written_bytes()) == 10


async def test_bytesio_payload_write_with_length_exact() -> None:
    """Test BytesIOPayload writing with exact content length."""
    data = b"0123456789"
    p = payload.BytesIOPayload(io.BytesIO(data))
    writer = MockStreamWriter()

    await p.write_with_length(writer, 10)
    assert writer.get_written_bytes() == data
    assert len(writer.get_written_bytes()) == 10


async def test_bytesio_payload_write_with_length_truncated() -> None:
    """Test BytesIOPayload writing with truncated content length."""
    data = b"0123456789"
    payload_bytesio = payload.BytesIOPayload(io.BytesIO(data))
    writer = MockStreamWriter()

    await payload_bytesio.write_with_length(writer, 5)
    assert writer.get_written_bytes() == b"01234"
    assert len(writer.get_written_bytes()) == 5


async def test_bytesio_payload_write_with_length_remaining_zero() -> None:
    """Test BytesIOPayload with content_length smaller than first read chunk."""
    data = b"0123456789" * 10  # 100 bytes
    bio = io.BytesIO(data)
    payload_bytesio = payload.BytesIOPayload(bio)
    writer = MockStreamWriter()

    # Mock the read method to return smaller chunks
    original_read = bio.read
    read_calls = 0

    def mock_read(size: Optional[int] = None) -> bytes:
        nonlocal read_calls
        read_calls += 1
        if read_calls == 1:
            # First call: return 3 bytes (less than content_length=5)
            return original_read(3)
        else:
            # Subsequent calls return remaining data normally
            return original_read(size)

    with unittest.mock.patch.object(bio, "read", mock_read):
        await payload_bytesio.write_with_length(writer, 5)

    assert len(writer.get_written_bytes()) == 5
    assert writer.get_written_bytes() == b"01234"


async def test_bytesio_payload_large_data_multiple_chunks() -> None:
    """Test BytesIOPayload with large data requiring multiple read chunks."""
    chunk_size = 2**16  # 64KB (READ_SIZE)
    data = b"x" * (chunk_size + 1000)  # Slightly larger than READ_SIZE
    payload_bytesio = payload.BytesIOPayload(io.BytesIO(data))
    writer = MockStreamWriter()

    await payload_bytesio.write_with_length(writer, None)
    assert writer.get_written_bytes() == data
    assert len(writer.get_written_bytes()) == chunk_size + 1000


async def test_bytesio_payload_remaining_bytes_exhausted() -> None:
    """Test BytesIOPayload when remaining_bytes becomes <= 0."""
    data = b"0123456789abcdef" * 1000  # 16000 bytes
    payload_bytesio = payload.BytesIOPayload(io.BytesIO(data))
    writer = MockStreamWriter()

    await payload_bytesio.write_with_length(writer, 8000)  # Exactly half the data
    written = writer.get_written_bytes()
    assert len(written) == 8000
    assert written == data[:8000]


async def test_iobase_payload_exact_chunk_size_limit() -> None:
    """Test IOBasePayload with content length matching exactly one read chunk."""
    chunk_size = 2**16  # 65536 bytes (READ_SIZE)
    data = b"x" * chunk_size + b"extra"  # Slightly larger than one read chunk
    p = payload.IOBasePayload(io.BytesIO(data))
    writer = MockStreamWriter()

    await p.write_with_length(writer, chunk_size)
    written = writer.get_written_bytes()
    assert len(written) == chunk_size
    assert written == data[:chunk_size]


async def test_iobase_payload_reads_in_chunks() -> None:
    """Test IOBasePayload reads data in chunks of READ_SIZE, not all at once."""
    # Create a large file that's multiple times larger than READ_SIZE
    large_data = b"x" * (READ_SIZE * 3 + 1000)  # ~192KB + 1000 bytes

    # Mock the file-like object to track read calls
    mock_file = unittest.mock.Mock(spec=io.BytesIO)
    mock_file.tell.return_value = 0
    mock_file.fileno.side_effect = AttributeError  # Make size return None

    # Track the sizes of read() calls
    read_sizes = []

    def mock_read(size: int) -> bytes:
        read_sizes.append(size)
        # Return data based on how many times read was called
        call_count = len(read_sizes)
        if call_count == 1:
            return large_data[:size]
        elif call_count == 2:
            return large_data[READ_SIZE : READ_SIZE + size]
        elif call_count == 3:
            return large_data[READ_SIZE * 2 : READ_SIZE * 2 + size]
        else:
            return large_data[READ_SIZE * 3 :]

    mock_file.read.side_effect = mock_read

    payload_obj = payload.IOBasePayload(mock_file)
    writer = MockStreamWriter()

    # Write with a large content_length
    await payload_obj.write_with_length(writer, len(large_data))

    # Verify that reads were limited to READ_SIZE
    assert len(read_sizes) > 1  # Should have multiple reads
    for read_size in read_sizes:
        assert (
            read_size <= READ_SIZE
        ), f"Read size {read_size} exceeds READ_SIZE {READ_SIZE}"


async def test_iobase_payload_large_content_length() -> None:
    """Test IOBasePayload with very large content_length doesn't read all at once."""
    data = b"x" * (READ_SIZE + 1000)

    # Create a custom file-like object that tracks read sizes
    class TrackingBytesIO(io.BytesIO):
        def __init__(self, data: bytes) -> None:
            super().__init__(data)
            self.read_sizes: List[int] = []

        def read(self, size: Optional[int] = -1) -> bytes:
            self.read_sizes.append(size if size is not None else -1)
            return super().read(size)

    tracking_file = TrackingBytesIO(data)
    payload_obj = payload.IOBasePayload(tracking_file)
    writer = MockStreamWriter()

    # Write with a very large content_length (simulating the bug scenario)
    large_content_length = 10 * 1024 * 1024  # 10MB
    await payload_obj.write_with_length(writer, large_content_length)

    # Verify no single read exceeded READ_SIZE
    for read_size in tracking_file.read_sizes:
        assert (
            read_size <= READ_SIZE
        ), f"Read size {read_size} exceeds READ_SIZE {READ_SIZE}"

    # Verify the correct amount of data was written
    assert writer.get_written_bytes() == data


async def test_textio_payload_reads_in_chunks() -> None:
    """Test TextIOPayload reads data in chunks of READ_SIZE, not all at once."""
    # Create a large text file that's multiple times larger than READ_SIZE
    large_text = "x" * (READ_SIZE * 3 + 1000)  # ~192KB + 1000 chars

    # Mock the file-like object to track read calls
    mock_file = unittest.mock.Mock(spec=io.StringIO)
    mock_file.tell.return_value = 0
    mock_file.fileno.side_effect = AttributeError  # Make size return None
    mock_file.encoding = "utf-8"

    # Track the sizes of read() calls
    read_sizes = []

    def mock_read(size: int) -> str:
        read_sizes.append(size)
        # Return data based on how many times read was called
        call_count = len(read_sizes)
        if call_count == 1:
            return large_text[:size]
        elif call_count == 2:
            return large_text[READ_SIZE : READ_SIZE + size]
        elif call_count == 3:
            return large_text[READ_SIZE * 2 : READ_SIZE * 2 + size]
        else:
            return large_text[READ_SIZE * 3 :]

    mock_file.read.side_effect = mock_read

    payload_obj = payload.TextIOPayload(mock_file)
    writer = MockStreamWriter()

    # Write with a large content_length
    await payload_obj.write_with_length(writer, len(large_text.encode("utf-8")))

    # Verify that reads were limited to READ_SIZE
    assert len(read_sizes) > 1  # Should have multiple reads
    for read_size in read_sizes:
        assert (
            read_size <= READ_SIZE
        ), f"Read size {read_size} exceeds READ_SIZE {READ_SIZE}"


async def test_textio_payload_large_content_length() -> None:
    """Test TextIOPayload with very large content_length doesn't read all at once."""
    text_data = "x" * (READ_SIZE + 1000)

    # Create a custom file-like object that tracks read sizes
    class TrackingStringIO(io.StringIO):
        def __init__(self, data: str) -> None:
            super().__init__(data)
            self.read_sizes: List[int] = []

        def read(self, size: Optional[int] = -1) -> str:
            self.read_sizes.append(size if size is not None else -1)
            return super().read(size)

    tracking_file = TrackingStringIO(text_data)
    payload_obj = payload.TextIOPayload(tracking_file)
    writer = MockStreamWriter()

    # Write with a very large content_length (simulating the bug scenario)
    large_content_length = 10 * 1024 * 1024  # 10MB
    await payload_obj.write_with_length(writer, large_content_length)

    # Verify no single read exceeded READ_SIZE
    for read_size in tracking_file.read_sizes:
        assert (
            read_size <= READ_SIZE
        ), f"Read size {read_size} exceeds READ_SIZE {READ_SIZE}"

    # Verify the correct amount of data was written
    assert writer.get_written_bytes() == text_data.encode("utf-8")


async def test_async_iterable_payload_write_with_length_no_limit() -> None:
    """Test AsyncIterablePayload writing with no content length limit."""

    async def gen() -> AsyncIterator[bytes]:
        yield b"0123"
        yield b"4567"
        yield b"89"

    p = payload.AsyncIterablePayload(gen())
    writer = MockStreamWriter()

    await p.write_with_length(writer, None)
    assert writer.get_written_bytes() == b"0123456789"
    assert len(writer.get_written_bytes()) == 10


async def test_async_iterable_payload_write_with_length_exact() -> None:
    """Test AsyncIterablePayload writing with exact content length."""

    async def gen() -> AsyncIterator[bytes]:
        yield b"0123"
        yield b"4567"
        yield b"89"

    p = payload.AsyncIterablePayload(gen())
    writer = MockStreamWriter()

    await p.write_with_length(writer, 10)
    assert writer.get_written_bytes() == b"0123456789"
    assert len(writer.get_written_bytes()) == 10


async def test_async_iterable_payload_write_with_length_truncated_mid_chunk() -> None:
    """Test AsyncIterablePayload writing with content length truncating mid-chunk."""

    async def gen() -> AsyncIterator[bytes]:
        yield b"0123"
        yield b"4567"
        yield b"89"  # pragma: no cover

    p = payload.AsyncIterablePayload(gen())
    writer = MockStreamWriter()

    await p.write_with_length(writer, 6)
    assert writer.get_written_bytes() == b"012345"
    assert len(writer.get_written_bytes()) == 6


async def test_async_iterable_payload_write_with_length_truncated_at_chunk() -> None:
    """Test AsyncIterablePayload writing with content length truncating at chunk boundary."""

    async def gen() -> AsyncIterator[bytes]:
        yield b"0123"
        yield b"4567"  # pragma: no cover
        yield b"89"  # pragma: no cover

    p = payload.AsyncIterablePayload(gen())
    writer = MockStreamWriter()

    await p.write_with_length(writer, 4)
    assert writer.get_written_bytes() == b"0123"
    assert len(writer.get_written_bytes()) == 4


async def test_bytes_payload_backwards_compatibility() -> None:
    """Test BytesPayload.write() backwards compatibility delegates to write_with_length()."""
    p = payload.BytesPayload(b"1234567890")
    writer = MockStreamWriter()

    await p.write(writer)
    assert writer.get_written_bytes() == b"1234567890"


async def test_textio_payload_with_encoding() -> None:
    """Test TextIOPayload reading with encoding and size constraints."""
    data = io.StringIO("hello world")
    p = payload.TextIOPayload(data, encoding="utf-8")
    writer = MockStreamWriter()

    await p.write_with_length(writer, 8)
    # Should write exactly 8 bytes: "hello wo"
    assert writer.get_written_bytes() == b"hello wo"


async def test_textio_payload_as_bytes() -> None:
    """Test TextIOPayload.as_bytes method with different encodings."""
    # Test with UTF-8 encoding
    data = io.StringIO("Hello 世界")
    p = payload.TextIOPayload(data, encoding="utf-8")

    # Test as_bytes() method
    result = await p.as_bytes()
    assert result == "Hello 世界".encode()

    # Test that position is restored for multiple reads
    result2 = await p.as_bytes()
    assert result2 == "Hello 世界".encode()

    # Test with different encoding parameter (should use instance encoding)
    result3 = await p.as_bytes(encoding="latin-1")
    assert result3 == "Hello 世界".encode()  # Should still use utf-8

    # Test with different encoding in payload
    data2 = io.StringIO("Hello World")
    p2 = payload.TextIOPayload(data2, encoding="latin-1")
    result4 = await p2.as_bytes()
    assert result4 == b"Hello World"  # latin-1 encoding

    # Test with no explicit encoding (defaults to utf-8)
    data3 = io.StringIO("Test データ")
    p3 = payload.TextIOPayload(data3)
    result5 = await p3.as_bytes()
    assert result5 == "Test データ".encode()

    # Test with encoding errors parameter
    data4 = io.StringIO("Test")
    p4 = payload.TextIOPayload(data4, encoding="ascii")
    result6 = await p4.as_bytes(errors="strict")
    assert result6 == b"Test"


async def test_bytesio_payload_backwards_compatibility() -> None:
    """Test BytesIOPayload.write() backwards compatibility delegates to write_with_length()."""
    data = io.BytesIO(b"test data")
    p = payload.BytesIOPayload(data)
    writer = MockStreamWriter()

    await p.write(writer)
    assert writer.get_written_bytes() == b"test data"


async def test_async_iterable_payload_backwards_compatibility() -> None:
    """Test AsyncIterablePayload.write() backwards compatibility delegates to write_with_length()."""

    async def gen() -> AsyncIterator[bytes]:
        yield b"chunk1"
        yield b"chunk2"  # pragma: no cover

    p = payload.AsyncIterablePayload(gen())
    writer = MockStreamWriter()

    await p.write(writer)
    assert writer.get_written_bytes() == b"chunk1chunk2"


async def test_async_iterable_payload_with_none_iterator() -> None:
    """Test AsyncIterablePayload with None iterator returns early without writing."""

    async def gen() -> AsyncIterator[bytes]:
        yield b"test"  # pragma: no cover

    p = payload.AsyncIterablePayload(gen())
    # Manually set _iter to None to test the guard clause
    p._iter = None
    writer = MockStreamWriter()

    # Should return early without writing anything
    await p.write_with_length(writer, 10)
    assert writer.get_written_bytes() == b""


async def test_async_iterable_payload_caching() -> None:
    """Test AsyncIterablePayload caching behavior."""

    async def gen() -> AsyncIterator[bytes]:
        yield b"Hello"
        yield b" "
        yield b"World"

    p = payload.AsyncIterablePayload(gen())

    # First call to as_bytes should consume iterator and cache
    result1 = await p.as_bytes()
    assert result1 == b"Hello World"
    assert p._iter is None  # Iterator exhausted
    assert p._cached_chunks == [b"Hello", b" ", b"World"]  # Chunks cached
    assert p._consumed is False  # Not marked as consumed to allow reuse

    # Second call should use cache
    result2 = await p.as_bytes()
    assert result2 == b"Hello World"
    assert p._cached_chunks == [b"Hello", b" ", b"World"]  # Still cached

    # decode should work with cached chunks
    decoded = p.decode()
    assert decoded == "Hello World"

    # write_with_length should use cached chunks
    writer = MockStreamWriter()
    await p.write_with_length(writer, None)
    assert writer.get_written_bytes() == b"Hello World"

    # write_with_length with limit should respect it
    writer2 = MockStreamWriter()
    await p.write_with_length(writer2, 5)
    assert writer2.get_written_bytes() == b"Hello"


async def test_async_iterable_payload_decode_without_cache() -> None:
    """Test AsyncIterablePayload decode raises error without cache."""

    async def gen() -> AsyncIterator[bytes]:
        yield b"test"

    p = payload.AsyncIterablePayload(gen())

    # decode should raise without cache
    with pytest.raises(TypeError) as excinfo:
        p.decode()
    assert "Unable to decode - content not cached" in str(excinfo.value)

    # After as_bytes, decode should work
    await p.as_bytes()
    assert p.decode() == "test"


async def test_async_iterable_payload_write_then_cache() -> None:
    """Test AsyncIterablePayload behavior when written before caching."""

    async def gen() -> AsyncIterator[bytes]:
        yield b"Hello"
        yield b"World"

    p = payload.AsyncIterablePayload(gen())

    # First write without caching (streaming)
    writer1 = MockStreamWriter()
    await p.write_with_length(writer1, None)
    assert writer1.get_written_bytes() == b"HelloWorld"
    assert p._iter is None  # Iterator exhausted
    assert p._cached_chunks is None  # No cache created
    assert p._consumed is True  # Marked as consumed

    # Subsequent operations should handle exhausted iterator
    result = await p.as_bytes()
    assert result == b""  # Empty since iterator exhausted without cache

    # Write should also be empty
    writer2 = MockStreamWriter()
    await p.write_with_length(writer2, None)
    assert writer2.get_written_bytes() == b""


async def test_bytes_payload_reusability() -> None:
    """Test that BytesPayload can be written and read multiple times."""
    data = b"test payload data"
    p = payload.BytesPayload(data)

    # First write_with_length
    writer1 = MockStreamWriter()
    await p.write_with_length(writer1, None)
    assert writer1.get_written_bytes() == data

    # Second write_with_length (simulating redirect)
    writer2 = MockStreamWriter()
    await p.write_with_length(writer2, None)
    assert writer2.get_written_bytes() == data

    # Write with partial length
    writer3 = MockStreamWriter()
    await p.write_with_length(writer3, 5)
    assert writer3.get_written_bytes() == b"test "

    # Test as_bytes multiple times
    bytes1 = await p.as_bytes()
    bytes2 = await p.as_bytes()
    bytes3 = await p.as_bytes()
    assert bytes1 == bytes2 == bytes3 == data


async def test_string_payload_reusability() -> None:
    """Test that StringPayload can be written and read multiple times."""
    text = "test string data"
    expected_bytes = text.encode("utf-8")
    p = payload.StringPayload(text)

    # First write_with_length
    writer1 = MockStreamWriter()
    await p.write_with_length(writer1, None)
    assert writer1.get_written_bytes() == expected_bytes

    # Second write_with_length (simulating redirect)
    writer2 = MockStreamWriter()
    await p.write_with_length(writer2, None)
    assert writer2.get_written_bytes() == expected_bytes

    # Write with partial length
    writer3 = MockStreamWriter()
    await p.write_with_length(writer3, 5)
    assert writer3.get_written_bytes() == b"test "

    # Test as_bytes multiple times
    bytes1 = await p.as_bytes()
    bytes2 = await p.as_bytes()
    bytes3 = await p.as_bytes()
    assert bytes1 == bytes2 == bytes3 == expected_bytes


async def test_bytes_io_payload_reusability() -> None:
    """Test that BytesIOPayload can be written and read multiple times."""
    data = b"test bytesio payload"
    bytes_io = io.BytesIO(data)
    p = payload.BytesIOPayload(bytes_io)

    # First write_with_length
    writer1 = MockStreamWriter()
    await p.write_with_length(writer1, None)
    assert writer1.get_written_bytes() == data

    # Second write_with_length (simulating redirect)
    writer2 = MockStreamWriter()
    await p.write_with_length(writer2, None)
    assert writer2.get_written_bytes() == data

    # Write with partial length
    writer3 = MockStreamWriter()
    await p.write_with_length(writer3, 5)
    assert writer3.get_written_bytes() == b"test "

    # Test as_bytes multiple times
    bytes1 = await p.as_bytes()
    bytes2 = await p.as_bytes()
    bytes3 = await p.as_bytes()
    assert bytes1 == bytes2 == bytes3 == data


async def test_string_io_payload_reusability() -> None:
    """Test that StringIOPayload can be written and read multiple times."""
    text = "test stringio payload"
    expected_bytes = text.encode("utf-8")
    string_io = io.StringIO(text)
    p = payload.StringIOPayload(string_io)

    # Note: StringIOPayload reads all content in __init__ and becomes a StringPayload
    # So it should be fully reusable

    # First write_with_length
    writer1 = MockStreamWriter()
    await p.write_with_length(writer1, None)
    assert writer1.get_written_bytes() == expected_bytes

    # Second write_with_length (simulating redirect)
    writer2 = MockStreamWriter()
    await p.write_with_length(writer2, None)
    assert writer2.get_written_bytes() == expected_bytes

    # Write with partial length
    writer3 = MockStreamWriter()
    await p.write_with_length(writer3, 5)
    assert writer3.get_written_bytes() == b"test "

    # Test as_bytes multiple times
    bytes1 = await p.as_bytes()
    bytes2 = await p.as_bytes()
    bytes3 = await p.as_bytes()
    assert bytes1 == bytes2 == bytes3 == expected_bytes


async def test_buffered_reader_payload_reusability() -> None:
    """Test that BufferedReaderPayload can be written and read multiple times."""
    data = b"test buffered reader payload"
    buffer = io.BufferedReader(io.BytesIO(data))
    p = payload.BufferedReaderPayload(buffer)

    # First write_with_length
    writer1 = MockStreamWriter()
    await p.write_with_length(writer1, None)
    assert writer1.get_written_bytes() == data

    # Second write_with_length (simulating redirect)
    writer2 = MockStreamWriter()
    await p.write_with_length(writer2, None)
    assert writer2.get_written_bytes() == data

    # Write with partial length
    writer3 = MockStreamWriter()
    await p.write_with_length(writer3, 5)
    assert writer3.get_written_bytes() == b"test "

    # Test as_bytes multiple times
    bytes1 = await p.as_bytes()
    bytes2 = await p.as_bytes()
    bytes3 = await p.as_bytes()
    assert bytes1 == bytes2 == bytes3 == data


async def test_async_iterable_payload_reusability_with_cache() -> None:
    """Test that AsyncIterablePayload can be reused when cached via as_bytes."""

    async def gen() -> AsyncIterator[bytes]:
        yield b"async "
        yield b"iterable "
        yield b"payload"

    expected_data = b"async iterable payload"
    p = payload.AsyncIterablePayload(gen())

    # First call to as_bytes should cache the data
    bytes1 = await p.as_bytes()
    assert bytes1 == expected_data
    assert p._cached_chunks is not None
    assert p._iter is None  # Iterator exhausted

    # Subsequent as_bytes calls should use cache
    bytes2 = await p.as_bytes()
    bytes3 = await p.as_bytes()
    assert bytes1 == bytes2 == bytes3 == expected_data

    # Now writes should also use the cached data
    writer1 = MockStreamWriter()
    await p.write_with_length(writer1, None)
    assert writer1.get_written_bytes() == expected_data

    # Second write should also work
    writer2 = MockStreamWriter()
    await p.write_with_length(writer2, None)
    assert writer2.get_written_bytes() == expected_data

    # Write with partial length
    writer3 = MockStreamWriter()
    await p.write_with_length(writer3, 5)
    assert writer3.get_written_bytes() == b"async"


async def test_async_iterable_payload_no_reuse_without_cache() -> None:
    """Test that AsyncIterablePayload cannot be reused without caching."""

    async def gen() -> AsyncIterator[bytes]:
        yield b"test "
        yield b"data"

    p = payload.AsyncIterablePayload(gen())

    # First write exhausts the iterator
    writer1 = MockStreamWriter()
    await p.write_with_length(writer1, None)
    assert writer1.get_written_bytes() == b"test data"
    assert p._iter is None  # Iterator exhausted
    assert p._consumed is True

    # Second write should produce empty result
    writer2 = MockStreamWriter()
    await p.write_with_length(writer2, None)
    assert writer2.get_written_bytes() == b""


async def test_bytes_io_payload_close_does_not_close_io() -> None:
    """Test that BytesIOPayload close() does not close the underlying BytesIO."""
    bytes_io = io.BytesIO(b"data")
    bytes_io_payload = payload.BytesIOPayload(bytes_io)

    # Close the payload
    await bytes_io_payload.close()

    # BytesIO should NOT be closed
    assert not bytes_io.closed

    # Can still write after close
    writer = MockStreamWriter()
    await bytes_io_payload.write_with_length(writer, None)
    assert writer.get_written_bytes() == b"data"


async def test_custom_payload_backwards_compat_as_bytes() -> None:
    """Test backwards compatibility for custom Payload that only implements decode()."""

    class LegacyPayload(payload.Payload):
        """A custom payload that only implements decode() like old code might do."""

        def __init__(self, data: str) -> None:
            super().__init__(data, headers=CIMultiDict())
            self._data = data

        def decode(self, encoding: str = "utf-8", errors: str = "strict") -> str:
            """Custom decode implementation."""
            return self._data

        async def write(self, writer: AbstractStreamWriter) -> None:
            """Write implementation which is a no-op for this test."""

    # Create instance with test data
    p = LegacyPayload("Hello, World!")

    # Test that as_bytes() works even though it's not explicitly implemented
    # The base class should call decode() and encode the result
    result = await p.as_bytes()
    assert result == b"Hello, World!"

    # Test with different text
    p2 = LegacyPayload("Test with special chars: café")
    result_utf8 = await p2.as_bytes(encoding="utf-8")
    assert result_utf8 == "Test with special chars: café".encode()

    # Test that decode() still works as expected
    assert p.decode() == "Hello, World!"
    assert p2.decode() == "Test with special chars: café"


async def test_custom_payload_with_encoding_backwards_compat() -> None:
    """Test custom Payload with encoding set uses instance encoding for as_bytes()."""

    class EncodedPayload(payload.Payload):
        """A custom payload with specific encoding."""

        def __init__(self, data: str, encoding: str) -> None:
            super().__init__(data, headers=CIMultiDict(), encoding=encoding)
            self._data = data

        def decode(self, encoding: str = "utf-8", errors: str = "strict") -> str:
            """Custom decode implementation."""
            return self._data

        async def write(self, writer: AbstractStreamWriter) -> None:
            """Write implementation is a no-op."""

    # Create instance with specific encoding
    p = EncodedPayload("Test data", encoding="latin-1")

    # as_bytes() should use the instance encoding (latin-1) not the default utf-8
    result = await p.as_bytes()
    assert result == b"Test data"  # ASCII chars are same in latin-1

    # Test with non-ASCII that differs between encodings
    p2 = EncodedPayload("café", encoding="latin-1")
    result_latin1 = await p2.as_bytes()
    assert result_latin1 == "café".encode("latin-1")
    assert result_latin1 != "café".encode()  # Should be different bytes


async def test_iobase_payload_close_idempotent() -> None:
    """Test that IOBasePayload.close() is idempotent and covers the _consumed check."""
    file_like = io.BytesIO(b"test data")
    p = payload.IOBasePayload(file_like)

    # First close should set _consumed to True
    await p.close()
    assert p._consumed is True

    # Second close should be a no-op due to _consumed check (line 621)
    await p.close()
    assert p._consumed is True


def test_iobase_payload_decode() -> None:
    """Test IOBasePayload.decode() returns correct string."""
    # Test with UTF-8 encoded text
    text = "Hello, 世界! 🌍"
    file_like = io.BytesIO(text.encode("utf-8"))
    p = payload.IOBasePayload(file_like)

    # decode() should return the original string
    assert p.decode() == text

    # Test with different encoding
    latin1_text = "café"
    file_like2 = io.BytesIO(latin1_text.encode("latin-1"))
    p2 = payload.IOBasePayload(file_like2)
    assert p2.decode("latin-1") == latin1_text

    # Test that file position is restored
    file_like3 = io.BytesIO(b"test data")
    file_like3.read(4)  # Move position forward
    p3 = payload.IOBasePayload(file_like3)
    # decode() should read from the stored start position (4)
    assert p3.decode() == " data"


def test_bytes_payload_size() -> None:
    """Test BytesPayload.size property returns correct byte length."""
    # Test with bytes
    bp = payload.BytesPayload(b"Hello World")
    assert bp.size == 11

    # Test with empty bytes
    bp_empty = payload.BytesPayload(b"")
    assert bp_empty.size == 0

    # Test with bytearray
    ba = bytearray(b"Hello World")
    bp_array = payload.BytesPayload(ba)
    assert bp_array.size == 11


def test_string_payload_size() -> None:
    """Test StringPayload.size property with different encodings."""
    # Test ASCII string with default UTF-8 encoding
    sp = payload.StringPayload("Hello World")
    assert sp.size == 11

    # Test Unicode string with default UTF-8 encoding
    unicode_str = "Hello 世界"
    sp_unicode = payload.StringPayload(unicode_str)
    assert sp_unicode.size == len(unicode_str.encode("utf-8"))

    # Test with UTF-16 encoding
    sp_utf16 = payload.StringPayload("Hello World", encoding="utf-16")
    assert sp_utf16.size == len("Hello World".encode("utf-16"))

    # Test with latin-1 encoding
    sp_latin1 = payload.StringPayload("café", encoding="latin-1")
    assert sp_latin1.size == len("café".encode("latin-1"))


def test_string_io_payload_size() -> None:
    """Test StringIOPayload.size property."""
    # Test normal string
    sio = StringIO("Hello World")
    siop = payload.StringIOPayload(sio)
    assert siop.size == 11

    # Test Unicode string
    sio_unicode = StringIO("Hello 世界")
    siop_unicode = payload.StringIOPayload(sio_unicode)
    assert siop_unicode.size == len("Hello 世界".encode())

    # Test with custom encoding
    sio_custom = StringIO("Hello")
    siop_custom = payload.StringIOPayload(sio_custom, encoding="utf-16")
    assert siop_custom.size == len("Hello".encode("utf-16"))

    # Test with emoji to ensure correct byte count
    sio_emoji = StringIO("Hello 👋🌍")
    siop_emoji = payload.StringIOPayload(sio_emoji)
    assert siop_emoji.size == len("Hello 👋🌍".encode())
    # Verify it's not the string length
    assert siop_emoji.size != len("Hello 👋🌍")


def test_all_string_payloads_size_is_bytes() -> None:
    """Test that all string-like payload classes report size in bytes, not string length."""
    # Test string with multibyte characters
    test_str = "Hello 👋 世界 🌍"  # Contains emoji and Chinese characters

    # StringPayload
    sp = payload.StringPayload(test_str)
    assert sp.size == len(test_str.encode("utf-8"))
    assert sp.size != len(test_str)  # Ensure it's not string length

    # StringIOPayload
    sio = StringIO(test_str)
    siop = payload.StringIOPayload(sio)
    assert siop.size == len(test_str.encode("utf-8"))
    assert siop.size != len(test_str)

    # Test with different encoding
    sp_utf16 = payload.StringPayload(test_str, encoding="utf-16")
    assert sp_utf16.size == len(test_str.encode("utf-16"))
    assert sp_utf16.size != sp.size  # Different encoding = different size

    # JsonPayload (which extends BytesPayload)
    json_data = {"message": test_str}
    jp = payload.JsonPayload(json_data)
    # JSON escapes Unicode, so we need to check the actual encoded size
    json_str = json.dumps(json_data)
    assert jp.size == len(json_str.encode("utf-8"))

    # Test JsonPayload with ensure_ascii=False to get actual UTF-8 encoding
    jp_utf8 = payload.JsonPayload(
        json_data, dumps=lambda x: json.dumps(x, ensure_ascii=False)
    )
    json_str_utf8 = json.dumps(json_data, ensure_ascii=False)
    assert jp_utf8.size == len(json_str_utf8.encode("utf-8"))
    assert jp_utf8.size != len(
        json_str_utf8
    )  # Now it's different due to multibyte chars


def test_bytes_io_payload_size() -> None:
    """Test BytesIOPayload.size property."""
    # Test normal bytes
    bio = io.BytesIO(b"Hello World")
    biop = payload.BytesIOPayload(bio)
    assert biop.size == 11

    # Test empty BytesIO
    bio_empty = io.BytesIO(b"")
    biop_empty = payload.BytesIOPayload(bio_empty)
    assert biop_empty.size == 0

    # Test with position not at start
    bio_pos = io.BytesIO(b"Hello World")
    bio_pos.seek(5)
    biop_pos = payload.BytesIOPayload(bio_pos)
    assert biop_pos.size == 6  # Size should be from position to end


def test_json_payload_size() -> None:
    """Test JsonPayload.size property."""
    # Test simple dict
    data = {"hello": "world"}
    jp = payload.JsonPayload(data)
    expected_json = json.dumps(data)  # Use actual json.dumps output
    assert jp.size == len(expected_json.encode("utf-8"))

    # Test with Unicode
    data_unicode = {"message": "Hello 世界"}
    jp_unicode = payload.JsonPayload(data_unicode)
    expected_unicode = json.dumps(data_unicode)
    assert jp_unicode.size == len(expected_unicode.encode("utf-8"))

    # Test with custom encoding
    data_custom = {"test": "data"}
    jp_custom = payload.JsonPayload(data_custom, encoding="utf-16")
    expected_custom = json.dumps(data_custom)
    assert jp_custom.size == len(expected_custom.encode("utf-16"))


async def test_text_io_payload_size_matches_file_encoding(tmp_path: Path) -> None:
    """Test TextIOPayload.size when file encoding matches payload encoding."""
    # Create UTF-8 file
    utf8_file = tmp_path / "test_utf8.txt"
    content = "Hello 世界"

    # Write file in executor
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, utf8_file.write_text, content, "utf-8")

    # Open file in executor
    def open_file() -> TextIO:
        return open(utf8_file, encoding="utf-8")

    f = await loop.run_in_executor(None, open_file)
    try:
        tiop = payload.TextIOPayload(f)
        # Size should match the actual UTF-8 encoded size
        assert tiop.size == len(content.encode("utf-8"))
    finally:
        await loop.run_in_executor(None, f.close)


async def test_text_io_payload_size_utf16(tmp_path: Path) -> None:
    """Test TextIOPayload.size reports correct size with utf-16."""
    # Create UTF-16 file
    utf16_file = tmp_path / "test_utf16.txt"
    content = "Hello World"

    loop = asyncio.get_running_loop()
    # Write file in executor
    await loop.run_in_executor(None, utf16_file.write_text, content, "utf-16")

    # Get file size in executor
    utf16_file_size = await loop.run_in_executor(
        None, lambda: utf16_file.stat().st_size
    )

    # Open file in executor
    def open_file() -> TextIO:
        return open(utf16_file, encoding="utf-16")

    f = await loop.run_in_executor(None, open_file)
    try:
        tiop = payload.TextIOPayload(f, encoding="utf-16")
        # Payload reports file size on disk (UTF-16)
        assert tiop.size == utf16_file_size

        # Write to a buffer to see what actually gets sent
        writer = BufferWriter()
        await tiop.write(writer)

        # Check that the actual written bytes match file size
        assert len(writer.buffer) == utf16_file_size
    finally:
        await loop.run_in_executor(None, f.close)


async def test_iobase_payload_size_after_reading(tmp_path: Path) -> None:
    """Test that IOBasePayload.size returns correct size after file has been read.

    This verifies that size calculation properly accounts for the initial
    file position, which is critical for 307/308 redirects where the same
    payload instance is reused.
    """
    # Create a test file with known content
    test_file = tmp_path / "test.txt"
    content = b"Hello, World! This is test content."
    await asyncio.to_thread(test_file.write_bytes, content)
    expected_size = len(content)

    # Open the file and create payload
    f = await asyncio.to_thread(open, test_file, "rb")
    try:
        p = payload.BufferedReaderPayload(f)

        # First size check - should return full file size
        assert p.size == expected_size

        # Read the file (simulating first request)
        writer = BufferWriter()
        await p.write(writer)
        assert len(writer.buffer) == expected_size

        # Second size check - should still return full file size
        assert p.size == expected_size

        # Attempting to write again should write the full content
        writer2 = BufferWriter()
        await p.write(writer2)
        assert len(writer2.buffer) == expected_size
    finally:
        await asyncio.to_thread(f.close)


async def test_iobase_payload_size_unseekable() -> None:
    """Test that IOBasePayload.size returns None for unseekable files."""

    class UnseekableFile:
        """Mock file object that doesn't support seeking."""

        def __init__(self, content: bytes) -> None:
            self.content = content
            self.pos = 0

        def read(self, size: int) -> bytes:
            result = self.content[self.pos : self.pos + size]
            self.pos += len(result)
            return result

        def tell(self) -> int:
            raise OSError("Unseekable file")

    content = b"Unseekable content"
    f = UnseekableFile(content)
    p = payload.IOBasePayload(f)  # type: ignore[arg-type]

    # Size should return None for unseekable files
    assert p.size is None

    # Payload should not be consumed before writing
    assert p.consumed is False

    # Writing should still work
    writer = BufferWriter()
    await p.write(writer)
    assert writer.buffer == content

    # For unseekable files that can't tell() or seek(),
    # they are marked as consumed after the first write
    assert p.consumed is True
