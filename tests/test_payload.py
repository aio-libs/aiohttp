import array
import io
import unittest.mock
from io import StringIO
from typing import AsyncIterator, Iterator, List, Optional, Union

import pytest
from multidict import CIMultiDict

from aiohttp import payload
from aiohttp.abc import AbstractStreamWriter


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
    buffer = io.BufferedReader(io.BytesIO(data))  # type: ignore[arg-type]
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
            """Write implementation."""
            await writer.write(self._data.encode())

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
            """Write implementation."""
            # Use instance encoding if set
            enc = self._encoding or "utf-8"
            await writer.write(self._data.encode(enc))

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
