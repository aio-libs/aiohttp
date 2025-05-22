import array
import io
import unittest.mock
from collections.abc import AsyncIterator
from io import StringIO
from typing import Optional, Union

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
def registry():
    old = payload.PAYLOAD_REGISTRY
    reg = payload.PAYLOAD_REGISTRY = payload.PayloadRegistry()
    yield reg
    payload.PAYLOAD_REGISTRY = old


class Payload(payload.Payload):
    def decode(self, encoding: str = "utf-8", errors: str = "strict") -> str:
        assert False

    async def write(self, writer):
        pass


def test_register_type(registry) -> None:
    class TestProvider:
        pass

    payload.register_payload(Payload, TestProvider)
    p = payload.get_payload(TestProvider())
    assert isinstance(p, Payload)


def test_register_unsupported_order(registry) -> None:
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
    async def gen():
        return
        yield

    p = payload.AsyncIterablePayload(gen())
    assert p.content_type == "application/octet-stream"


def test_async_iterable_payload_explicit_content_type() -> None:
    async def gen():
        return
        yield

    p = payload.AsyncIterablePayload(gen(), content_type="application/custom")
    assert p.content_type == "application/custom"


def test_async_iterable_payload_not_async_iterable() -> None:

    with pytest.raises(TypeError):
        payload.AsyncIterablePayload(object())  # type: ignore[arg-type]


class MockStreamWriter(AbstractStreamWriter):
    """Mock stream writer for testing payload writes."""

    def __init__(self) -> None:
        self.written: list[bytes] = []

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
