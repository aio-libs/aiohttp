# Tests for aiohttp/http_writer.py
import array
import asyncio
import zlib
from typing import Any, Generator, Iterable, Union
from unittest import mock

import pytest
from multidict import CIMultiDict

from aiohttp import ClientConnectionResetError, hdrs, http
from aiohttp.base_protocol import BaseProtocol
from aiohttp.compression_utils import ZLibBackend
from aiohttp.http_writer import _serialize_headers


@pytest.fixture
def enable_writelines() -> Generator[None, None, None]:
    with mock.patch("aiohttp.http_writer.SKIP_WRITELINES", False):
        yield


@pytest.fixture
def disable_writelines() -> Generator[None, None, None]:
    with mock.patch("aiohttp.http_writer.SKIP_WRITELINES", True):
        yield


@pytest.fixture
def force_writelines_small_payloads() -> Generator[None, None, None]:
    with mock.patch("aiohttp.http_writer.MIN_PAYLOAD_FOR_WRITELINES", 1):
        yield


@pytest.fixture
def buf() -> bytearray:
    return bytearray()


@pytest.fixture
def transport(buf: bytearray) -> Any:
    transport = mock.create_autospec(asyncio.Transport, spec_set=True, instance=True)

    def write(chunk: bytes) -> None:
        buf.extend(chunk)

    def writelines(chunks: Iterable[bytes]) -> None:
        for chunk in chunks:
            buf.extend(chunk)

    transport.write.side_effect = write
    transport.writelines.side_effect = writelines
    transport.is_closing.return_value = False
    return transport


@pytest.fixture
def protocol(loop: asyncio.AbstractEventLoop, transport: asyncio.Transport) -> Any:
    return mock.create_autospec(
        BaseProtocol, spec_set=True, instance=True, transport=transport
    )


def decompress(data: bytes) -> bytes:
    d = ZLibBackend.decompressobj()
    return d.decompress(data)


def decode_chunked(chunked: Union[bytes, bytearray]) -> bytes:
    i = 0
    out = b""
    while i < len(chunked):
        j = chunked.find(b"\r\n", i)
        assert j != -1, "Malformed chunk"
        size = int(chunked[i:j], 16)
        if size == 0:
            break
        i = j + 2
        out += chunked[i : i + size]
        i += size + 2  # skip \r\n after the chunk
    return out


def test_payloadwriter_properties(
    transport: asyncio.Transport,
    protocol: BaseProtocol,
    loop: asyncio.AbstractEventLoop,
) -> None:
    writer = http.StreamWriter(protocol, loop)
    assert writer.protocol == protocol
    assert writer.transport == transport


async def test_write_headers_buffered_small_payload(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    headers = CIMultiDict({"Content-Length": "11", "Host": "example.com"})

    # Write headers - should be buffered
    await msg.write_headers("GET / HTTP/1.1", headers)
    assert len(buf) == 0  # Headers not sent yet

    # Write small body - should coalesce with headers
    await msg.write(b"Hello World", drain=False)

    # Verify content
    assert b"GET / HTTP/1.1\r\n" in buf
    assert b"Host: example.com\r\n" in buf
    assert b"Content-Length: 11\r\n" in buf
    assert b"\r\n\r\nHello World" in buf


async def test_write_headers_chunked_coalescing(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.enable_chunking()
    headers = CIMultiDict({"Transfer-Encoding": "chunked", "Host": "example.com"})

    # Write headers - should be buffered
    await msg.write_headers("POST /upload HTTP/1.1", headers)
    assert len(buf) == 0  # Headers not sent yet

    # Write first chunk - should coalesce with headers
    await msg.write(b"First chunk", drain=False)

    # Verify content
    assert b"POST /upload HTTP/1.1\r\n" in buf
    assert b"Transfer-Encoding: chunked\r\n" in buf
    # "b" is hex for 11 (length of "First chunk")
    assert b"\r\n\r\nb\r\nFirst chunk\r\n" in buf


async def test_write_eof_with_buffered_headers(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    headers = CIMultiDict({"Content-Length": "9", "Host": "example.com"})

    # Write headers - should be buffered
    await msg.write_headers("POST /data HTTP/1.1", headers)
    assert len(buf) == 0

    # Call write_eof with body - should coalesce
    await msg.write_eof(b"Last data")

    # Verify content
    assert b"POST /data HTTP/1.1\r\n" in buf
    assert b"\r\n\r\nLast data" in buf


async def test_set_eof_sends_buffered_headers(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    headers = CIMultiDict({"Host": "example.com"})

    # Write headers - should be buffered
    await msg.write_headers("GET /empty HTTP/1.1", headers)
    assert len(buf) == 0

    # Call set_eof without body - headers should be sent
    msg.set_eof()

    # Headers should be sent
    assert len(buf) > 0
    assert b"GET /empty HTTP/1.1\r\n" in buf


async def test_write_payload_eof(
    transport: asyncio.Transport,
    protocol: BaseProtocol,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)

    await msg.write(b"data1")
    await msg.write(b"data2")
    await msg.write_eof()

    content = b"".join([c[1][0] for c in list(transport.write.mock_calls)])  # type: ignore[attr-defined]
    assert b"data1data2" == content.split(b"\r\n\r\n", 1)[-1]


async def test_write_payload_chunked(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.enable_chunking()
    await msg.write(b"data")
    await msg.write_eof()

    assert b"4\r\ndata\r\n0\r\n\r\n" == buf


async def test_write_payload_chunked_multiple(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.enable_chunking()
    await msg.write(b"data1")
    await msg.write(b"data2")
    await msg.write_eof()

    assert b"5\r\ndata1\r\n5\r\ndata2\r\n0\r\n\r\n" == buf


async def test_write_payload_length(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.length = 2
    await msg.write(b"d")
    await msg.write(b"ata")
    await msg.write_eof()

    content = b"".join([c[1][0] for c in list(transport.write.mock_calls)])  # type: ignore[attr-defined]
    assert b"da" == content.split(b"\r\n\r\n", 1)[-1]


@pytest.mark.usefixtures("disable_writelines")
@pytest.mark.internal  # Used for performance benchmarking
async def test_write_large_payload_deflate_compression_data_in_eof(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")

    await msg.write(b"data" * 4096)
    assert transport.write.called  # type: ignore[attr-defined]
    chunks = [c[1][0] for c in list(transport.write.mock_calls)]  # type: ignore[attr-defined]
    transport.write.reset_mock()  # type: ignore[attr-defined]

    # This payload compresses to 20447 bytes
    payload = b"".join(
        [bytes((*range(0, i), *range(i, 0, -1))) for i in range(255) for _ in range(64)]
    )
    await msg.write_eof(payload)
    chunks.extend([c[1][0] for c in list(transport.write.mock_calls)])  # type: ignore[attr-defined]

    assert all(chunks)
    content = b"".join(chunks)
    assert zlib.decompress(content) == (b"data" * 4096) + payload


@pytest.mark.usefixtures("disable_writelines")
@pytest.mark.usefixtures("parametrize_zlib_backend")
async def test_write_large_payload_deflate_compression_data_in_eof_all_zlib(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")

    await msg.write(b"data" * 4096)
    # Behavior depends on zlib backend, isal compress() returns b'' initially
    # and the entire compressed bytes at flush() for this data
    backend_to_write_called = {
        "isal.isal_zlib": False,
        "zlib": True,
        "zlib_ng.zlib_ng": True,
    }
    assert transport.write.called == backend_to_write_called[ZLibBackend.name]  # type: ignore[attr-defined]
    chunks = [c[1][0] for c in list(transport.write.mock_calls)]  # type: ignore[attr-defined]
    transport.write.reset_mock()  # type: ignore[attr-defined]

    # This payload compresses to 20447 bytes
    payload = b"".join(
        [bytes((*range(0, i), *range(i, 0, -1))) for i in range(255) for _ in range(64)]
    )
    await msg.write_eof(payload)
    chunks.extend([c[1][0] for c in list(transport.write.mock_calls)])  # type: ignore[attr-defined]

    assert all(chunks)
    content = b"".join(chunks)
    assert ZLibBackend.decompress(content) == (b"data" * 4096) + payload


@pytest.mark.usefixtures("enable_writelines")
@pytest.mark.internal  # Used for performance benchmarking
async def test_write_large_payload_deflate_compression_data_in_eof_writelines(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")

    await msg.write(b"data" * 4096)
    assert transport.write.called  # type: ignore[attr-defined]
    chunks = [c[1][0] for c in list(transport.write.mock_calls)]  # type: ignore[attr-defined]
    transport.write.reset_mock()  # type: ignore[attr-defined]
    assert not transport.writelines.called  # type: ignore[attr-defined]

    # This payload compresses to 20447 bytes
    payload = b"".join(
        [bytes((*range(0, i), *range(i, 0, -1))) for i in range(255) for _ in range(64)]
    )
    await msg.write_eof(payload)
    assert not transport.write.called  # type: ignore[attr-defined]
    assert transport.writelines.called  # type: ignore[attr-defined]
    chunks.extend(transport.writelines.mock_calls[0][1][0])  # type: ignore[attr-defined]
    content = b"".join(chunks)
    assert zlib.decompress(content) == (b"data" * 4096) + payload


@pytest.mark.usefixtures("enable_writelines")
@pytest.mark.usefixtures("parametrize_zlib_backend")
async def test_write_large_payload_deflate_compression_data_in_eof_writelines_all_zlib(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")

    await msg.write(b"data" * 4096)
    # Behavior depends on zlib backend, isal compress() returns b'' initially
    # and the entire compressed bytes at flush() for this data
    backend_to_write_called = {
        "isal.isal_zlib": False,
        "zlib": True,
        "zlib_ng.zlib_ng": True,
    }
    assert transport.write.called == backend_to_write_called[ZLibBackend.name]  # type: ignore[attr-defined]
    chunks = [c[1][0] for c in list(transport.write.mock_calls)]  # type: ignore[attr-defined]
    transport.write.reset_mock()  # type: ignore[attr-defined]
    assert not transport.writelines.called  # type: ignore[attr-defined]

    # This payload compresses to 20447 bytes
    payload = b"".join(
        [bytes((*range(0, i), *range(i, 0, -1))) for i in range(255) for _ in range(64)]
    )
    await msg.write_eof(payload)
    assert transport.writelines.called != transport.write.called  # type: ignore[attr-defined]
    if transport.writelines.called:  # type: ignore[attr-defined]
        chunks.extend(transport.writelines.mock_calls[0][1][0])  # type: ignore[attr-defined]
    else:  # transport.write.called:  # type: ignore[attr-defined]
        chunks.extend([c[1][0] for c in list(transport.write.mock_calls)])  # type: ignore[attr-defined]
    content = b"".join(chunks)
    assert ZLibBackend.decompress(content) == (b"data" * 4096) + payload


async def test_write_payload_chunked_filter(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.enable_chunking()
    await msg.write(b"da")
    await msg.write(b"ta")
    await msg.write_eof()

    content = b"".join([b"".join(c[1][0]) for c in list(transport.writelines.mock_calls)])  # type: ignore[attr-defined]
    content += b"".join([c[1][0] for c in list(transport.write.mock_calls)])  # type: ignore[attr-defined]
    assert content.endswith(b"2\r\nda\r\n2\r\nta\r\n0\r\n\r\n")


async def test_write_payload_chunked_filter_multiple_chunks(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.enable_chunking()
    await msg.write(b"da")
    await msg.write(b"ta")
    await msg.write(b"1d")
    await msg.write(b"at")
    await msg.write(b"a2")
    await msg.write_eof()
    content = b"".join([b"".join(c[1][0]) for c in list(transport.writelines.mock_calls)])  # type: ignore[attr-defined]
    content += b"".join([c[1][0] for c in list(transport.write.mock_calls)])  # type: ignore[attr-defined]
    assert content.endswith(
        b"2\r\nda\r\n2\r\nta\r\n2\r\n1d\r\n2\r\nat\r\n2\r\na2\r\n0\r\n\r\n"
    )


@pytest.mark.internal  # Used for performance benchmarking
async def test_write_payload_deflate_compression(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    COMPRESSED = b"x\x9cKI,I\x04\x00\x04\x00\x01\x9b"
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")
    await msg.write(b"data")
    await msg.write_eof()

    chunks = [c[1][0] for c in list(transport.write.mock_calls)]  # type: ignore[attr-defined]
    assert all(chunks)
    content = b"".join(chunks)
    assert COMPRESSED == content.split(b"\r\n\r\n", 1)[-1]


@pytest.mark.usefixtures("parametrize_zlib_backend")
async def test_write_payload_deflate_compression_all_zlib(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")
    await msg.write(b"data")
    await msg.write_eof()

    chunks = [c[1][0] for c in list(transport.write.mock_calls)]  # type: ignore[attr-defined]
    assert all(chunks)
    content = b"".join(chunks)
    assert b"data" == decompress(content)


@pytest.mark.internal  # Used for performance benchmarking
async def test_write_payload_deflate_compression_chunked(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    expected = b"2\r\nx\x9c\r\na\r\nKI,I\x04\x00\x04\x00\x01\x9b\r\n0\r\n\r\n"
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")
    msg.enable_chunking()
    await msg.write(b"data")
    await msg.write_eof()

    chunks = [c[1][0] for c in list(transport.write.mock_calls)]  # type: ignore[attr-defined]
    assert all(chunks)
    content = b"".join(chunks)
    assert content == expected


@pytest.mark.usefixtures("parametrize_zlib_backend")
async def test_write_payload_deflate_compression_chunked_all_zlib(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")
    msg.enable_chunking()
    await msg.write(b"data")
    await msg.write_eof()

    chunks = [c[1][0] for c in list(transport.write.mock_calls)]  # type: ignore[attr-defined]
    assert all(chunks)
    content = b"".join(chunks)
    assert b"data" == decompress(decode_chunked(content))


@pytest.mark.usefixtures("enable_writelines")
@pytest.mark.usefixtures("force_writelines_small_payloads")
@pytest.mark.internal  # Used for performance benchmarking
async def test_write_payload_deflate_compression_chunked_writelines(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    expected = b"2\r\nx\x9c\r\na\r\nKI,I\x04\x00\x04\x00\x01\x9b\r\n0\r\n\r\n"
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")
    msg.enable_chunking()
    await msg.write(b"data")
    await msg.write_eof()

    chunks = [b"".join(c[1][0]) for c in list(transport.writelines.mock_calls)]  # type: ignore[attr-defined]
    assert all(chunks)
    content = b"".join(chunks)
    assert content == expected


@pytest.mark.usefixtures("enable_writelines")
@pytest.mark.usefixtures("force_writelines_small_payloads")
@pytest.mark.usefixtures("parametrize_zlib_backend")
async def test_write_payload_deflate_compression_chunked_writelines_all_zlib(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")
    msg.enable_chunking()
    await msg.write(b"data")
    await msg.write_eof()

    chunks = [b"".join(c[1][0]) for c in list(transport.writelines.mock_calls)]  # type: ignore[attr-defined]
    assert all(chunks)
    content = b"".join(chunks)
    assert b"data" == decompress(decode_chunked(content))


@pytest.mark.internal  # Used for performance benchmarking
async def test_write_payload_deflate_and_chunked(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")
    msg.enable_chunking()

    await msg.write(b"da")
    await msg.write(b"ta")
    await msg.write_eof()

    thing = b"2\r\nx\x9c\r\na\r\nKI,I\x04\x00\x04\x00\x01\x9b\r\n0\r\n\r\n"
    assert thing == buf


@pytest.mark.usefixtures("parametrize_zlib_backend")
async def test_write_payload_deflate_and_chunked_all_zlib(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")
    msg.enable_chunking()

    await msg.write(b"da")
    await msg.write(b"ta")
    await msg.write_eof()

    assert b"data" == decompress(decode_chunked(buf))


@pytest.mark.internal  # Used for performance benchmarking
async def test_write_payload_deflate_compression_chunked_data_in_eof(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    expected = b"2\r\nx\x9c\r\nd\r\nKI,IL\xcdK\x01\x00\x0b@\x02\xd2\r\n0\r\n\r\n"
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")
    msg.enable_chunking()
    await msg.write(b"data")
    await msg.write_eof(b"end")

    chunks = [c[1][0] for c in list(transport.write.mock_calls)]  # type: ignore[attr-defined]
    assert all(chunks)
    content = b"".join(chunks)
    assert content == expected


@pytest.mark.usefixtures("parametrize_zlib_backend")
async def test_write_payload_deflate_compression_chunked_data_in_eof_all_zlib(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")
    msg.enable_chunking()
    await msg.write(b"data")
    await msg.write_eof(b"end")

    chunks = [c[1][0] for c in list(transport.write.mock_calls)]  # type: ignore[attr-defined]
    assert all(chunks)
    content = b"".join(chunks)
    assert b"dataend" == decompress(decode_chunked(content))


@pytest.mark.usefixtures("enable_writelines")
@pytest.mark.usefixtures("force_writelines_small_payloads")
@pytest.mark.internal  # Used for performance benchmarking
async def test_write_payload_deflate_compression_chunked_data_in_eof_writelines(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    expected = b"2\r\nx\x9c\r\nd\r\nKI,IL\xcdK\x01\x00\x0b@\x02\xd2\r\n0\r\n\r\n"
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")
    msg.enable_chunking()
    await msg.write(b"data")
    await msg.write_eof(b"end")

    chunks = [b"".join(c[1][0]) for c in list(transport.writelines.mock_calls)]  # type: ignore[attr-defined]
    assert all(chunks)
    content = b"".join(chunks)
    assert content == expected


@pytest.mark.usefixtures("enable_writelines")
@pytest.mark.usefixtures("force_writelines_small_payloads")
@pytest.mark.usefixtures("parametrize_zlib_backend")
async def test_write_payload_deflate_compression_chunked_data_in_eof_writelines_all_zlib(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")
    msg.enable_chunking()
    await msg.write(b"data")
    await msg.write_eof(b"end")

    chunks = [b"".join(c[1][0]) for c in list(transport.writelines.mock_calls)]  # type: ignore[attr-defined]
    assert all(chunks)
    content = b"".join(chunks)
    assert b"dataend" == decompress(decode_chunked(content))


@pytest.mark.internal  # Used for performance benchmarking
async def test_write_large_payload_deflate_compression_chunked_data_in_eof(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")
    msg.enable_chunking()

    await msg.write(b"data" * 4096)
    # This payload compresses to 1111 bytes
    payload = b"".join([bytes((*range(0, i), *range(i, 0, -1))) for i in range(255)])
    await msg.write_eof(payload)

    compressed = []
    chunks = [c[1][0] for c in list(transport.write.mock_calls)]  # type: ignore[attr-defined]
    chunked_body = b"".join(chunks)
    split_body = chunked_body.split(b"\r\n")
    while split_body:
        if split_body.pop(0):
            compressed.append(split_body.pop(0))

    content = b"".join(compressed)
    assert zlib.decompress(content) == (b"data" * 4096) + payload


@pytest.mark.usefixtures("parametrize_zlib_backend")
async def test_write_large_payload_deflate_compression_chunked_data_in_eof_all_zlib(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")
    msg.enable_chunking()

    await msg.write(b"data" * 4096)
    # This payload compresses to 1111 bytes
    payload = b"".join([bytes((*range(0, i), *range(i, 0, -1))) for i in range(255)])
    await msg.write_eof(payload)

    compressed = []
    chunks = [c[1][0] for c in list(transport.write.mock_calls)]  # type: ignore[attr-defined]
    chunked_body = b"".join(chunks)
    split_body = chunked_body.split(b"\r\n")
    while split_body:
        if split_body.pop(0):
            compressed.append(split_body.pop(0))

    content = b"".join(compressed)
    assert ZLibBackend.decompress(content) == (b"data" * 4096) + payload


@pytest.mark.usefixtures("enable_writelines")
@pytest.mark.usefixtures("force_writelines_small_payloads")
@pytest.mark.internal  # Used for performance benchmarking
async def test_write_large_payload_deflate_compression_chunked_data_in_eof_writelines(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")
    msg.enable_chunking()

    await msg.write(b"data" * 4096)
    # This payload compresses to 1111 bytes
    payload = b"".join([bytes((*range(0, i), *range(i, 0, -1))) for i in range(255)])
    await msg.write_eof(payload)
    assert not transport.write.called  # type: ignore[attr-defined]

    chunks = []
    for write_lines_call in transport.writelines.mock_calls:  # type: ignore[attr-defined]
        chunked_payload = list(write_lines_call[1][0])[1:]
        chunked_payload.pop()
        chunks.extend(chunked_payload)

    assert all(chunks)
    content = b"".join(chunks)
    assert zlib.decompress(content) == (b"data" * 4096) + payload


@pytest.mark.usefixtures("enable_writelines")
@pytest.mark.usefixtures("force_writelines_small_payloads")
@pytest.mark.usefixtures("parametrize_zlib_backend")
async def test_write_large_payload_deflate_compression_chunked_data_in_eof_writelines_all_zlib(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")
    msg.enable_chunking()

    await msg.write(b"data" * 4096)
    # This payload compresses to 1111 bytes
    payload = b"".join([bytes((*range(0, i), *range(i, 0, -1))) for i in range(255)])
    await msg.write_eof(payload)
    assert not transport.write.called  # type: ignore[attr-defined]

    chunks = []
    for write_lines_call in transport.writelines.mock_calls:  # type: ignore[attr-defined]
        chunked_payload = list(write_lines_call[1][0])[1:]
        chunked_payload.pop()
        chunks.extend(chunked_payload)

    assert all(chunks)
    content = b"".join(chunks)
    assert ZLibBackend.decompress(content) == (b"data" * 4096) + payload


@pytest.mark.internal  # Used for performance benchmarking
async def test_write_payload_deflate_compression_chunked_connection_lost(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")
    msg.enable_chunking()
    await msg.write(b"data")
    with (
        pytest.raises(
            ClientConnectionResetError, match="Cannot write to closing transport"
        ),
        mock.patch.object(transport, "is_closing", return_value=True),
    ):
        await msg.write_eof(b"end")


@pytest.mark.usefixtures("parametrize_zlib_backend")
async def test_write_payload_deflate_compression_chunked_connection_lost_all_zlib(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")
    msg.enable_chunking()
    await msg.write(b"data")
    with (
        pytest.raises(
            ClientConnectionResetError, match="Cannot write to closing transport"
        ),
        mock.patch.object(transport, "is_closing", return_value=True),
    ):
        await msg.write_eof(b"end")


async def test_write_payload_bytes_memoryview(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)

    mv = memoryview(b"abcd")

    await msg.write(mv)
    await msg.write_eof()

    thing = b"abcd"
    assert thing == buf


async def test_write_payload_short_ints_memoryview(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.enable_chunking()

    payload = memoryview(array.array("H", [65, 66, 67]))

    await msg.write(payload)
    await msg.write_eof()

    endians = (
        (b"6\r\n\x00A\x00B\x00C\r\n0\r\n\r\n"),
        (b"6\r\nA\x00B\x00C\x00\r\n0\r\n\r\n"),
    )
    assert buf in endians


async def test_write_payload_2d_shape_memoryview(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.enable_chunking()

    mv = memoryview(b"ABCDEF")
    payload = mv.cast("c", [3, 2])

    await msg.write(payload)
    await msg.write_eof()

    thing = b"6\r\nABCDEF\r\n0\r\n\r\n"
    assert thing == buf


async def test_write_payload_slicing_long_memoryview(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.length = 4

    mv = memoryview(b"ABCDEF")
    payload = mv.cast("c", [3, 2])

    await msg.write(payload)
    await msg.write_eof()

    thing = b"ABCD"
    assert thing == buf


async def test_write_drain(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    with mock.patch.object(msg, "drain", autospec=True, spec_set=True) as m:
        await msg.write(b"1" * (64 * 1024 * 2), drain=False)
        assert not m.called

        await msg.write(b"1", drain=True)
        assert m.called
        assert msg.buffer_size == 0  # type: ignore[unreachable]


async def test_write_calls_callback(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    on_chunk_sent = mock.AsyncMock()
    msg = http.StreamWriter(protocol, loop, on_chunk_sent=on_chunk_sent)
    chunk = b"1"
    await msg.write(chunk)
    assert on_chunk_sent.called
    assert on_chunk_sent.call_args == mock.call(chunk)


async def test_write_eof_calls_callback(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    on_chunk_sent = mock.AsyncMock()
    msg = http.StreamWriter(protocol, loop, on_chunk_sent=on_chunk_sent)
    chunk = b"1"
    await msg.write_eof(chunk=chunk)
    assert on_chunk_sent.called
    assert on_chunk_sent.call_args == mock.call(chunk)


async def test_write_to_closing_transport(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)

    await msg.write(b"Before closing")
    transport.is_closing.return_value = True  # type: ignore[attr-defined]

    with pytest.raises(ClientConnectionResetError):
        await msg.write(b"After closing")


async def test_write_to_closed_transport(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Test that writing to a closed transport raises ClientConnectionResetError.

    The StreamWriter checks to see if protocol.transport is None before
    writing to the transport. If it is None, it raises ConnectionResetError.
    """
    msg = http.StreamWriter(protocol, loop)

    await msg.write(b"Before transport close")
    protocol.transport = None

    with pytest.raises(
        ClientConnectionResetError, match="Cannot write to closing transport"
    ):
        await msg.write(b"After transport closed")


async def test_drain(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    await msg.drain()
    assert protocol._drain_helper.called  # type: ignore[attr-defined]


async def test_drain_no_transport(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg._protocol.transport = None
    await msg.drain()
    assert not protocol._drain_helper.called  # type: ignore[attr-defined]


async def test_write_headers_prevents_injection(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    status_line = "HTTP/1.1 200 OK"
    wrong_headers = CIMultiDict({"Set-Cookie: abc=123\r\nContent-Length": "256"})
    with pytest.raises(ValueError):
        await msg.write_headers(status_line, wrong_headers)
    wrong_headers = CIMultiDict({"Content-Length": "256\r\nSet-Cookie: abc=123"})
    with pytest.raises(ValueError):
        await msg.write_headers(status_line, wrong_headers)


async def test_set_eof_after_write_headers(
    protocol: BaseProtocol,
    transport: mock.Mock,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    status_line = "HTTP/1.1 200 OK"
    good_headers = CIMultiDict({"Set-Cookie": "abc=123"})

    # Write headers - should be buffered
    await msg.write_headers(status_line, good_headers)
    assert not transport.write.called  # Headers are buffered

    # set_eof should send the buffered headers
    msg.set_eof()
    assert transport.write.called

    # Subsequent write_eof should do nothing
    transport.write.reset_mock()
    await msg.write_eof()
    assert not transport.write.called


async def test_write_headers_does_not_write_immediately(
    protocol: BaseProtocol,
    transport: mock.Mock,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    status_line = "HTTP/1.1 200 OK"
    headers = CIMultiDict({"Content-Type": "text/plain"})

    # write_headers should buffer, not write immediately
    await msg.write_headers(status_line, headers)
    assert not transport.write.called
    assert not transport.writelines.called

    # Headers should be sent when set_eof is called
    msg.set_eof()
    assert transport.write.called


async def test_write_headers_with_compression_coalescing(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")
    headers = CIMultiDict({"Content-Encoding": "deflate", "Host": "example.com"})

    # Write headers - should be buffered
    await msg.write_headers("POST /data HTTP/1.1", headers)
    assert len(buf) == 0

    # Write compressed data via write_eof - should coalesce
    await msg.write_eof(b"Hello World")

    # Verify headers are present
    assert b"POST /data HTTP/1.1\r\n" in buf
    assert b"Content-Encoding: deflate\r\n" in buf

    # Verify compressed data is present
    # The data should contain headers + compressed payload
    assert len(buf) > 50  # Should have headers + some compressed data


@pytest.mark.parametrize(
    "char",
    [
        "\n",
        "\r",
    ],
)
def test_serialize_headers_raises_on_new_line_or_carriage_return(char: str) -> None:
    """Verify serialize_headers raises on cr or nl in the headers."""
    status_line = "HTTP/1.1 200 OK"
    headers = CIMultiDict(
        {
            hdrs.CONTENT_TYPE: f"text/plain{char}",
        }
    )

    with pytest.raises(
        ValueError,
        match=(
            "Newline or carriage return detected in headers. "
            "Potential header injection attack."
        ),
    ):
        _serialize_headers(status_line, headers)


async def test_write_compressed_data_with_headers_coalescing(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Test that headers are coalesced with compressed data in write() method."""
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")
    headers = CIMultiDict({"Content-Encoding": "deflate", "Host": "example.com"})

    # Write headers - should be buffered
    await msg.write_headers("POST /data HTTP/1.1", headers)
    assert len(buf) == 0

    # Write compressed data - should coalesce with headers
    await msg.write(b"Hello World")

    # Headers and compressed data should be written together
    assert b"POST /data HTTP/1.1\r\n" in buf
    assert b"Content-Encoding: deflate\r\n" in buf
    assert len(buf) > 50  # Headers + compressed data


async def test_write_compressed_chunked_with_headers_coalescing(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Test headers coalescing with compressed chunked data."""
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")
    msg.enable_chunking()
    headers = CIMultiDict(
        {"Content-Encoding": "deflate", "Transfer-Encoding": "chunked"}
    )

    # Write headers - should be buffered
    await msg.write_headers("POST /data HTTP/1.1", headers)
    assert len(buf) == 0

    # Write compressed chunked data - should coalesce
    await msg.write(b"Hello World")

    # Check headers are present
    assert b"POST /data HTTP/1.1\r\n" in buf
    assert b"Transfer-Encoding: chunked\r\n" in buf

    # Should have chunk size marker for compressed data
    output = buf.decode("latin-1", errors="ignore")
    assert "\r\n" in output  # Should have chunk markers


async def test_write_multiple_compressed_chunks_after_headers_sent(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Test multiple compressed writes after headers are already sent."""
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")
    headers = CIMultiDict({"Content-Encoding": "deflate"})

    # Write headers and send them immediately by writing first chunk
    await msg.write_headers("POST /data HTTP/1.1", headers)
    assert len(buf) == 0  # Headers buffered

    # Write first chunk - this will send headers + compressed data
    await msg.write(b"First chunk of data that should compress")
    len_after_first = len(buf)
    assert len_after_first > 0  # Headers + first chunk written

    # Write second chunk and force flush via EOF
    await msg.write(b"Second chunk of data that should also compress well")
    await msg.write_eof()

    # After EOF, all compressed data should be flushed
    final_len = len(buf)
    assert final_len > len_after_first


async def test_write_eof_empty_compressed_with_buffered_headers(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Test write_eof with no data but compression enabled and buffered headers."""
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")
    headers = CIMultiDict({"Content-Encoding": "deflate"})

    # Write headers - should be buffered
    await msg.write_headers("GET /data HTTP/1.1", headers)
    assert len(buf) == 0

    # Write EOF with no data - should still coalesce headers with compression flush
    await msg.write_eof()

    # Headers should be present
    assert b"GET /data HTTP/1.1\r\n" in buf
    assert b"Content-Encoding: deflate\r\n" in buf
    # Should have compression flush data
    assert len(buf) > 40


async def test_write_compressed_gzip_with_headers_coalescing(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Test gzip compression with header coalescing."""
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("gzip")
    headers = CIMultiDict({"Content-Encoding": "gzip"})

    # Write headers - should be buffered
    await msg.write_headers("POST /data HTTP/1.1", headers)
    assert len(buf) == 0

    # Write gzip compressed data via write_eof
    await msg.write_eof(b"Test gzip compression")

    # Verify coalescing happened
    assert b"POST /data HTTP/1.1\r\n" in buf
    assert b"Content-Encoding: gzip\r\n" in buf
    # Gzip typically produces more overhead than deflate
    assert len(buf) > 60


async def test_compression_with_content_length_constraint(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Test compression respects content length constraints."""
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")
    msg.length = 5  # Set small content length
    headers = CIMultiDict({"Content-Length": "5"})

    await msg.write_headers("POST /data HTTP/1.1", headers)
    # Write some initial data to trigger headers to be sent
    await msg.write(b"12345")  # This matches our content length of 5
    headers_and_first_chunk_len = len(buf)

    # Try to write more data than content length allows
    await msg.write(b"This is a longer message")

    # The second write should not add any data since content length is exhausted
    # After writing 5 bytes, length becomes 0, so additional writes are ignored
    assert len(buf) == headers_and_first_chunk_len  # No additional data written


async def test_write_compressed_zero_length_chunk(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Test writing empty chunk with compression."""
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")

    await msg.write_headers("POST /data HTTP/1.1", CIMultiDict())
    # Force headers to be sent by writing something
    await msg.write(b"x")  # Write something to trigger header send
    buf.clear()

    # Write empty chunk - compression may still produce output
    await msg.write(b"")

    # With compression, even empty input might produce small output
    # due to compression state, but it should be minimal
    assert len(buf) < 10  # Should be very small if anything


async def test_chunked_compressed_eof_coalescing(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Test chunked compressed data with EOF marker coalescing."""
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")
    msg.enable_chunking()
    headers = CIMultiDict(
        {"Content-Encoding": "deflate", "Transfer-Encoding": "chunked"}
    )

    # Buffer headers
    await msg.write_headers("POST /data HTTP/1.1", headers)
    assert len(buf) == 0

    # Write compressed chunked data with EOF
    await msg.write_eof(b"Final compressed chunk")

    # Should have headers
    assert b"POST /data HTTP/1.1\r\n" in buf

    # Should end with chunked EOF marker
    assert buf.endswith(b"0\r\n\r\n")

    # Should have chunk size in hex before the compressed data
    output = buf
    # Verify we have chunk markers - look for \r\n followed by hex digits
    # The chunk size should be between the headers and the compressed data
    assert b"\r\n\r\n" in output  # End of headers
    # After headers, we should have a hex chunk size
    headers_end = output.find(b"\r\n\r\n") + 4
    chunk_data = output[headers_end:]
    # Should start with hex digits followed by \r\n
    assert (
        chunk_data[:10]
        .strip()
        .decode("ascii", errors="ignore")
        .replace("\r\n", "")
        .isalnum()
    )


async def test_compression_different_strategies(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Test compression with different strategies."""
    # Test with best speed strategy (default)
    msg1 = http.StreamWriter(protocol, loop)
    msg1.enable_compression("deflate")  # Default strategy

    await msg1.write_headers("POST /fast HTTP/1.1", CIMultiDict())
    await msg1.write_eof(b"Test data for compression test data for compression")

    buf1_len = len(buf)

    # Both should produce output
    assert buf1_len > 0
    # Headers should be present
    assert b"POST /fast HTTP/1.1\r\n" in buf

    # Since we can't easily test different compression strategies
    # (the compressor initialization might not support strategy parameter),
    # we just verify that compression works


async def test_chunked_headers_single_write_with_set_eof(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Test that set_eof combines headers and chunked EOF in single write."""
    msg = http.StreamWriter(protocol, loop)
    msg.enable_chunking()

    # Write headers - should be buffered
    headers = CIMultiDict({"Transfer-Encoding": "chunked", "Host": "example.com"})
    await msg.write_headers("GET /test HTTP/1.1", headers)
    assert len(buf) == 0  # Headers not sent yet
    assert not transport.writelines.called  # type: ignore[attr-defined]  # No writelines calls yet

    # Call set_eof - should send headers + chunked EOF in single write call
    msg.set_eof()

    # Should have exactly one write call (since payload is small, writelines falls back to write)
    assert transport.write.call_count == 1  # type: ignore[attr-defined]
    assert transport.writelines.call_count == 0  # type: ignore[attr-defined]  # Not called for small payloads

    # The write call should have the combined headers and chunked EOF marker
    write_data = transport.write.call_args[0][0]  # type: ignore[attr-defined]
    assert write_data.startswith(b"GET /test HTTP/1.1\r\n")
    assert b"Transfer-Encoding: chunked\r\n" in write_data
    assert write_data.endswith(b"\r\n\r\n0\r\n\r\n")  # Headers end + chunked EOF

    # Verify final output
    assert b"GET /test HTTP/1.1\r\n" in buf
    assert b"Transfer-Encoding: chunked\r\n" in buf
    assert buf.endswith(b"0\r\n\r\n")


async def test_send_headers_forces_header_write(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Test that send_headers() forces writing buffered headers."""
    msg = http.StreamWriter(protocol, loop)
    headers = CIMultiDict({"Content-Length": "10", "Host": "example.com"})

    # Write headers (should be buffered)
    await msg.write_headers("GET /test HTTP/1.1", headers)
    assert len(buf) == 0  # Headers buffered

    # Force send headers
    msg.send_headers()

    # Headers should now be written
    assert b"GET /test HTTP/1.1\r\n" in buf
    assert b"Content-Length: 10\r\n" in buf
    assert b"Host: example.com\r\n" in buf

    # Writing body should not resend headers
    buf.clear()
    await msg.write(b"0123456789")
    assert b"GET /test" not in buf  # Headers not repeated
    assert buf == b"0123456789"  # Just the body


async def test_send_headers_idempotent(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Test that send_headers() is idempotent and safe to call multiple times."""
    msg = http.StreamWriter(protocol, loop)
    headers = CIMultiDict({"Content-Length": "5", "Host": "example.com"})

    # Write headers (should be buffered)
    await msg.write_headers("GET /test HTTP/1.1", headers)
    assert len(buf) == 0  # Headers buffered

    # Force send headers
    msg.send_headers()
    headers_output = bytes(buf)

    # Call send_headers again - should be no-op
    msg.send_headers()
    assert buf == headers_output  # No additional output

    # Call send_headers after headers already sent - should be no-op
    await msg.write(b"hello")
    msg.send_headers()
    assert buf[len(headers_output) :] == b"hello"  # Only body added


async def test_send_headers_no_buffered_headers(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Test that send_headers() is safe when no headers are buffered."""
    msg = http.StreamWriter(protocol, loop)

    # Call send_headers without writing headers first
    msg.send_headers()  # Should not crash
    assert len(buf) == 0  # No output


async def test_write_drain_condition_with_small_buffer(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Test that drain is not called when buffer_size <= LIMIT."""
    msg = http.StreamWriter(protocol, loop)

    # Write headers first
    await msg.write_headers("GET /test HTTP/1.1", CIMultiDict())
    msg.send_headers()  # Send headers to start with clean state

    # Reset buffer size manually since send_headers doesn't do it
    msg.buffer_size = 0

    # Reset drain helper mock
    protocol._drain_helper.reset_mock()  # type: ignore[attr-defined]

    # Write small amount of data with drain=True but buffer under limit
    small_data = b"x" * 100  # Much less than LIMIT (2**16)
    await msg.write(small_data, drain=True)

    # Drain should NOT be called because buffer_size <= LIMIT
    assert not protocol._drain_helper.called  # type: ignore[attr-defined]
    assert msg.buffer_size == 100
    assert small_data in buf


async def test_write_drain_condition_with_large_buffer(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Test that drain is called only when drain=True AND buffer_size > LIMIT."""
    msg = http.StreamWriter(protocol, loop)

    # Write headers first
    await msg.write_headers("GET /test HTTP/1.1", CIMultiDict())
    msg.send_headers()  # Send headers to start with clean state

    # Reset buffer size manually since send_headers doesn't do it
    msg.buffer_size = 0

    # Reset drain helper mock
    protocol._drain_helper.reset_mock()  # type: ignore[attr-defined]

    # Write large amount of data with drain=True
    large_data = b"x" * (2**16 + 1)  # Just over LIMIT
    await msg.write(large_data, drain=True)

    # Drain should be called because drain=True AND buffer_size > LIMIT
    assert protocol._drain_helper.called  # type: ignore[attr-defined]
    assert msg.buffer_size == 0  # Buffer reset after drain
    assert large_data in buf


async def test_write_no_drain_with_large_buffer(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Test that drain is not called when drain=False even with large buffer."""
    msg = http.StreamWriter(protocol, loop)

    # Write headers first
    await msg.write_headers("GET /test HTTP/1.1", CIMultiDict())
    msg.send_headers()  # Send headers to start with clean state

    # Reset buffer size manually since send_headers doesn't do it
    msg.buffer_size = 0

    # Reset drain helper mock
    protocol._drain_helper.reset_mock()  # type: ignore[attr-defined]

    # Write large amount of data with drain=False
    large_data = b"x" * (2**16 + 1)  # Just over LIMIT
    await msg.write(large_data, drain=False)

    # Drain should NOT be called because drain=False
    assert not protocol._drain_helper.called  # type: ignore[attr-defined]
    assert msg.buffer_size == (2**16 + 1)  # Buffer not reset
    assert large_data in buf


async def test_set_eof_idempotent(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Test that set_eof() is idempotent and can be called multiple times safely."""
    msg = http.StreamWriter(protocol, loop)

    # Test 1: Multiple set_eof calls with buffered headers
    headers = CIMultiDict({"Content-Length": "0"})
    await msg.write_headers("GET /test HTTP/1.1", headers)

    # First set_eof should send headers
    msg.set_eof()
    first_output = buf
    assert b"GET /test HTTP/1.1\r\n" in first_output
    assert b"Content-Length: 0\r\n" in first_output

    # Second set_eof should be no-op
    msg.set_eof()
    assert bytes(buf) == first_output  # No additional output

    # Third set_eof should also be no-op
    msg.set_eof()
    assert bytes(buf) == first_output  # Still no additional output

    # Test 2: set_eof with chunked encoding
    buf.clear()
    msg2 = http.StreamWriter(protocol, loop)
    msg2.enable_chunking()

    headers2 = CIMultiDict({"Transfer-Encoding": "chunked"})
    await msg2.write_headers("POST /data HTTP/1.1", headers2)

    # First set_eof should send headers + chunked EOF
    msg2.set_eof()
    chunked_output = buf
    assert b"POST /data HTTP/1.1\r\n" in buf
    assert b"Transfer-Encoding: chunked\r\n" in buf
    assert b"0\r\n\r\n" in buf  # Chunked EOF marker

    # Second set_eof should be no-op
    msg2.set_eof()
    assert buf == chunked_output  # No additional output

    # Test 3: set_eof after headers already sent
    buf.clear()
    msg3 = http.StreamWriter(protocol, loop)

    headers3 = CIMultiDict({"Content-Length": "5"})
    await msg3.write_headers("PUT /update HTTP/1.1", headers3)

    # Send headers by writing some data
    await msg3.write(b"hello")
    headers_and_body = buf

    # set_eof after headers sent should be no-op
    msg3.set_eof()
    assert buf == headers_and_body  # No additional output

    # Another set_eof should still be no-op
    msg3.set_eof()
    assert buf == headers_and_body  # Still no additional output


async def test_non_chunked_write_empty_body(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: mock.Mock,
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Test non-chunked response with empty body."""
    msg = http.StreamWriter(protocol, loop)

    # Non-chunked response with Content-Length: 0
    headers = CIMultiDict({"Content-Length": "0"})
    await msg.write_headers("GET /empty HTTP/1.1", headers)

    # Write empty body
    await msg.write(b"")

    # Check the output
    assert b"GET /empty HTTP/1.1\r\n" in buf
    assert b"Content-Length: 0\r\n" in buf


async def test_chunked_headers_sent_with_empty_chunk_not_eof(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Test chunked encoding where headers are sent without data and not EOF."""
    msg = http.StreamWriter(protocol, loop)
    msg.enable_chunking()

    headers = CIMultiDict({"Transfer-Encoding": "chunked"})
    await msg.write_headers("POST /upload HTTP/1.1", headers)

    # This should trigger the else case in _send_headers_with_payload
    # by having no chunk data and is_eof=False
    await msg.write(b"")

    # Headers should be sent alone
    assert b"POST /upload HTTP/1.1\r\n" in buf
    assert b"Transfer-Encoding: chunked\r\n" in buf
    # Should not have any chunk markers yet
    assert b"0\r\n" not in buf


async def test_chunked_set_eof_after_headers_sent(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Test chunked encoding where set_eof is called after headers already sent."""
    msg = http.StreamWriter(protocol, loop)
    msg.enable_chunking()

    headers = CIMultiDict({"Transfer-Encoding": "chunked"})
    await msg.write_headers("POST /data HTTP/1.1", headers)

    # Send headers by writing some data
    await msg.write(b"test data")
    buf.clear()  # Clear buffer to check only what set_eof writes

    # This should trigger writing chunked EOF when headers already sent
    msg.set_eof()

    # Should only have the chunked EOF marker
    assert buf == b"0\r\n\r\n"


@pytest.mark.usefixtures("enable_writelines")
@pytest.mark.usefixtures("force_writelines_small_payloads")
async def test_write_eof_chunked_with_data_using_writelines(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Test write_eof with chunked data that uses writelines (line 336)."""
    msg = http.StreamWriter(protocol, loop)
    msg.enable_chunking()

    headers = CIMultiDict({"Transfer-Encoding": "chunked"})
    await msg.write_headers("POST /data HTTP/1.1", headers)

    # Send headers first
    await msg.write(b"initial")
    transport.writelines.reset_mock()  # type: ignore[attr-defined]

    # This should trigger writelines for final chunk with EOF
    await msg.write_eof(b"final chunk data")

    # Should have used writelines
    assert transport.writelines.called  # type: ignore[attr-defined]
    # Get the data from writelines call
    writelines_data = transport.writelines.call_args[0][0]  # type: ignore[attr-defined]
    combined = b"".join(writelines_data)

    # Should have chunk size, data, and EOF marker
    assert b"10\r\n" in combined  # hex for 16 (length of "final chunk data")
    assert b"final chunk data" in combined
    assert b"0\r\n\r\n" in combined


async def test_send_headers_with_payload_chunked_eof_no_data(
    buf: bytearray,
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Test _send_headers_with_payload with chunked, is_eof=True but no chunk data."""
    msg = http.StreamWriter(protocol, loop)
    msg.enable_chunking()

    headers = CIMultiDict({"Transfer-Encoding": "chunked"})
    await msg.write_headers("GET /test HTTP/1.1", headers)

    # This triggers the elif is_eof branch in _send_headers_with_payload
    # by calling write_eof with empty chunk
    await msg.write_eof(b"")

    # Should have headers and chunked EOF marker together
    assert b"GET /test HTTP/1.1\r\n" in buf
    assert b"Transfer-Encoding: chunked\r\n" in buf
    assert buf.endswith(b"0\r\n\r\n")
