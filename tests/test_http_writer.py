# Tests for aiohttp/http_writer.py
import array
import asyncio
from typing import Any
from unittest import mock

import pytest
from multidict import CIMultiDict

from aiohttp import http
from aiohttp.base_protocol import BaseProtocol
from aiohttp.test_utils import make_mocked_coro


@pytest.fixture
def buf() -> bytearray:
    return bytearray()


@pytest.fixture
def transport(buf: bytearray) -> Any:
    transport = mock.create_autospec(asyncio.Transport, spec_set=True, instance=True)

    def write(chunk: bytes) -> None:
        buf.extend(chunk)

    transport.write.side_effect = write
    transport.is_closing.return_value = False
    return transport


@pytest.fixture
def protocol(loop: asyncio.AbstractEventLoop, transport: asyncio.Transport) -> Any:
    return mock.create_autospec(
        BaseProtocol, spec_set=True, instance=True, transport=transport
    )


def test_payloadwriter_properties(
    transport: asyncio.Transport,
    protocol: BaseProtocol,
    loop: asyncio.AbstractEventLoop,
) -> None:
    writer = http.StreamWriter(protocol, loop)
    assert writer.protocol == protocol
    assert writer.transport == transport


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

    content = b"".join([c[1][0] for c in list(transport.write.mock_calls)])  # type: ignore[attr-defined]
    assert content.endswith(b"2\r\nda\r\n2\r\nta\r\n0\r\n\r\n")


async def test_write_payload_chunked_filter_mutiple_chunks(
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
    content = b"".join([c[1][0] for c in list(transport.write.mock_calls)])  # type: ignore[attr-defined]
    assert content.endswith(
        b"2\r\nda\r\n2\r\nta\r\n2\r\n1d\r\n2\r\nat\r\n2\r\na2\r\n0\r\n\r\n"
    )


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
        assert msg.buffer_size == 0


async def test_write_calls_callback(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    on_chunk_sent = make_mocked_coro()
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
    on_chunk_sent = make_mocked_coro()
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

    with pytest.raises(ConnectionResetError):
        await msg.write(b"After closing")


async def test_write_to_closed_transport(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Test that writing to a closed transport raises ConnectionResetError.

    The StreamWriter checks to see if protocol.transport is None before
    writing to the transport. If it is None, it raises ConnectionResetError.
    """
    msg = http.StreamWriter(protocol, loop)

    await msg.write(b"Before transport close")
    protocol.transport = None

    with pytest.raises(ConnectionResetError, match="Cannot write to closing transport"):
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
