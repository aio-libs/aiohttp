# type: ignore
# Tests for aiohttp/http_writer.py
import array
from typing import Any
from unittest import mock

import pytest
from multidict import CIMultiDict

from aiohttp import http
from aiohttp.test_utils import make_mocked_coro


@pytest.fixture
def buf():
    return bytearray()


@pytest.fixture
def transport(buf: Any):
    transport = mock.Mock()

    def write(chunk):
        buf.extend(chunk)

    transport.write.side_effect = write
    transport.is_closing.return_value = False
    return transport


@pytest.fixture
def protocol(loop: Any, transport: Any):
    protocol = mock.Mock(transport=transport)
    protocol._drain_helper = make_mocked_coro()
    return protocol


def test_payloadwriter_properties(transport: Any, protocol: Any, loop: Any) -> None:
    writer = http.StreamWriter(protocol, loop)
    assert writer.protocol == protocol
    assert writer.transport == transport


async def test_write_payload_eof(transport: Any, protocol: Any, loop: Any) -> None:
    write = transport.write = mock.Mock()
    msg = http.StreamWriter(protocol, loop)

    await msg.write(b"data1")
    await msg.write(b"data2")
    await msg.write_eof()

    content = b"".join([c[1][0] for c in list(write.mock_calls)])
    assert b"data1data2" == content.split(b"\r\n\r\n", 1)[-1]


async def test_write_payload_chunked(
    buf: Any, protocol: Any, transport: Any, loop: Any
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.enable_chunking()
    await msg.write(b"data")
    await msg.write_eof()

    assert b"4\r\ndata\r\n0\r\n\r\n" == buf


async def test_write_payload_chunked_multiple(
    buf: Any, protocol: Any, transport: Any, loop: Any
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.enable_chunking()
    await msg.write(b"data1")
    await msg.write(b"data2")
    await msg.write_eof()

    assert b"5\r\ndata1\r\n5\r\ndata2\r\n0\r\n\r\n" == buf


async def test_write_payload_length(protocol: Any, transport: Any, loop: Any) -> None:
    write = transport.write = mock.Mock()

    msg = http.StreamWriter(protocol, loop)
    msg.length = 2
    await msg.write(b"d")
    await msg.write(b"ata")
    await msg.write_eof()

    content = b"".join([c[1][0] for c in list(write.mock_calls)])
    assert b"da" == content.split(b"\r\n\r\n", 1)[-1]


async def test_write_payload_chunked_filter(
    protocol: Any, transport: Any, loop: Any
) -> None:
    write = transport.write = mock.Mock()

    msg = http.StreamWriter(protocol, loop)
    msg.enable_chunking()
    await msg.write(b"da")
    await msg.write(b"ta")
    await msg.write_eof()

    content = b"".join([c[1][0] for c in list(write.mock_calls)])
    assert content.endswith(b"2\r\nda\r\n2\r\nta\r\n0\r\n\r\n")


async def test_write_payload_chunked_filter_mutiple_chunks(
    protocol: Any, transport: Any, loop: Any
) -> None:
    write = transport.write = mock.Mock()
    msg = http.StreamWriter(protocol, loop)
    msg.enable_chunking()
    await msg.write(b"da")
    await msg.write(b"ta")
    await msg.write(b"1d")
    await msg.write(b"at")
    await msg.write(b"a2")
    await msg.write_eof()
    content = b"".join([c[1][0] for c in list(write.mock_calls)])
    assert content.endswith(
        b"2\r\nda\r\n2\r\nta\r\n2\r\n1d\r\n2\r\nat\r\n" b"2\r\na2\r\n0\r\n\r\n"
    )


async def test_write_payload_deflate_compression(
    protocol: Any, transport: Any, loop: Any
) -> None:

    COMPRESSED = b"x\x9cKI,I\x04\x00\x04\x00\x01\x9b"
    write = transport.write = mock.Mock()
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")
    await msg.write(b"data")
    await msg.write_eof()

    chunks = [c[1][0] for c in list(write.mock_calls)]
    assert all(chunks)
    content = b"".join(chunks)
    assert COMPRESSED == content.split(b"\r\n\r\n", 1)[-1]


async def test_write_payload_deflate_and_chunked(
    buf: Any, protocol: Any, transport: Any, loop: Any
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.enable_compression("deflate")
    msg.enable_chunking()

    await msg.write(b"da")
    await msg.write(b"ta")
    await msg.write_eof()

    thing = b"2\r\nx\x9c\r\n" b"a\r\nKI,I\x04\x00\x04\x00\x01\x9b\r\n" b"0\r\n\r\n"
    assert thing == buf


async def test_write_payload_bytes_memoryview(
    buf: Any, protocol: Any, transport: Any, loop: Any
) -> None:

    msg = http.StreamWriter(protocol, loop)

    mv = memoryview(b"abcd")

    await msg.write(mv)
    await msg.write_eof()

    thing = b"abcd"
    assert thing == buf


async def test_write_payload_short_ints_memoryview(
    buf: Any, protocol: Any, transport: Any, loop: Any
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.enable_chunking()

    payload = memoryview(array.array("H", [65, 66, 67]))

    await msg.write(payload)
    await msg.write_eof()

    endians = (
        (b"6\r\n" b"\x00A\x00B\x00C\r\n" b"0\r\n\r\n"),
        (b"6\r\n" b"A\x00B\x00C\x00\r\n" b"0\r\n\r\n"),
    )
    assert buf in endians


async def test_write_payload_2d_shape_memoryview(
    buf: Any, protocol: Any, transport: Any, loop: Any
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.enable_chunking()

    mv = memoryview(b"ABCDEF")
    payload = mv.cast("c", [3, 2])

    await msg.write(payload)
    await msg.write_eof()

    thing = b"6\r\n" b"ABCDEF\r\n" b"0\r\n\r\n"
    assert thing == buf


async def test_write_payload_slicing_long_memoryview(
    buf: Any, protocol: Any, transport: Any, loop: Any
) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.length = 4

    mv = memoryview(b"ABCDEF")
    payload = mv.cast("c", [3, 2])

    await msg.write(payload)
    await msg.write_eof()

    thing = b"ABCD"
    assert thing == buf


async def test_write_drain(protocol: Any, transport: Any, loop: Any) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg.drain = make_mocked_coro()
    await msg.write(b"1" * (64 * 1024 * 2), drain=False)
    assert not msg.drain.called

    await msg.write(b"1", drain=True)
    assert msg.drain.called
    assert msg.buffer_size == 0


async def test_write_calls_callback(protocol: Any, transport: Any, loop: Any) -> None:
    on_chunk_sent = make_mocked_coro()
    msg = http.StreamWriter(protocol, loop, on_chunk_sent=on_chunk_sent)
    chunk = b"1"
    await msg.write(chunk)
    assert on_chunk_sent.called
    assert on_chunk_sent.call_args == mock.call(chunk)


async def test_write_eof_calls_callback(
    protocol: Any, transport: Any, loop: Any
) -> None:
    on_chunk_sent = make_mocked_coro()
    msg = http.StreamWriter(protocol, loop, on_chunk_sent=on_chunk_sent)
    chunk = b"1"
    await msg.write_eof(chunk=chunk)
    assert on_chunk_sent.called
    assert on_chunk_sent.call_args == mock.call(chunk)


async def test_write_to_closing_transport(
    protocol: Any, transport: Any, loop: Any
) -> None:
    msg = http.StreamWriter(protocol, loop)

    await msg.write(b"Before closing")
    transport.is_closing.return_value = True

    with pytest.raises(ConnectionResetError):
        await msg.write(b"After closing")


async def test_drain(protocol: Any, transport: Any, loop: Any) -> None:
    msg = http.StreamWriter(protocol, loop)
    await msg.drain()
    assert protocol._drain_helper.called


async def test_drain_no_transport(protocol: Any, transport: Any, loop: Any) -> None:
    msg = http.StreamWriter(protocol, loop)
    msg._protocol.transport = None
    await msg.drain()
    assert not protocol._drain_helper.called


async def test_write_headers_prevents_injection(
    protocol: Any, transport: Any, loop: Any
) -> None:
    msg = http.StreamWriter(protocol, loop)
    status_line = "HTTP/1.1 200 OK"
    wrong_headers = CIMultiDict({"Set-Cookie: abc=123\r\nContent-Length": "256"})
    with pytest.raises(ValueError):
        await msg.write_headers(status_line, wrong_headers)
    wrong_headers = CIMultiDict({"Content-Length": "256\r\nSet-Cookie: abc=123"})
    with pytest.raises(ValueError):
        await msg.write_headers(status_line, wrong_headers)
