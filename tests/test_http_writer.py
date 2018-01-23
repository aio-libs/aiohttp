"""Tests for aiohttp/http_writer.py"""
import asyncio
import zlib
from unittest import mock

import pytest

from aiohttp import http


@pytest.fixture
def buf():
    return bytearray()


@pytest.fixture
def transport(buf):
    transport = mock.Mock()

    def write(chunk):
        buf.extend(chunk)

    transport.write.side_effect = write
    transport.is_closing.return_value = False
    return transport


@pytest.fixture
def protocol(loop, transport):
    protocol = mock.Mock(transport=transport)
    protocol._drain_helper.return_value = loop.create_future()
    protocol._drain_helper.return_value.set_result(None)
    return protocol


def test_payloadwriter_properties(transport, protocol, loop):
    writer = http.StreamWriter(protocol, transport, loop)
    assert writer.protocol == protocol
    assert writer.transport == transport


async def test_write_payload_eof(transport, protocol, loop):
    write = transport.write = mock.Mock()
    msg = http.StreamWriter(protocol, transport, loop)

    msg.write(b'data1')
    msg.write(b'data2')
    await msg.write_eof()

    content = b''.join([c[1][0] for c in list(write.mock_calls)])
    assert b'data1data2' == content.split(b'\r\n\r\n', 1)[-1]


async def test_write_payload_chunked(buf, protocol, transport, loop):
    msg = http.StreamWriter(protocol, transport, loop)
    msg.enable_chunking()
    msg.write(b'data')
    await msg.write_eof()

    assert b'4\r\ndata\r\n0\r\n\r\n' == buf


async def test_write_payload_chunked_multiple(buf, protocol, transport, loop):
    msg = http.StreamWriter(protocol, transport, loop)
    msg.enable_chunking()
    msg.write(b'data1')
    msg.write(b'data2')
    await msg.write_eof()

    assert b'5\r\ndata1\r\n5\r\ndata2\r\n0\r\n\r\n' == buf


async def test_write_payload_length(protocol, transport, loop):
    write = transport.write = mock.Mock()

    msg = http.StreamWriter(protocol, transport, loop)
    msg.length = 2
    msg.write(b'd')
    msg.write(b'ata')
    await msg.write_eof()

    content = b''.join([c[1][0] for c in list(write.mock_calls)])
    assert b'da' == content.split(b'\r\n\r\n', 1)[-1]


async def test_write_payload_chunked_filter(protocol, transport, loop):
    write = transport.write = mock.Mock()

    msg = http.StreamWriter(protocol, transport, loop)
    msg.enable_chunking()
    msg.write(b'da')
    msg.write(b'ta')
    await msg.write_eof()

    content = b''.join([c[1][0] for c in list(write.mock_calls)])
    assert content.endswith(b'2\r\nda\r\n2\r\nta\r\n0\r\n\r\n')


async def test_write_payload_chunked_filter_mutiple_chunks(
        protocol,
        transport,
        loop):
    write = transport.write = mock.Mock()
    msg = http.StreamWriter(protocol, transport, loop)
    msg.enable_chunking()
    msg.write(b'da')
    msg.write(b'ta')
    msg.write(b'1d')
    msg.write(b'at')
    msg.write(b'a2')
    await msg.write_eof()
    content = b''.join([c[1][0] for c in list(write.mock_calls)])
    assert content.endswith(
        b'2\r\nda\r\n2\r\nta\r\n2\r\n1d\r\n2\r\nat\r\n'
        b'2\r\na2\r\n0\r\n\r\n')


compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
COMPRESSED = b''.join([compressor.compress(b'data'), compressor.flush()])


async def test_write_payload_deflate_compression(protocol, transport, loop):
    write = transport.write = mock.Mock()
    msg = http.StreamWriter(protocol, transport, loop)
    msg.enable_compression('deflate')
    msg.write(b'data')
    await msg.write_eof()

    chunks = [c[1][0] for c in list(write.mock_calls)]
    assert all(chunks)
    content = b''.join(chunks)
    assert COMPRESSED == content.split(b'\r\n\r\n', 1)[-1]


async def test_write_payload_deflate_and_chunked(
        buf,
        protocol,
        transport,
        loop):
    msg = http.StreamWriter(protocol, transport, loop)
    msg.enable_compression('deflate')
    msg.enable_chunking()

    msg.write(b'da')
    msg.write(b'ta')
    await msg.write_eof()

    assert b'6\r\nKI,I\x04\x00\r\n0\r\n\r\n' == buf


def test_write_drain(protocol, transport, loop):
    msg = http.StreamWriter(protocol, transport, loop)
    msg.drain = mock.Mock()
    msg.write(b'1' * (64 * 1024 * 2), drain=False)
    assert not msg.drain.called

    msg.write(b'1', drain=True)
    assert msg.drain.called
    assert msg.buffer_size == 0


def test_write_to_closing_transport(protocol, transport, loop):
    msg = http.StreamWriter(protocol, transport, loop)

    msg.write(b'Before closing')
    transport.is_closing.return_value = True

    with pytest.raises(asyncio.CancelledError):
        msg.write(b'After closing')


async def test_drain(protocol, transport, loop):
    msg = http.StreamWriter(protocol, transport, loop)
    await msg.drain()
    assert protocol._drain_helper.called


async def test_drain_no_transport(protocol, transport, loop):
    msg = http.StreamWriter(protocol, transport, loop)
    msg._protocol.transport = None
    await msg.drain()
    assert not protocol._drain_helper.called
