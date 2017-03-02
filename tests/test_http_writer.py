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
    return transport


@pytest.fixture
def stream(transport):
    stream = mock.Mock(transport=transport)

    def acquire(writer):
        writer.set_transport(transport)

    stream.acquire = acquire
    stream.drain.return_value = ()
    return stream


def test_write_payload_eof(stream, loop):
    write = stream.transport.write = mock.Mock()
    msg = http.PayloadWriter(stream, loop)

    msg.write(b'data1')
    msg.write(b'data2')
    msg.write_eof()

    content = b''.join([c[1][0] for c in list(write.mock_calls)])
    assert b'data1data2' == content.split(b'\r\n\r\n', 1)[-1]


@asyncio.coroutine
def test_write_payload_chunked(buf, stream, loop):
    msg = http.PayloadWriter(stream, loop)
    msg.enable_chunking()
    msg.write(b'data')
    yield from msg.write_eof()

    assert b'4\r\ndata\r\n0\r\n\r\n' == buf


@asyncio.coroutine
def test_write_payload_chunked_multiple(buf, stream, loop):
    msg = http.PayloadWriter(stream, loop)
    msg.enable_chunking()
    msg.write(b'data1')
    msg.write(b'data2')
    yield from msg.write_eof()

    assert b'5\r\ndata1\r\n5\r\ndata2\r\n0\r\n\r\n' == buf


@asyncio.coroutine
def test_write_payload_length(stream, loop):
    write = stream.transport.write = mock.Mock()

    msg = http.PayloadWriter(stream, loop)
    msg.length = 2
    msg.write(b'd')
    msg.write(b'ata')
    yield from msg.write_eof()

    content = b''.join([c[1][0] for c in list(write.mock_calls)])
    assert b'da' == content.split(b'\r\n\r\n', 1)[-1]


@asyncio.coroutine
def test_write_payload_chunked_filter(stream, loop):
    write = stream.transport.write = mock.Mock()

    msg = http.PayloadWriter(stream, loop)
    msg.enable_chunking()
    msg.write(b'da')
    msg.write(b'ta')
    yield from msg.write_eof()

    content = b''.join([c[1][0] for c in list(write.mock_calls)])
    assert content.endswith(b'2\r\nda\r\n2\r\nta\r\n0\r\n\r\n')


@asyncio.coroutine
def test_write_payload_chunked_filter_mutiple_chunks(stream, loop):
    write = stream.transport.write = mock.Mock()
    msg = http.PayloadWriter(stream, loop)
    msg.enable_chunking()
    msg.write(b'da')
    msg.write(b'ta')
    msg.write(b'1d')
    msg.write(b'at')
    msg.write(b'a2')
    yield from msg.write_eof()
    content = b''.join([c[1][0] for c in list(write.mock_calls)])
    assert content.endswith(
        b'2\r\nda\r\n2\r\nta\r\n2\r\n1d\r\n2\r\nat\r\n'
        b'2\r\na2\r\n0\r\n\r\n')


compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
COMPRESSED = b''.join([compressor.compress(b'data'), compressor.flush()])


@asyncio.coroutine
def test_write_payload_deflate_compression(stream, loop):
    write = stream.transport.write = mock.Mock()
    msg = http.PayloadWriter(stream, loop)
    msg.enable_compression('deflate')
    msg.write(b'data')
    yield from msg.write_eof()

    chunks = [c[1][0] for c in list(write.mock_calls)]
    assert all(chunks)
    content = b''.join(chunks)
    assert COMPRESSED == content.split(b'\r\n\r\n', 1)[-1]


@asyncio.coroutine
def test_write_payload_deflate_and_chunked(buf, stream, loop):
    msg = http.PayloadWriter(stream, loop)
    msg.enable_compression('deflate')
    msg.enable_chunking()

    msg.write(b'da')
    msg.write(b'ta')
    yield from msg.write_eof()

    assert b'6\r\nKI,I\x04\x00\r\n0\r\n\r\n' == buf


def test_write_drain(stream, loop):
    msg = http.PayloadWriter(stream, loop)
    msg.drain = mock.Mock()
    msg.write(b'1' * (64 * 1024 * 2), drain=False)
    assert not msg.drain.called

    msg.write(b'1', drain=True)
    assert msg.drain.called
    assert msg.buffer_size == 0
