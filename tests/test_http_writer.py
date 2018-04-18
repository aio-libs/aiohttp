"""Tests for aiohttp/http_writer.py"""
import asyncio
import zlib
from unittest import mock

import pytest

from aiohttp import http
from aiohttp.test_utils import make_mocked_coro
from tests.conftest import skip_if_no_brotli


try:
    import brotli
except ImportError:
    brotli = None


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
    protocol._drain_helper = make_mocked_coro()
    return protocol


def test_payloadwriter_properties(transport, protocol, loop):
    writer = http.StreamWriter(protocol, transport, loop)
    assert writer.protocol == protocol
    assert writer.transport == transport


async def test_write_payload_eof(transport, protocol, loop):
    write = transport.write = mock.Mock()
    msg = http.StreamWriter(protocol, transport, loop)

    await msg.write(b'data1')
    await msg.write(b'data2')
    await msg.write_eof()

    content = b''.join([c[1][0] for c in list(write.mock_calls)])
    assert b'data1data2' == content.split(b'\r\n\r\n', 1)[-1]


async def test_write_payload_chunked(buf, protocol, transport, loop):
    msg = http.StreamWriter(protocol, transport, loop)
    msg.enable_chunking()
    await msg.write(b'data')
    await msg.write_eof()

    assert b'4\r\ndata\r\n0\r\n\r\n' == buf


async def test_write_payload_chunked_multiple(buf, protocol, transport, loop):
    msg = http.StreamWriter(protocol, transport, loop)
    msg.enable_chunking()
    await msg.write(b'data1')
    await msg.write(b'data2')
    await msg.write_eof()

    assert b'5\r\ndata1\r\n5\r\ndata2\r\n0\r\n\r\n' == buf


async def test_write_payload_length(protocol, transport, loop):
    write = transport.write = mock.Mock()

    msg = http.StreamWriter(protocol, transport, loop)
    msg.length = 2
    await msg.write(b'd')
    await msg.write(b'ata')
    await msg.write_eof()

    content = b''.join([c[1][0] for c in list(write.mock_calls)])
    assert b'da' == content.split(b'\r\n\r\n', 1)[-1]


async def test_write_payload_chunked_filter(protocol, transport, loop):
    write = transport.write = mock.Mock()

    msg = http.StreamWriter(protocol, transport, loop)
    msg.enable_chunking()
    await msg.write(b'da')
    await msg.write(b'ta')
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
    await msg.write(b'da')
    await msg.write(b'ta')
    await msg.write(b'1d')
    await msg.write(b'at')
    await msg.write(b'a2')
    await msg.write_eof()
    content = b''.join([c[1][0] for c in list(write.mock_calls)])
    assert content.endswith(
        b'2\r\nda\r\n2\r\nta\r\n2\r\n1d\r\n2\r\nat\r\n'
        b'2\r\na2\r\n0\r\n\r\n')


def compress(encoding, *chunks):
    if encoding == 'gzip':
        obj = zlib.compressobj(wbits=16 + zlib.MAX_WBITS)
    elif encoding == 'deflate':
        obj = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    elif encoding == 'br':
        obj = brotli.Compressor()
    else:
        raise RuntimeError(encoding)
    out = []
    for chunk in chunks:
        out.append(obj.compress(chunk))
    if encoding == 'br':
        out.append(obj.finish())
    else:
        out.append(obj.flush())
    return out


@pytest.mark.parametrize('compression', [
    'deflate',
    'gzip',
    pytest.param('br', marks=skip_if_no_brotli)
])
async def test_write_payload_compression(protocol, transport, loop,
                                         compression):
    write = transport.write = mock.Mock()
    msg = http.StreamWriter(protocol, transport, loop)
    msg.enable_compression(compression)
    await msg.write(b'data')
    await msg.write_eof()

    chunks = [c[1][0] for c in list(write.mock_calls)]
    assert all(chunks)
    content = b''.join(chunks)
    expected_content = b''.join(compress(compression, b'data'))
    assert expected_content == content.split(b'\r\n\r\n', 1)[-1]


@pytest.mark.parametrize('compression', [
    'deflate',
    'gzip',
    pytest.param('br', marks=skip_if_no_brotli),
])
async def test_write_payload_compressed_and_chunked(
        buf,
        protocol,
        transport,
        loop,
        compression):
    msg = http.StreamWriter(protocol, transport, loop)
    msg.enable_compression(compression)
    msg.enable_chunking()

    await msg.write(b'da')
    await msg.write(b'ta')
    await msg.write_eof()

    parts = [p for chunk in compress(compression, b'da', b'ta')
             for p in [('%x' % len(chunk)).encode('ascii'), chunk]
             if chunk]
    assert b'\r\n'.join(parts) + b'\r\n0\r\n\r\n' == buf


async def test_write_drain(protocol, transport, loop):
    msg = http.StreamWriter(protocol, transport, loop)
    msg.drain = make_mocked_coro()
    await msg.write(b'1' * (64 * 1024 * 2), drain=False)
    assert not msg.drain.called

    await msg.write(b'1', drain=True)
    assert msg.drain.called
    assert msg.buffer_size == 0


async def test_write_calls_callback(protocol, transport, loop):
    on_chunk_sent = make_mocked_coro()
    msg = http.StreamWriter(
        protocol, transport, loop,
        on_chunk_sent=on_chunk_sent
    )
    chunk = b'1'
    await msg.write(chunk)
    assert on_chunk_sent.called
    assert on_chunk_sent.call_args == mock.call(chunk)


async def test_write_eof_calls_callback(protocol, transport, loop):
    on_chunk_sent = make_mocked_coro()
    msg = http.StreamWriter(
        protocol, transport, loop,
        on_chunk_sent=on_chunk_sent
    )
    chunk = b'1'
    await msg.write_eof(chunk=chunk)
    assert on_chunk_sent.called
    assert on_chunk_sent.call_args == mock.call(chunk)


async def test_write_to_closing_transport(protocol, transport, loop):
    msg = http.StreamWriter(protocol, transport, loop)

    await msg.write(b'Before closing')
    transport.is_closing.return_value = True

    with pytest.raises(asyncio.CancelledError):
        await msg.write(b'After closing')


async def test_drain(protocol, transport, loop):
    msg = http.StreamWriter(protocol, transport, loop)
    await msg.drain()
    assert protocol._drain_helper.called


async def test_drain_no_transport(protocol, transport, loop):
    msg = http.StreamWriter(protocol, transport, loop)
    msg._protocol.transport = None
    await msg.drain()
    assert not protocol._drain_helper.called
