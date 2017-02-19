"""Tests for aiohttp/http_message.py"""

import asyncio
import zlib
from unittest import mock

import pytest

from aiohttp import hdrs, http


@pytest.fixture
def stream():
    stream = mock.Mock()

    def acquire(cb):
        cb(stream)

    stream.acquire = acquire
    stream.drain.return_value = ()
    return stream


compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
COMPRESSED = b''.join([compressor.compress(b'data'), compressor.flush()])


def test_start_request(stream, loop):
    msg = http.Request(
        stream, 'GET', '/index.html', close=True, loop=loop)

    assert msg._transport is stream.transport
    assert msg.closing
    assert msg.status_line == 'GET /index.html HTTP/1.1\r\n'


def test_start_response_with_reason(stream, loop):
    msg = http.Response(stream, 333, close=True, reason="My Reason", loop=loop)

    assert msg.status == 333
    assert msg.reason == "My Reason"
    assert msg.status_line == 'HTTP/1.1 333 My Reason\r\n'


def test_start_response_with_unknown_reason(stream, loop):
    msg = http.Response(stream, 777, close=True, loop=loop)

    assert msg.status == 777
    assert msg.reason == ""
    assert msg.status_line == 'HTTP/1.1 777 \r\n'


def test_force_close(stream, loop):
    msg = http.Response(stream, 200, loop=loop)
    assert not msg.closing
    msg.force_close()
    assert msg.closing


def test_force_chunked(stream, loop):
    msg = http.Response(stream, 200, loop=loop)
    assert not msg.chunked
    msg.enable_chunking()
    assert msg.chunked


def test_keep_alive(stream, loop):
    msg = http.Response(stream, 200, close=True, loop=loop)
    assert not msg.keep_alive()
    msg.keepalive = True
    assert msg.keep_alive()

    msg.force_close()
    assert not msg.keep_alive()


def test_keep_alive_http10(stream, loop):
    msg = http.Response(stream, 200, http_version=(1, 0), loop=loop)
    assert not msg.keepalive
    assert not msg.keep_alive()

    msg = http.Response(stream, 200, http_version=(1, 1), loop=loop)
    assert msg.keepalive is None


def test_http_message_keepsalive(stream, loop):
    msg = http.Response(stream, 200, http_version=(0, 9), loop=loop)
    assert not msg.keep_alive()

    msg = http.Response(stream, 200, http_version=(1, 0), loop=loop)
    assert not msg.keep_alive()

    msg = http.Response(stream, 200, http_version=(1, 0), loop=loop)
    msg.headers[hdrs.CONNECTION] = 'keep-alive'
    assert msg.keep_alive()

    msg = http.Response(
        stream, 200, http_version=(1, 1), close=False, loop=loop)
    assert msg.keep_alive()
    msg = http.Response(
        stream, 200, http_version=(1, 1), close=True, loop=loop)
    assert not msg.keep_alive()

    msg = http.Response(stream, 200, http_version=(0, 9), loop=loop)
    msg.keepalive = True
    assert msg.keep_alive()


def test_add_header(stream, loop):
    msg = http.Response(stream, 200, loop=loop)
    assert [] == list(msg.headers)

    msg.add_header('content-type', 'plain/html')
    assert [('Content-Type', 'plain/html')] == list(msg.headers.items())


def test_add_header_with_spaces(stream, loop):
    msg = http.Response(stream, 200, loop=loop)
    assert [] == list(msg.headers)

    msg.add_header('content-type', '  plain/html  ')
    assert [('Content-Type', 'plain/html')] == list(msg.headers.items())


def test_add_header_non_ascii(stream, loop):
    msg = http.Response(stream, 200, loop=loop)
    assert [] == list(msg.headers)

    with pytest.raises(AssertionError):
        msg.add_header('тип-контента', 'текст/плейн')


def test_add_header_invalid_value_type(stream, loop):
    msg = http.Response(stream, 200, loop=loop)
    assert [] == list(msg.headers)

    with pytest.raises(AssertionError):
        msg.add_header('content-type', {'test': 'plain'})

    with pytest.raises(AssertionError):
        msg.add_header(list('content-type'), 'text/plain')


def test_add_headers(stream, loop):
    msg = http.Response(stream, 200, loop=loop)
    assert [] == list(msg.headers)

    msg.add_headers(('content-type', 'plain/html'))
    assert [('Content-Type', 'plain/html')] == list(msg.headers.items())


def test_add_headers_length(stream, loop):
    msg = http.Response(stream, 200, loop=loop)
    assert msg.length is None

    msg.add_headers(('content-length', '42'))
    assert 42 == msg.length


def test_add_headers_upgrade(stream, loop):
    msg = http.Response(stream, 200, loop=loop)
    assert not msg.upgrade

    msg.add_headers(('connection', 'upgrade'))
    assert msg.upgrade


def test_add_headers_upgrade_websocket(stream, loop):
    msg = http.Response(stream, 200, loop=loop)
    msg.add_headers(('upgrade', 'test'))
    assert not msg.websocket
    assert [('Upgrade', 'test')] == list(msg.headers.items())

    msg = http.Response(stream, 200, loop=loop)
    msg.add_headers(('upgrade', 'websocket'))
    assert msg.websocket
    assert [('Upgrade', 'websocket')] == list(msg.headers.items())


def test_add_headers_connection_keepalive(stream, loop):
    msg = http.Response(stream, 200, loop=loop)

    msg.add_headers(('connection', 'keep-alive'))
    assert [] == list(msg.headers)
    assert msg.keepalive

    msg.add_headers(('connection', 'close'))
    assert not msg.keepalive


def test_add_headers_hop_headers(stream, loop):
    msg = http.Response(stream, 200, loop=loop)
    msg.HOP_HEADERS = (hdrs.TRANSFER_ENCODING,)

    msg.add_headers(('connection', 'test'), ('transfer-encoding', 't'))
    assert [] == list(msg.headers)


def test_default_headers_http_10(stream, loop):
    msg = http.Response(stream, 200,
                        http_version=http.HttpVersion10, loop=loop)
    msg._add_default_headers()

    assert 'DATE' in msg.headers
    assert 'keep-alive' == msg.headers['CONNECTION']


def test_default_headers_http_11(stream, loop):
    msg = http.Response(stream, 200, loop=loop)
    msg._add_default_headers()

    assert 'DATE' in msg.headers
    assert 'CONNECTION' not in msg.headers


def test_default_headers_server(stream, loop):
    msg = http.Response(stream, 200, loop=loop)
    msg._add_default_headers()

    assert 'SERVER' in msg.headers


def test_default_headers_chunked(stream, loop):
    msg = http.Response(stream, 200, loop=loop)
    msg._add_default_headers()

    assert 'TRANSFER-ENCODING' not in msg.headers

    msg = http.Response(stream, 200, loop=loop)
    msg.enable_chunking()
    msg.send_headers()

    assert 'TRANSFER-ENCODING' in msg.headers


def test_default_headers_connection_upgrade(stream, loop):
    msg = http.Response(stream, 200, loop=loop)
    msg.upgrade = True
    msg._add_default_headers()

    assert msg.headers['Connection'] == 'Upgrade'


def test_default_headers_connection_close(stream, loop):
    msg = http.Response(stream, 200, loop=loop)
    msg.force_close()
    msg._add_default_headers()

    assert msg.headers['Connection'] == 'close'


def test_default_headers_connection_keep_alive_http_10(stream, loop):
    msg = http.Response(stream, 200,
                        http_version=http.HttpVersion10, loop=loop)
    msg.keepalive = True
    msg._add_default_headers()

    assert msg.headers['Connection'] == 'keep-alive'


def test_default_headers_connection_keep_alive_11(stream, loop):
    msg = http.Response(stream, 200,
                        http_version=http.HttpVersion11, loop=loop)
    msg.keepalive = True
    msg._add_default_headers()

    assert 'Connection' not in msg.headers


def test_send_headers(stream, loop):
    msg = http.Response(stream, 200, loop=loop)
    msg.add_headers(('content-type', 'plain/html'))
    assert not msg.is_headers_sent()

    msg.send_headers()

    content = b''.join(msg._buffer)
    assert content.startswith(b'HTTP/1.1 200 OK\r\n')
    assert b'Content-Type: plain/html' in content
    assert msg.headers_sent
    assert msg.is_headers_sent()


def test_send_headers_non_ascii(stream, loop):
    msg = http.Response(stream, 200, loop=loop)
    msg.add_headers(('x-header', 'текст'))
    assert not msg.is_headers_sent()

    msg.send_headers()

    content = b''.join(msg._buffer)

    assert content.startswith(b'HTTP/1.1 200 OK\r\n')
    assert b'X-Header: \xd1\x82\xd0\xb5\xd0\xba\xd1\x81\xd1\x82' in content
    assert msg.headers_sent
    assert msg.is_headers_sent()


def test_send_headers_nomore_add(stream, loop):
    msg = http.Response(stream, 200, loop=loop)
    msg.add_headers(('content-type', 'plain/html'))
    msg.send_headers()

    with pytest.raises(AssertionError):
        msg.add_header('content-type', 'plain/html')


def test_prepare_length(stream, loop):
    msg = http.Response(stream, 200, loop=loop)
    msg.add_headers(('content-length', '42'))
    msg.send_headers()

    assert msg.length == 42


def test_prepare_chunked_force(stream, loop):
    msg = http.Response(stream, 200, loop=loop)
    msg.enable_chunking()
    msg.add_headers(('content-length', '42'))
    msg.send_headers()
    assert msg.chunked


def test_prepare_chunked_no_length(stream, loop):
    msg = http.Response(stream, 200, loop=loop)
    msg.send_headers()
    assert msg.chunked


def test_prepare_eof(stream, loop):
    msg = http.Response(stream, 200, http_version=(1, 0), loop=loop)
    msg.send_headers()
    assert msg.length is None


def test_write_auto_send_headers(stream, loop):
    msg = http.Response(stream, 200, http_version=(1, 0), loop=loop)
    msg.send_headers()
    msg.write(b'data1')
    assert msg.headers_sent


def test_write_payload_eof(stream, loop):
    write = stream.transport.write = mock.Mock()
    msg = http.Response(stream, 200, http_version=(1, 0), loop=loop)
    msg.send_headers()

    msg.write(b'data1')
    assert msg.headers_sent

    msg.write(b'data2')
    msg.write_eof()

    content = b''.join([c[1][0] for c in list(write.mock_calls)])
    assert b'data1data2' == content.split(b'\r\n\r\n', 1)[-1]


@asyncio.coroutine
def test_write_payload_chunked(stream, loop):
    write = stream.transport.write = mock.Mock()

    msg = http.Response(stream, 200, loop=loop)
    msg.enable_chunking()
    msg.send_headers()

    msg.write(b'data')
    yield from msg.write_eof()

    content = b''.join([c[1][0] for c in list(write.mock_calls)])
    assert b'4\r\ndata\r\n0\r\n\r\n' == content.split(b'\r\n\r\n', 1)[-1]


@asyncio.coroutine
def test_write_payload_chunked_multiple(stream, loop):
    write = stream.transport.write = mock.Mock()

    msg = http.Response(stream, 200, loop=loop)
    msg.enable_chunking()
    msg.send_headers()

    msg.write(b'data1')
    msg.write(b'data2')
    yield from msg.write_eof()

    content = b''.join([c[1][0] for c in list(write.mock_calls)])
    assert (b'5\r\ndata1\r\n5\r\ndata2\r\n0\r\n\r\n' ==
            content.split(b'\r\n\r\n', 1)[-1])


@asyncio.coroutine
def test_write_payload_length(stream, loop):
    write = stream.transport.write = mock.Mock()

    msg = http.Response(stream, 200, loop=loop)
    msg.add_headers(('content-length', '2'))
    msg.send_headers()

    msg.write(b'd')
    msg.write(b'ata')
    yield from msg.write_eof()

    content = b''.join([c[1][0] for c in list(write.mock_calls)])
    assert b'da' == content.split(b'\r\n\r\n', 1)[-1]


@asyncio.coroutine
def test_write_payload_chunked_filter(stream, loop):
    write = stream.transport.write = mock.Mock()

    msg = http.Response(stream, 200, loop=loop)
    msg.send_headers()

    msg.enable_chunking()
    msg.write(b'da')
    msg.write(b'ta')
    yield from msg.write_eof()

    content = b''.join([c[1][0] for c in list(write.mock_calls)])
    assert content.endswith(b'2\r\nda\r\n2\r\nta\r\n0\r\n\r\n')


@asyncio.coroutine
def test_write_payload_chunked_filter_mutiple_chunks(stream, loop):
    write = stream.transport.write = mock.Mock()
    msg = http.Response(stream, 200, loop=loop)
    msg.send_headers()

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


@asyncio.coroutine
def test_write_payload_deflate_compression(stream, loop):
    write = stream.transport.write = mock.Mock()
    msg = http.Response(stream, 200, loop=loop)
    msg.add_headers(('content-length', '{}'.format(len(COMPRESSED))))
    msg.send_headers()

    msg.enable_compression('deflate')
    msg.write(b'data')
    yield from msg.write_eof()

    chunks = [c[1][0] for c in list(write.mock_calls)]
    assert all(chunks)
    content = b''.join(chunks)
    assert COMPRESSED == content.split(b'\r\n\r\n', 1)[-1]


@asyncio.coroutine
def test_write_payload_deflate_and_chunked(stream, loop):
    write = stream.transport.write = mock.Mock()
    msg = http.Response(stream, 200, loop=loop)
    msg.send_headers()

    msg.enable_compression('deflate')
    msg.enable_chunking()

    msg.write(b'da')
    msg.write(b'ta')
    yield from msg.write_eof()

    chunks = [c[1][0] for c in list(write.mock_calls)]
    assert all(chunks)
    content = b''.join(chunks)
    assert (b'6\r\nKI,I\x04\x00\r\n0\r\n\r\n' ==
            content.split(b'\r\n\r\n', 1)[-1])


def test_write_drain(stream, loop):
    msg = http.Response(stream, 200, http_version=(1, 0), loop=loop)
    msg.drain = mock.Mock()
    msg.send_headers()
    msg.write(b'1' * (64 * 1024 * 2), drain=False)
    assert not msg.drain.called

    msg.write(b'1', drain=True)
    assert msg.drain.called
    assert msg.buffer_size == 0


def test_dont_override_request_headers_with_default_values(stream, loop):
    msg = http.Request(
        stream, 'GET', '/index.html', close=True, loop=loop)
    msg.add_header('USER-AGENT', 'custom')
    msg._add_default_headers()
    assert 'custom' == msg.headers['USER-AGENT']


def test_dont_override_response_headers_with_default_values(stream, loop):
    msg = http.Response(stream, 200, http_version=(1, 0), loop=loop)
    msg.add_header('DATE', 'now')
    msg.add_header('SERVER', 'custom')
    msg._add_default_headers()
    assert 'custom' == msg.headers['SERVER']
    assert 'now' == msg.headers['DATE']


def test_request_close_from_version(stream, loop):
    msg = http.Request(stream, 'POST', '/', http_version=(0, 9), loop=loop)
    assert msg.closing
