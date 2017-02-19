"""Tests for aiohttp/server.py"""

import asyncio
import socket
from functools import partial
from html import escape
from unittest import mock

import pytest

from aiohttp import helpers, server, streams


@pytest.yield_fixture
def make_srv(loop):
    srv = None

    def maker(cls=server.ServerHttpProtocol, **kwargs):
        nonlocal srv
        srv = cls(loop=loop, access_log=None, **kwargs)
        return srv

    yield maker
    if srv is not None:
        srv.connection_lost(None)


@pytest.fixture
def srv(make_srv):
    return make_srv()


@pytest.fixture
def writer():
    writer = mock.Mock()

    def acquire(cb):
        cb(writer)

    writer.acquire = acquire
    writer.drain.return_value = ()
    return writer


@pytest.yield_fixture
def transport():
    transport = mock.Mock()

    buf = bytearray()

    def acquire(cb):
        cb(transport)

    def write(chunk):
        buf.extend(chunk)

    transport.acquire.side_effect = acquire
    transport.write.side_effect = write
    transport.transport.write.side_effect = write
    transport.drain.return_value = ()

    return (transport, buf)


@asyncio.coroutine
def test_handle_request(srv, writer):
    transport = mock.Mock()
    srv.connection_made(transport)
    srv.writer = writer

    message = mock.Mock()
    message.headers = []
    message.version = (1, 1)
    yield from srv.handle_request(message, mock.Mock())

    content = b''.join(
        [c[1][0] for c in list(srv.writer.transport.write.mock_calls)])
    assert content.startswith(b'HTTP/1.1 404 Not Found\r\n')


@asyncio.coroutine
def test_shutdown(srv, loop):
    transport = mock.Mock()
    transport.close.side_effect = partial(srv.connection_lost, None)
    transport.drain.side_effect = []
    srv.connection_made(transport)
    assert transport is srv.transport

    yield from asyncio.sleep(0, loop=loop)

    srv.data_received(
        b'GET / HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 0\r\n\r\n')

    srv._keepalive = True

    request_handler = srv._request_handlers[-1]

    yield from asyncio.sleep(0.1, loop=loop)

    t0 = loop.time()
    yield from srv.shutdown()
    t1 = loop.time()

    assert t1 - t0 < 0.05, t1-t0

    assert transport.close.called
    assert srv.transport is None

    assert not srv._request_handlers
    assert request_handler.done()


@asyncio.coroutine
def test_double_shutdown(srv):
    transport = srv.transport = mock.Mock()
    transport.close.side_effect = partial(srv.connection_lost, None)
    srv.connection_made(transport)
    srv.writer = mock.Mock()

    yield from srv.shutdown()
    assert transport.close.called
    assert srv.transport is None

    transport.reset_mock()
    yield from srv.shutdown()
    assert not transport.close.called
    assert srv.transport is None


def test_connection_made(srv):
    assert not srv._request_handlers

    srv.connection_made(mock.Mock())
    assert not srv._request_handlers
    assert not srv._closing


def test_connection_made_with_keepaplive(srv):
    sock = mock.Mock()
    transport = mock.Mock()
    transport.get_extra_info.return_value = sock
    srv.connection_made(transport)
    sock.setsockopt.assert_called_with(socket.SOL_SOCKET,
                                       socket.SO_KEEPALIVE, 1)


def test_connection_made_without_keepaplive(make_srv):
    srv = make_srv(tcp_keepalive=False)

    sock = mock.Mock()
    transport = mock.Mock()
    transport.get_extra_info.return_value = sock
    srv.connection_made(transport)
    assert not sock.setsockopt.called


def _test_data_received(srv):
    srv.connection_made(mock.Mock())

    srv.data_received(b'123')
    assert b'123' == srv._message_tail

    srv.data_received(b'456')
    assert b'123456' == srv._message_tail


def test_eof_received(srv):
    srv.connection_made(mock.Mock())
    srv.eof_received()
    # assert srv.reader._eof


@asyncio.coroutine
def test_connection_lost(srv, loop):
    srv.connection_made(mock.Mock())

    srv.data_received(
        b'GET / HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 0\r\n\r\n')
    srv._keepalive = True

    handle = srv._request_handlers[0]
    yield from asyncio.sleep(0, loop=loop)  # wait for .start() starting
    srv.connection_lost(None)

    assert srv._closing

    yield from handle

    assert not srv._request_handlers


def test_srv_keep_alive(srv):
    assert not srv._keepalive

    srv.keep_alive(True)
    assert srv._keepalive

    srv.keep_alive(False)
    assert not srv._keepalive


def test_slow_request(make_srv):
    with pytest.warns(DeprecationWarning):
        make_srv(slow_request_timeout=0.01)


@asyncio.coroutine
def test_bad_method(srv, loop, transport):
    transport, buf = transport
    srv.connection_made(transport)

    srv.data_received(
        b'!@#$ / HTTP/1.0\r\n'
        b'Host: example.com\r\n\r\n')
    handler = srv._request_handlers[0]

    yield from handler
    assert buf.startswith(b'HTTP/1.1 400 Bad Request\r\n')


@asyncio.coroutine
def test_line_too_long(srv, loop, transport):
    transport, buf = transport
    srv.connection_made(transport)
    srv.data_received(b''.join([b'a' for _ in range(10000)]) + b'\r\n\r\n')

    handler = srv._request_handlers[0]
    yield from handler
    assert buf.startswith(b'HTTP/1.1 400 Bad Request\r\n')


@asyncio.coroutine
def test_invalid_content_length(srv, loop, transport):
    transport, buf = transport
    srv.connection_made(transport)

    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: sdgg\r\n\r\n')

    handler = srv._request_handlers[0]
    yield from handler

    assert buf.startswith(b'HTTP/1.1 400 Bad Request\r\n')


@asyncio.coroutine
def test_handle_error(srv, writer):
    transport = mock.Mock()
    srv.connection_made(transport)
    srv.keep_alive(True)
    srv.writer = writer

    yield from srv.handle_error(404, headers=(('X-Server', 'asyncio'),))
    content = b''.join(
        [c[1][0] for c in list(srv.writer.transport.write.mock_calls)])
    assert b'HTTP/1.1 404 Not Found' in content
    assert b'X-Server: asyncio' in content
    assert not srv._keepalive


@asyncio.coroutine
def test_handle_error__utf(make_srv, writer):
    transport = mock.Mock()
    srv = make_srv(debug=True)
    srv.connection_made(transport)
    srv.keep_alive(True)
    srv.writer = writer
    srv.logger = mock.Mock()

    try:
        raise RuntimeError('что-то пошло не так')
    except RuntimeError as exc:
        yield from srv.handle_error(exc=exc)

    content = b''.join(
        [c[1][0] for c in list(srv.writer.transport.write.mock_calls)])
    assert b'HTTP/1.1 500 Internal Server Error' in content
    assert b'Content-Type: text/html; charset=utf-8' in content
    pattern = escape("raise RuntimeError('что-то пошло не так')")
    assert pattern.encode('utf-8') in content
    assert not srv._keepalive

    srv.logger.exception.assert_called_with("Error handling request")


@asyncio.coroutine
def test_handle_error_traceback_exc(make_srv, transport):
    log = mock.Mock()
    srv = make_srv(debug=True, logger=log)
    stream, buf = transport
    srv.transport = stream
    srv.transport.get_extra_info.return_value = '127.0.0.1'
    srv.writer = stream
    srv._request_handlers.append(mock.Mock())

    with mock.patch('aiohttp.server.traceback') as m_trace:
        m_trace.format_exc.side_effect = ValueError

        yield from srv.handle_error(500, exc=object())

    assert buf.startswith(b'HTTP/1.1 500 Internal Server Error')
    assert log.exception.called


@asyncio.coroutine
def test_handle_error_debug(srv, writer):
    transport = mock.Mock()
    srv.debug = True
    srv.connection_made(transport)
    srv.writer = writer

    try:
        raise ValueError()
    except Exception as exc:
        yield from srv.handle_error(999, exc=exc)

    content = b''.join(
        [c[1][0] for c in list(srv.writer.transport.write.mock_calls)])

    assert b'HTTP/1.1 500 Internal' in content
    assert b'Traceback (most recent call last):' in content


@asyncio.coroutine
def test_handle_error_500(make_srv, loop, writer):
    log = mock.Mock()
    transport = mock.Mock()
    transport.drain.return_value = ()

    srv = make_srv(logger=log)
    srv.connection_made(transport)
    srv.writer = writer

    yield from srv.handle_error(500)
    assert log.exception.called


@asyncio.coroutine
def test_handle(srv, loop, transport):

    def get_mock_coro(return_value):
        @asyncio.coroutine
        def mock_coro(*args, **kwargs):
            return return_value
        return mock.Mock(wraps=mock_coro)

    transport, buf = transport
    srv.connection_made(transport)

    handle = srv.handle_request = get_mock_coro(return_value=None)

    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n\r\n')

    yield from srv._request_handlers[0]
    assert handle.called
    assert transport.close.called


@asyncio.coroutine
def test_handle_uncompleted(make_srv, loop, transport):
    transport, buf = transport
    closed = False

    def close():
        nonlocal closed
        closed = True

    transport.close = close

    srv = make_srv(lingering_timeout=0)

    srv.connection_made(transport)
    srv.logger.exception = mock.Mock()

    handle = srv.handle_request = mock.Mock()
    handle.side_effect = ValueError

    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 50000\r\n\r\n')

    yield from srv._request_handlers[0]
    assert handle.called
    assert closed
    srv.logger.exception.assert_called_with("Error handling request")


@pytest.mark.xfail
@asyncio.coroutine
def test_lingering(srv, loop):

    transport = mock.Mock()
    srv.connection_made(transport)

    yield from asyncio.sleep(0, loop=loop)
    assert not transport.close.called

    srv.reader.feed_data(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 3\r\n\r\n')

    yield from asyncio.sleep(0.1, loop=loop)
    assert not transport.close.called

    srv.reader.feed_data(b'123')
    srv.reader.feed_eof()

    yield from asyncio.sleep(0, loop=loop)
    transport.close.assert_called_with()


@pytest.mark.xfail
@asyncio.coroutine
def test_lingering_disabled(make_srv, loop):

    class Server(server.ServerHttpProtocol):

        def handle_request(self, message, payload):
            yield from payload.read()
            return super().handle_request(message, payload)

    srv = make_srv(Server, lingering_time=0)

    transport = mock.Mock()
    srv.connection_made(transport)

    yield from asyncio.sleep(0, loop=loop)
    assert not transport.close.called

    srv.reader.feed_data(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 50\r\n\r\n')

    srv.reader.feed_data(b'123')

    yield from asyncio.sleep(0, loop=loop)
    assert not transport.close.called
    srv.reader.feed_eof()
    yield from asyncio.sleep(0, loop=loop)
    transport.close.assert_called_with()


@pytest.mark.xfail
@asyncio.coroutine
def test_lingering_zero_timeout(make_srv, loop):

    class Server(server.ServerHttpProtocol):

        def handle_request(self, message, payload):
            yield from payload.read()
            return super().handle_request(message, payload)

    srv = make_srv(Server, lingering_time=1e-30)

    transport = mock.Mock()
    srv.connection_made(transport)

    yield from asyncio.sleep(0, loop=loop)
    assert not transport.close.called

    srv.reader.feed_data(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 50\r\n\r\n')

    srv.reader.feed_data(b'123')

    yield from asyncio.sleep(0, loop=loop)
    assert not transport.close.called
    srv.reader.feed_eof()

    yield from asyncio.sleep(0, loop=loop)
    transport.close.assert_called_with()


def test_handle_coro(srv, loop):
    transport = mock.Mock()

    called = False

    @asyncio.coroutine
    def coro(message, payload):
        nonlocal called
        called = True
        srv.eof_received()

    srv.handle_request = coro
    srv.connection_made(transport)

    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n\r\n')
    loop.run_until_complete(srv._request_handlers[0])
    assert called


def test_handle_cancel(make_srv, loop, transport):
    log = mock.Mock()
    transport, buf = transport

    srv = make_srv(logger=log, debug=True)
    srv.connection_made(transport)

    def handle_request(message, payload):
        yield from asyncio.sleep(10, loop=loop)

    srv.handle_request = handle_request

    @asyncio.coroutine
    def cancel():
        srv._request_handlers[0].cancel()

    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'Content-Length: 10\r\n'
        b'Host: example.com\r\n\r\n')

    loop.run_until_complete(
        asyncio.gather(srv._request_handlers[0], cancel(), loop=loop))
    assert log.debug.called


def test_handle_cancelled(make_srv, loop):
    log = mock.Mock()
    transport = mock.Mock()

    srv = make_srv(logger=log, debug=True)
    srv.connection_made(transport)

    srv.handle_request = mock.Mock()
    # start request_handler task
    loop.run_until_complete(asyncio.sleep(0, loop=loop))

    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n\r\n')

    r_handler = srv._request_handlers[0]
    assert loop.run_until_complete(r_handler) is None


def test_handle_400(srv, loop):
    transport = mock.Mock()
    transport.drain.side_effect = []
    srv.connection_made(transport)
    srv.data_received(b'GET / HT/asd\r\n\r\n')

    loop.run_until_complete(srv._request_handlers[0])

    assert b'400 Bad Request' in srv.transport.write.call_args[0][0]


def test_handle_500(srv, loop):
    transport = mock.Mock()
    transport.drain.side_effect = []
    srv.connection_made(transport)

    handle = srv.handle_request = mock.Mock()
    handle.side_effect = ValueError

    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n\r\n')
    loop.run_until_complete(srv._request_handlers[0])

    assert b'500 Internal Server Error' in srv.transport.write.call_args[0][0]


@asyncio.coroutine
def test_handle_error_no_handle_task(srv):
    transport = mock.Mock()
    srv.keep_alive(True)
    srv.connection_made(transport)
    srv.connection_lost(None)

    yield from srv.handle_error(300)
    assert not srv._keepalive


def test_keep_alive(make_srv, loop):
    srv = make_srv(keepalive_timeout=0.1)
    transport = mock.Mock()
    closed = False

    def close():
        nonlocal closed
        closed = True
        srv.connection_lost(None)
        loop.stop()

    transport.close = close

    srv.connection_made(transport)

    handle = srv.handle_request = mock.Mock()
    handle.return_value = ()

    srv.data_received(
        b'GET / HTTP/1.1\r\n'
        b'CONNECTION: keep-alive\r\n'
        b'HOST: example.com\r\n\r\n')

    loop.run_forever()
    assert handle.called
    assert closed


def test_keep_alive_close_existing(make_srv, loop):
    transport = mock.Mock()
    srv = make_srv(keepalive_timeout=15)
    srv.connection_made(transport)

    srv.handle_request = mock.Mock()
    srv.handle_request.return_value = helpers.create_future(loop)
    srv.handle_request.return_value.set_result(1)

    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'HOST: example.com\r\n\r\n')

    loop.run_until_complete(srv._request_handlers[0])
    assert transport.close.called


def test_srv_process_request_without_timeout(make_srv, loop):
    transport = mock.Mock()
    srv = make_srv()
    srv.connection_made(transport)

    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n\r\n')

    loop.run_until_complete(srv._request_handlers[0])
    assert transport.close.called


def test_keep_alive_timeout_default(srv):
    assert 75 == srv.keepalive_timeout


def test_keep_alive_timeout_nondefault(make_srv):
    srv = make_srv(keepalive_timeout=10)
    assert 10 == srv.keepalive_timeout


@asyncio.coroutine
def test_supports_connect_method(srv, loop):
    transport = mock.Mock()
    srv.connection_made(transport)

    with mock.patch.object(srv, 'handle_request') as m_handle_request:
        srv.data_received(
            b'CONNECT aiohttp.readthedocs.org:80 HTTP/1.0\r\n'
            b'Content-Length: 0\r\n\r\n')
        yield from asyncio.sleep(0.1, loop=loop)

        srv.connection_lost(None)
        yield from asyncio.sleep(0.05, loop=loop)

        assert m_handle_request.called
        assert isinstance(
            m_handle_request.call_args[0][1], streams.FlowControlStreamReader)


def test_content_length_0(srv, loop):
    transport = mock.Mock()
    srv.connection_made(transport)

    with mock.patch.object(srv, 'handle_request') as m_handle_request:
        srv.data_received(
            b'GET / HTTP/1.1\r\n'
            b'Host: example.org\r\n'
            b'Content-Length: 0\r\n\r\n')

        loop.run_until_complete(srv._request_handlers[0])

    assert m_handle_request.called
    assert m_handle_request.call_args[0] == (mock.ANY, streams.EMPTY_PAYLOAD)


def test_rudimentary_transport(srv, loop):
    transport = mock.Mock()
    srv.connection_made(transport)

    srv.pause_reading()
    assert srv._reading_paused
    assert transport.pause_reading.called

    srv.resume_reading()
    assert not srv._reading_paused
    assert transport.resume_reading.called

    transport.resume_reading.side_effect = NotImplementedError()
    transport.pause_reading.side_effect = NotImplementedError()

    srv._reading_paused = False
    srv.pause_reading()
    assert srv._reading_paused

    srv.resume_reading()
    assert not srv._reading_paused
