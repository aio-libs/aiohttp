"""Tests for aiohttp/server.py"""

import asyncio
import socket
from functools import partial
from html import escape
from unittest import mock

import pytest

from aiohttp import helpers, http, server, streams


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
def srv(make_srv, transport):
    srv = make_srv()
    srv.connection_made(transport)
    transport.close.side_effect = partial(srv.connection_lost, None)
    return srv


@pytest.fixture
def buf():
    return bytearray()


@pytest.fixture
def handle_with_error():
    def wrapper(exc=ValueError):

        @asyncio.coroutine
        def handle(message, payload, writer):
            raise exc

        h = mock.Mock()
        h.side_effect = handle
        return h
    return wrapper


@pytest.yield_fixture
def writer(srv):
    return http.PayloadWriter(srv.writer, srv._loop)


@pytest.yield_fixture
def transport(buf):
    transport = mock.Mock()

    def write(chunk):
        buf.extend(chunk)

    transport.write.side_effect = write
    transport.drain.side_effect = helpers.noop

    return transport


@pytest.fixture
def ceil(mocker):
    def ceil(val):
        return val

    mocker.patch('aiohttp.helpers.ceil').side_effect = ceil


@asyncio.coroutine
def test_handle_request(srv, buf, writer):
    message = mock.Mock()
    message.headers = []
    message.version = (1, 1)
    yield from srv.handle_request(message, mock.Mock(), writer)

    content = bytes(buf)
    assert content.startswith(b'HTTP/1.1 404 Not Found\r\n')


@asyncio.coroutine
def test_shutdown(srv, loop, transport):
    srv.handle_request = mock.Mock()
    srv.handle_request.side_effect = helpers.noop

    assert transport is srv.transport

    srv._keepalive = True
    srv.data_received(
        b'GET / HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 0\r\n\r\n')

    request_handler = srv._request_handlers[-1]

    yield from asyncio.sleep(0.1, loop=loop)
    assert len(srv._waiters) == 1
    assert len(srv._request_handlers) == 1

    t0 = loop.time()
    yield from srv.shutdown()
    t1 = loop.time()

    assert t1 - t0 < 0.05, t1-t0

    assert transport.close.called
    assert srv.transport is None

    assert not srv._request_handlers
    assert request_handler.done()


@asyncio.coroutine
def test_shutdown_multiple_handlers(srv, loop, transport):
    srv.handle_request = mock.Mock()
    srv.handle_request.side_effect = helpers.noop

    assert transport is srv.transport

    srv._keepalive = True
    srv.data_received(
        b'GET / HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 0\r\n\r\n'
        b'GET / HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 0\r\n\r\n')

    h1, h2 = srv._request_handlers

    yield from asyncio.sleep(0.1, loop=loop)
    assert len(srv._waiters) == 2
    assert len(srv._request_handlers) == 2

    t0 = loop.time()
    yield from srv.shutdown()
    t1 = loop.time()

    assert t1 - t0 < 0.05, t1-t0

    assert transport.close.called
    assert srv.transport is None

    assert not srv._request_handlers
    assert h1.done()
    assert h2.done()


@asyncio.coroutine
def test_double_shutdown(srv, transport):
    yield from srv.shutdown()
    assert transport.close.called
    assert srv.transport is None

    transport.reset_mock()
    yield from srv.shutdown()
    assert not transport.close.called
    assert srv.transport is None


@asyncio.coroutine
def test_close_after_response(srv, loop, transport):
    srv.handle_request = mock.Mock()
    srv.handle_request.side_effect = helpers.noop
    srv._keepalive = False

    srv.data_received(
        b'GET / HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 0\r\n\r\n')
    h, = srv._request_handlers

    yield from asyncio.sleep(0.1, loop=loop)
    assert len(srv._waiters) == 0
    assert len(srv._request_handlers) == 0

    assert transport.close.called
    assert srv.transport is None

    assert not srv._request_handlers
    assert h.done()


def test_connection_made(make_srv):
    srv = make_srv()
    assert not srv._request_handlers

    srv.connection_made(mock.Mock())
    assert not srv._request_handlers
    assert not srv._force_close


def test_connection_made_with_keepaplive(make_srv, transport):
    srv = make_srv()

    sock = mock.Mock()
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


def test_eof_received(make_srv):
    srv = make_srv()
    srv.connection_made(mock.Mock())
    srv.eof_received()
    # assert srv.reader._eof


@asyncio.coroutine
def test_connection_lost(srv, loop):
    srv.data_received(
        b'GET / HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 0\r\n\r\n')
    srv._keepalive = True

    handle = srv._request_handlers[0]
    yield from asyncio.sleep(0, loop=loop)  # wait for .start() starting
    srv.connection_lost(None)

    assert srv._force_close

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
def test_bad_method(srv, loop, buf):
    srv.data_received(
        b'!@#$ / HTTP/1.0\r\n'
        b'Host: example.com\r\n\r\n')

    yield from asyncio.sleep(0, loop=loop)
    assert buf.startswith(b'HTTP/1.1 400 Bad Request\r\n')


@asyncio.coroutine
def test_internal_error(srv, loop, buf):
    srv._request_parser = mock.Mock()
    srv._request_parser.feed_data.side_effect = TypeError

    srv.data_received(
        b'!@#$ / HTTP/1.0\r\n'
        b'Host: example.com\r\n\r\n')

    yield from asyncio.sleep(0, loop=loop)
    assert buf.startswith(b'HTTP/1.1 500 Internal Server Error\r\n')


@asyncio.coroutine
def test_line_too_long(srv, loop, buf):
    srv.data_received(b''.join([b'a' for _ in range(10000)]) + b'\r\n\r\n')

    yield from asyncio.sleep(0, loop=loop)
    assert buf.startswith(b'HTTP/1.1 400 Bad Request\r\n')


@asyncio.coroutine
def test_invalid_content_length(srv, loop, buf):
    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: sdgg\r\n\r\n')
    yield from asyncio.sleep(0, loop=loop)

    assert buf.startswith(b'HTTP/1.1 400 Bad Request\r\n')


@asyncio.coroutine
def test_handle_error(srv, buf, writer):
    srv.keep_alive(True)

    yield from srv.handle_error(writer, 404)
    assert b'HTTP/1.1 404 Not Found' in buf
    assert not srv._keepalive


@asyncio.coroutine
def test_handle_error__utf(make_srv, buf, transport, writer):
    srv = make_srv(debug=True)
    srv.connection_made(transport)
    srv.keep_alive(True)
    srv.logger = mock.Mock()

    try:
        raise RuntimeError('что-то пошло не так')
    except RuntimeError as exc:
        yield from srv.handle_error(writer, exc=exc)

    assert b'HTTP/1.1 500 Internal Server Error' in buf
    assert b'Content-Type: text/html; charset=utf-8' in buf
    pattern = escape("raise RuntimeError('что-то пошло не так')")
    assert pattern.encode('utf-8') in buf
    assert not srv._keepalive

    srv.logger.exception.assert_called_with("Error handling request")


@asyncio.coroutine
def test_handle_error_traceback_exc(make_srv, buf, transport, writer):
    log = mock.Mock()
    srv = make_srv(debug=True, logger=log)
    srv.connection_made(transport)
    srv.transport.get_extra_info.return_value = '127.0.0.1'
    srv._request_handlers.append(mock.Mock())

    with mock.patch('aiohttp.server.traceback') as m_trace:
        m_trace.format_exc.side_effect = ValueError

        yield from srv.handle_error(writer, 500, exc=object())

    assert buf.startswith(b'HTTP/1.1 500 Internal Server Error')
    assert log.exception.called


@asyncio.coroutine
def test_handle_error_debug(srv, buf, writer):
    srv.debug = True

    try:
        raise ValueError()
    except Exception as exc:
        yield from srv.handle_error(writer, 999, exc=exc)

    assert b'HTTP/1.1 500 Internal' in buf
    assert b'Traceback (most recent call last):' in buf


@asyncio.coroutine
def test_handle_error_500(make_srv, loop, buf, transport, writer):
    log = mock.Mock()

    srv = make_srv(logger=log)
    srv.connection_made(transport)

    yield from srv.handle_error(writer, 500)
    assert log.exception.called


@asyncio.coroutine
def test_handle(srv, loop, transport):

    def get_mock_coro(return_value):
        @asyncio.coroutine
        def mock_coro(*args, **kwargs):
            return return_value
        return mock.Mock(wraps=mock_coro)

    srv.connection_made(transport)

    handle = srv.handle_request = get_mock_coro(return_value=None)

    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n\r\n')

    yield from srv._request_handlers[0]
    assert handle.called
    assert transport.close.called


@asyncio.coroutine
def test_handle_uncompleted(make_srv, loop, transport, handle_with_error):
    closed = False

    def close():
        nonlocal closed
        closed = True

    transport.close.side_effect = close

    srv = make_srv(lingering_timeout=0)
    srv.connection_made(transport)
    srv.logger.exception = mock.Mock()
    handle = srv.handle_request = handle_with_error()

    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 50000\r\n\r\n')

    yield from srv._request_handlers[0]
    assert handle.called
    assert closed
    srv.logger.exception.assert_called_with("Error handling request")


@asyncio.coroutine
def test_handle_uncompleted_pipe(make_srv, loop, transport, handle_with_error):
    closed = False
    normal_completed = False

    def close():
        nonlocal closed
        closed = True

    transport.close.side_effect = close

    srv = make_srv(lingering_timeout=0)
    srv.connection_made(transport)
    srv.logger.exception = mock.Mock()

    @asyncio.coroutine
    def handle(message, request, writer):
        nonlocal normal_completed
        normal_completed = True
        yield from asyncio.sleep(0.05, loop=loop)
        yield from writer.write_eof()

    # normal
    srv.handle_request = handle
    srv.data_received(
        b'GET / HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 0\r\n\r\n')
    yield from asyncio.sleep(0, loop=loop)

    # with exception
    handle = srv.handle_request = handle_with_error()
    srv.data_received(
        b'GET / HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 50000\r\n\r\n')

    assert len(srv._request_handlers) == 2

    yield from asyncio.sleep(0, loop=loop)

    yield from srv._request_handlers[0]
    assert normal_completed
    assert handle.called
    assert closed
    srv.logger.exception.assert_called_with("Error handling request")


@asyncio.coroutine
def test_lingering(srv, loop, transport):
    assert not transport.close.called

    @asyncio.coroutine
    def handle(message, request, writer):
        pass

    srv.handle_request = handle
    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 3\r\n\r\n')

    yield from asyncio.sleep(0.05, loop=loop)
    assert not transport.close.called

    srv.data_received(b'123')

    yield from asyncio.sleep(0, loop=loop)
    transport.close.assert_called_with()


@asyncio.coroutine
def test_lingering_disabled(make_srv, loop, transport):

    class Server(server.ServerHttpProtocol):

        @asyncio.coroutine
        def handle_request(self, message, payload, writer):
            yield from asyncio.sleep(0, loop=loop)

    srv = make_srv(Server, lingering_time=0)
    srv.connection_made(transport)

    yield from asyncio.sleep(0, loop=loop)
    assert not transport.close.called

    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 50\r\n\r\n')
    yield from asyncio.sleep(0, loop=loop)
    assert not transport.close.called
    yield from asyncio.sleep(0, loop=loop)
    transport.close.assert_called_with()


@asyncio.coroutine
def test_lingering_timeout(make_srv, loop, transport, ceil):

    class Server(server.ServerHttpProtocol):

        def handle_request(self, message, payload, writer):
            yield from asyncio.sleep(0, loop=loop)

    srv = make_srv(Server, lingering_time=1e-30)
    srv.connection_made(transport)

    yield from asyncio.sleep(0, loop=loop)
    assert not transport.close.called

    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 50\r\n\r\n')
    yield from asyncio.sleep(0, loop=loop)
    assert not transport.close.called

    yield from asyncio.sleep(0, loop=loop)
    transport.close.assert_called_with()


def test_handle_coro(srv, loop, transport):
    called = False

    @asyncio.coroutine
    def coro(message, payload, writer):
        nonlocal called
        called = True
        srv.eof_received()

    srv.handle_request = coro
    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n\r\n')
    loop.run_until_complete(srv._request_handlers[0])
    assert called


def test_handle_cancel(make_srv, loop, transport):
    log = mock.Mock()

    srv = make_srv(logger=log, debug=True)
    srv.connection_made(transport)

    def handle_request(message, payload, writer):
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


def test_handle_cancelled(make_srv, loop, transport):
    log = mock.Mock()

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


@asyncio.coroutine
def test_handle_400(srv, loop, buf, transport):
    srv.data_received(b'GET / HT/asd\r\n\r\n')

    yield from asyncio.sleep(0, loop=loop)
    assert b'400 Bad Request' in buf


def test_handle_500(srv, loop, buf, transport):
    handle = srv.handle_request = mock.Mock()
    handle.side_effect = ValueError

    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n\r\n')
    loop.run_until_complete(srv._request_handlers[0])

    assert b'500 Internal Server Error' in buf


@asyncio.coroutine
def test_handle_error_no_handle_task(srv, transport, writer):
    srv.keep_alive(True)
    srv.connection_lost(None)

    yield from srv.handle_error(writer, 300)
    assert not srv._keepalive


@asyncio.coroutine
def test_keep_alive(make_srv, loop, transport, ceil):
    srv = make_srv(keepalive_timeout=0.05)
    srv.connection_made(transport)

    srv.keep_alive(True)
    srv.handle_request = mock.Mock()
    srv.handle_request.return_value = helpers.create_future(loop)
    srv.handle_request.return_value.set_result(1)

    srv.data_received(
        b'GET / HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 0\r\n\r\n')

    yield from asyncio.sleep(0, loop=loop)
    assert len(srv._waiters) == 1
    assert srv._keepalive_handle is not None
    assert not transport.close.called

    yield from asyncio.sleep(0.1, loop=loop)
    assert transport.close.called
    assert srv._waiters[0].cancelled


def test_srv_process_request_without_timeout(make_srv, loop, transport):
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
def test_supports_connect_method(srv, loop, transport):
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


def test_content_length_0(srv, loop, transport):
    with mock.patch.object(srv, 'handle_request') as m_handle_request:
        srv.data_received(
            b'GET / HTTP/1.1\r\n'
            b'Host: example.org\r\n'
            b'Content-Length: 0\r\n\r\n')

        loop.run_until_complete(srv._request_handlers[0])

    assert m_handle_request.called
    assert m_handle_request.call_args[0] == (
        mock.ANY, streams.EMPTY_PAYLOAD, mock.ANY)


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


@asyncio.coroutine
def test_close(srv, loop, transport):
    transport.close.side_effect = partial(srv.connection_lost, None)
    srv._max_concurrent_handlers = 2
    srv.connection_made(transport)

    srv.handle_request = mock.Mock()
    srv.handle_request.side_effect = helpers.noop

    assert transport is srv.transport

    srv._keepalive = True
    srv.data_received(
        b'GET / HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 0\r\n\r\n'
        b'GET / HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 0\r\n\r\n')

    yield from asyncio.sleep(0, loop=loop)
    assert len(srv._request_handlers) == 2
    assert len(srv._waiters) == 2

    srv.close()
    yield from asyncio.sleep(0, loop=loop)
    assert len(srv._request_handlers) == 0
    assert srv.transport is None
    assert transport.close.called


@asyncio.coroutine
def test_pipeline_multiple_messages(srv, loop, transport):
    transport.close.side_effect = partial(srv.connection_lost, None)
    srv._max_concurrent_handlers = 1

    processed = 0

    @asyncio.coroutine
    def handle(message, request, writer):
        nonlocal processed
        processed += 1
        yield from writer.write_eof()

    srv.handle_request = mock.Mock()
    srv.handle_request.side_effect = handle

    assert transport is srv.transport

    srv._keepalive = True
    srv.data_received(
        b'GET / HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 0\r\n\r\n'
        b'GET / HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 0\r\n\r\n')

    assert len(srv._request_handlers) == 1
    assert len(srv._messages) == 1
    assert len(srv._waiters) == 0

    yield from asyncio.sleep(0, loop=loop)
    assert len(srv._request_handlers) == 1
    assert len(srv._waiters) == 1
    assert processed == 2


@asyncio.coroutine
def test_pipeline_response_order(srv, loop, buf, transport):
    transport.close.side_effect = partial(srv.connection_lost, None)
    srv.connection_made(transport)
    srv._keepalive = True
    srv.handle_request = mock.Mock()

    processed = []

    @asyncio.coroutine
    def handle1(message, payload, writer):
        nonlocal processed
        yield from asyncio.sleep(0.01, loop=loop)
        writer.write(b'test1')
        yield from writer.write_eof()
        processed.append(1)

    srv.handle_request.side_effect = handle1
    srv.data_received(
        b'GET / HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 0\r\n\r\n')
    yield from asyncio.sleep(0, loop=loop)

    # second
    @asyncio.coroutine
    def handle2(message, request, writer):
        nonlocal processed
        writer.write(b'test2')
        yield from writer.write_eof()
        processed.append(2)

    srv.handle_request.side_effect = handle2
    srv.data_received(
        b'GET / HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 0\r\n\r\n')
    yield from asyncio.sleep(0, loop=loop)

    assert len(srv._request_handlers) == 2

    yield from asyncio.sleep(0.1, loop=loop)
    assert processed == [1, 2]
