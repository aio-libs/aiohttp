"""Tests for aiohttp/server.py"""

import asyncio
import socket
from functools import partial
from html import escape
from unittest import mock

import pytest

from aiohttp import errors, helpers, server


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


def test_http_error_exception():
    exc = errors.HttpProcessingError(code=500, message='Internal error')
    assert exc.code == 500
    assert exc.message == 'Internal error'


def test_handle_request(srv):
    transport = mock.Mock()

    srv.connection_made(transport)
    srv.writer = mock.Mock()

    message = mock.Mock()
    message.headers = []
    message.version = (1, 1)
    srv.handle_request(message, mock.Mock())

    content = b''.join(
        [c[1][0] for c in list(srv.writer.write.mock_calls)])
    assert content.startswith(b'HTTP/1.1 404 Not Found\r\n')


@asyncio.coroutine
def test_shutdown(srv, loop):
    transport = mock.Mock()
    transport.close.side_effect = partial(srv.connection_lost, None)
    transport.drain.side_effect = []
    srv.connection_made(transport)
    assert transport is srv.transport

    yield from asyncio.sleep(0, loop=loop)

    srv.reader.feed_data(
        b'GET / HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 0\r\n\r\n')

    srv._keepalive = True

    request_handler = srv._request_handler

    t0 = loop.time()
    yield from srv.shutdown()
    t1 = loop.time()

    assert t1 - t0 < 0.05, t1-t0

    assert transport.close.called
    assert srv.transport is None

    assert srv._request_handler is None
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
    assert srv._request_handler is None

    srv.connection_made(mock.Mock())
    assert srv._request_handler is not None
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


def test_data_received(srv):
    srv.connection_made(mock.Mock())

    srv.data_received(b'123')
    assert b'123' == bytes(srv.reader._buffer)

    srv.data_received(b'456')
    assert b'123456' == bytes(srv.reader._buffer)


def test_eof_received(srv):
    srv.connection_made(mock.Mock())
    srv.eof_received()
    assert srv.reader._eof


@asyncio.coroutine
def test_connection_lost(srv, loop):
    srv.connection_made(mock.Mock())

    handle = srv._request_handler
    yield from asyncio.sleep(0, loop=loop)  # wait for .start() starting
    srv.connection_lost(None)

    assert srv._closing

    yield from handle

    assert srv._request_handler is None


def test_srv_keep_alive(srv):
    assert not srv._keepalive

    srv.keep_alive(True)
    assert srv._keepalive

    srv.keep_alive(False)
    assert not srv._keepalive


def test_slow_request(make_srv, loop):
    transport = mock.Mock()
    srv = make_srv(slow_request_timeout=0.01, keepalive_timeout=0)
    srv.connection_made(transport)

    srv.reader.feed_data(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n')

    loop.run_until_complete(srv._request_handler)
    assert transport.close.called


def test_bad_method(srv, loop):
    transport = mock.Mock()
    srv.connection_made(transport)

    srv.reader.feed_data(
        b'!@#$ / HTTP/1.0\r\n'
        b'Host: example.com\r\n\r\n')

    loop.run_until_complete(srv._request_handler)
    assert transport.write.mock_calls[0][1][0].startswith(
        b'HTTP/1.1 400 Bad Request\r\n')


def test_line_too_long(srv, loop):
    transport = mock.Mock()
    srv.connection_made(transport)
    srv.data_received(b''.join([b'a' for _ in range(10000)]) + b'\r\n\r\n')

    loop.run_until_complete(srv._request_handler)
    assert transport.write.mock_calls[0][1][0].startswith(
        b'HTTP/1.1 400 Bad Request\r\n')


def test_invalid_content_length(srv, loop):
    transport = mock.Mock()
    srv.connection_made(transport)

    srv.reader.feed_data(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: sdgg\r\n\r\n')

    loop.run_until_complete(srv._request_handler)
    assert transport.write.mock_calls[0][1][0].startswith(
        b'HTTP/1.1 400 Bad Request\r\n')


def test_handle_error(srv):
    transport = mock.Mock()
    srv.connection_made(transport)
    srv.keep_alive(True)
    srv.writer = mock.Mock()

    srv.handle_error(404, headers=(('X-Server', 'asyncio'),))
    content = b''.join(
        [c[1][0] for c in list(srv.writer.write.mock_calls)])
    assert b'HTTP/1.1 404 Not Found' in content
    assert b'X-Server: asyncio' in content
    assert not srv._keepalive


def test_handle_error__utf(make_srv):
    transport = mock.Mock()
    srv = make_srv(debug=True)
    srv.connection_made(transport)
    srv.keep_alive(True)
    srv.writer = mock.Mock()
    srv.logger = mock.Mock()

    try:
        raise RuntimeError('что-то пошло не так')
    except RuntimeError as exc:
        srv.handle_error(exc=exc)
    content = b''.join(
        [c[1][0] for c in list(srv.writer.write.mock_calls)])
    assert b'HTTP/1.1 500 Internal Server Error' in content
    assert b'Content-Type: text/html; charset=utf-8' in content
    pattern = escape("raise RuntimeError('что-то пошло не так')")
    assert pattern.encode('utf-8') in content
    assert not srv._keepalive

    srv.logger.exception.assert_called_with("Error handling request")


def test_handle_error_traceback_exc(make_srv):
    log = mock.Mock()
    srv = make_srv(debug=True, logger=log)
    srv.transport = mock.Mock()
    srv.transport.get_extra_info.return_value = '127.0.0.1'
    srv.writer = mock.Mock()
    srv._request_handler = mock.Mock()

    with mock.patch('aiohttp.server.traceback') as m_trace:
        m_trace.format_exc.side_effect = ValueError

        srv.handle_error(500, exc=object())

    content = b''.join(
        [c[1][0] for c in list(srv.writer.write.mock_calls)])
    assert content.startswith(b'HTTP/1.1 500 Internal Server Error')
    assert log.exception.called


def test_handle_error_debug(srv):
    transport = mock.Mock()
    srv.debug = True
    srv.connection_made(transport)
    srv.writer = mock.Mock()

    try:
        raise ValueError()
    except Exception as exc:
        srv.handle_error(999, exc=exc)

    content = b''.join(
        [c[1][0] for c in list(srv.writer.write.mock_calls)])

    assert b'HTTP/1.1 500 Internal' in content
    assert b'Traceback (most recent call last):' in content


def test_handle_error_500(make_srv, loop):
    log = mock.Mock()
    transport = mock.Mock()
    transport.drain.return_value = ()

    srv = make_srv(logger=log)
    srv.connection_made(transport)
    srv.writer = mock.Mock()

    srv.handle_error(500)
    assert log.exception.called


def test_handle(srv, loop):

    def get_mock_coro(return_value):
        @asyncio.coroutine
        def mock_coro(*args, **kwargs):
            return return_value
        return mock.Mock(wraps=mock_coro)

    transport = mock.Mock()
    srv.connection_made(transport)

    handle = srv.handle_request = get_mock_coro(return_value=None)

    srv.reader.feed_data(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n\r\n')

    loop.run_until_complete(srv._request_handler)
    assert handle.called
    assert transport.close.called


def test_handle_uncompleted(make_srv, loop):
    transport = mock.Mock()
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

    srv.reader.feed_data(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 50000\r\n\r\n')

    loop.run_until_complete(srv._request_handler)
    assert handle.called
    assert closed
    srv.logger.exception.assert_called_with("Error handling request")


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

    srv.reader.feed_data(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n\r\n')
    loop.run_until_complete(srv._request_handler)
    assert called


def test_handle_cancel(make_srv, loop):
    log = mock.Mock()
    transport = mock.Mock()

    srv = make_srv(logger=log, debug=True)
    srv.connection_made(transport)
    srv.writer = mock.Mock()
    srv.handle_request = mock.Mock()

    @asyncio.coroutine
    def cancel():
        srv._request_handler.cancel()

    loop.run_until_complete(
        asyncio.gather(srv._request_handler, cancel(), loop=loop))
    assert log.debug.called


def test_handle_cancelled(make_srv, loop):
    log = mock.Mock()
    transport = mock.Mock()

    srv = make_srv(logger=log, debug=True)
    srv.connection_made(transport)

    srv.handle_request = mock.Mock()
    # start request_handler task
    loop.run_until_complete(asyncio.sleep(0, loop=loop))

    srv.reader.feed_data(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n\r\n')

    r_handler = srv._request_handler
    srv._request_handler = None  # emulate srv.connection_lost()

    assert loop.run_until_complete(r_handler) is None


def test_handle_400(srv, loop):
    transport = mock.Mock()
    transport.drain.side_effect = []
    srv.connection_made(transport)
    srv.reader.feed_data(b'GET / HT/asd\r\n\r\n')

    loop.run_until_complete(srv._request_handler)

    assert b'400 Bad Request' in srv.transport.write.call_args[0][0]


def test_handle_500(srv, loop):
    transport = mock.Mock()
    transport.drain.side_effect = []
    srv.connection_made(transport)

    handle = srv.handle_request = mock.Mock()
    handle.side_effect = ValueError

    srv.reader.feed_data(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n\r\n')
    loop.run_until_complete(srv._request_handler)

    assert b'500 Internal Server Error' in srv.transport.write.call_args[0][0]


def test_handle_error_no_handle_task(srv):
    transport = mock.Mock()
    srv.keep_alive(True)
    srv.connection_made(transport)
    srv.connection_lost(None)

    srv.handle_error(300)
    assert not srv._keepalive


def test_keep_alive(make_srv, loop):
    srv = make_srv(keep_alive=0.1)
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

    srv.reader.feed_data(
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

    loop.run_until_complete(srv._request_handler)
    assert transport.close.called


def test_srv_process_request_without_timeout(make_srv, loop):
    transport = mock.Mock()
    srv = make_srv(timeout=0)
    srv.connection_made(transport)

    srv.reader.feed_data(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n\r\n')

    loop.run_until_complete(srv._request_handler)
    assert transport.close.called


def test_keep_alive_timeout_default(srv):
    assert 75 == srv.keepalive_timeout


def test_keep_alive_timeout_nondefault(make_srv):
    srv = make_srv(keepalive_timeout=10)
    assert 10 == srv.keepalive_timeout


def test_keep_alive_timeout_deprecated(make_srv):
    with pytest.warns(DeprecationWarning) as ctx:
        make_srv(keep_alive=10)
    assert len(ctx) == 1
    expected = "keep_alive is deprecated, use keepalive_timeout instead"
    assert ctx[0].message.args == (expected,)


def test_keep_alive_timeout_deprecated2(make_srv):
    srv = make_srv(keepalive_timeout=10)

    with pytest.warns(DeprecationWarning) as ctx:
        assert 10 == srv.keep_alive_timeout
    assert len(ctx) == 1
    expected = "Use keepalive_timeout property instead"
    assert ctx[0].message.args == (expected,)


def test_supports_connect_method(srv, loop):
    transport = mock.Mock()
    srv.connection_made(transport)

    with mock.patch.object(srv, 'handle_request') as m_handle_request:
        srv.reader.feed_data(
            b'CONNECT aiohttp.readthedocs.org:80 HTTP/1.0\r\n'
            b'Content-Length: 0\r\n\r\n')

        loop.run_until_complete(srv._request_handler)

    assert m_handle_request.called
    assert m_handle_request.call_args[0] != (mock.ANY, server.EMPTY_PAYLOAD)


def test_content_length_0(srv, loop):
    transport = mock.Mock()
    srv.connection_made(transport)

    with mock.patch.object(srv, 'handle_request') as m_handle_request:
        srv.reader.feed_data(
            b'GET / HTTP/1.1\r\n'
            b'Host: example.org\r\n'
            b'Content-Length: 0\r\n\r\n')

        loop.run_until_complete(srv._request_handler)

    assert m_handle_request.called
    assert m_handle_request.call_args[0] == (mock.ANY, server.EMPTY_PAYLOAD)
