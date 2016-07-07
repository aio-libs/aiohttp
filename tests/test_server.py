"""Tests for aiohttp/server.py"""

import asyncio
import pytest
import socket

from html import escape
from unittest import mock

from aiohttp import server
from aiohttp import errors
from aiohttp import helpers


@pytest.yield_fixture
def make_srv(loop):
    srv = None

    def maker(**kwargs):
        nonlocal srv
        srv = server.ServerHttpProtocol(loop=loop, access_log=None,
                                        **kwargs)
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


def test_closing(srv):
    srv._keep_alive = True

    keep_alive_handle = mock.Mock()
    srv._keep_alive_handle = keep_alive_handle
    timeout_handle = mock.Mock()
    srv._timeout_handle = timeout_handle
    transport = srv.transport = mock.Mock()
    request_handler = srv._request_handler = mock.Mock()
    srv.writer = mock.Mock()

    srv.closing()
    assert transport.close.called
    assert srv.transport is None

    assert srv._keep_alive_handle is not None
    assert not keep_alive_handle.cancel.called

    assert srv._timeout_handle is not None
    assert not timeout_handle.cancel.called

    assert srv._request_handler is None
    assert request_handler.cancel.called


def test_closing_during_reading(srv):
    srv._keep_alive = True
    srv._keep_alive_on = True
    srv._reading_request = True
    srv._timeout_handle = timeout_handle = mock.Mock()
    transport = srv.transport = mock.Mock()

    srv.closing()
    assert not transport.close.called
    assert srv.transport is not None

    # cancel existing slow request handler
    assert srv._timeout_handle is not None
    assert timeout_handle.cancel.called
    assert timeout_handle is not srv._timeout_handle


def test_double_closing(srv):
    srv._keep_alive = True

    keep_alive_handle = mock.Mock()
    srv._keep_alive_handle = keep_alive_handle
    timeout_handle = mock.Mock()
    srv._timeout_handle = timeout_handle
    transport = srv.transport = mock.Mock()
    srv.writer = mock.Mock()

    srv.closing()
    assert transport.close.called
    assert srv.transport is None

    transport.reset_mock()
    srv.closing()
    assert not transport.close.called
    assert srv.transport is None

    assert srv._keep_alive_handle is not None
    assert not keep_alive_handle.cancel.called

    assert srv._timeout_handle is not None
    assert not timeout_handle.cancel.called


def test_connection_made(srv):
    assert srv._request_handler is None

    srv.connection_made(mock.Mock())
    assert srv._request_handler is not None
    assert srv._timeout_handle is None


def test_connection_made_without_timeout(srv):
    srv.connection_made(mock.Mock())
    assert srv._timeout_handle is None


def test_connection_made_with_keepaplive(srv):
    sock = mock.Mock()
    transport = mock.Mock()
    transport.get_extra_info.return_value = sock
    srv.connection_made(transport)
    sock.setsockopt.assert_called_with(socket.SOL_SOCKET,
                                       socket.SO_KEEPALIVE, 1)


def test_connection_made_without_keepaplive(make_srv):
    srv = make_srv(keep_alive_on=False)

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


@pytest.mark.run_loop
def test_connection_lost(srv, loop):
    srv.connection_made(mock.Mock())
    srv.data_received(b'123')

    timeout_handle = srv._timeout_handle = mock.Mock()
    keep_alive_handle = srv._keep_alive_handle = mock.Mock()

    handle = srv._request_handler
    srv.connection_lost(None)
    yield from asyncio.sleep(0, loop=loop)

    assert srv._request_handler is None
    assert handle.cancelled()

    assert srv._keep_alive_handle is None
    assert keep_alive_handle.cancel.called

    assert srv._timeout_handle is None
    assert timeout_handle.cancel.called

    srv.connection_lost(None)
    assert srv._request_handler is None
    assert srv._keep_alive_handle is None


def test_srv_keep_alive(srv):
    assert not srv._keep_alive

    srv.keep_alive(True)
    assert srv._keep_alive

    srv.keep_alive(False)
    assert not srv._keep_alive


def test_srv_slow_request(make_srv, loop):
    transport = mock.Mock()
    srv = make_srv(timeout=0.01)
    srv.connection_made(transport)

    srv.reader.feed_data(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n')

    loop.run_until_complete(srv._request_handler)
    assert transport.close.called
    srv.connection_lost(None)
    assert srv._timeout_handle is None


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

    srv.reader.feed_data(b''.join([b'a' for _ in range(10000)]))

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
    assert b'X-SERVER: asyncio' in content
    assert not srv._keep_alive


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
    assert b'CONTENT-TYPE: text/html; charset=utf-8' in content
    pattern = escape("raise RuntimeError('что-то пошло не так')")
    assert pattern.encode('utf-8') in content
    assert not srv._keep_alive

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


def test_handle_error_500(make_srv):
    log = mock.Mock()
    transport = mock.Mock()

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


def test_handle_uncompleted(srv, loop):
    transport = mock.Mock()
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
    assert transport.close.called
    srv.logger.exception.assert_called_with("Error handling request")


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
        asyncio.wait([srv._request_handler, cancel()], loop=loop))
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
    srv.connection_made(transport)
    srv.handle_error = mock.Mock()
    srv.keep_alive(True)
    srv.reader.feed_data(b'GET / HT/asd\r\n\r\n')

    loop.run_until_complete(srv._request_handler)
    assert srv.handle_error.called
    assert 400 == srv.handle_error.call_args[0][0]
    assert transport.close.called


def test_handle_500(srv, loop):
    transport = mock.Mock()
    srv.connection_made(transport)

    handle = srv.handle_request = mock.Mock()
    handle.side_effect = ValueError
    srv.handle_error = mock.Mock()

    srv.reader.feed_data(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n\r\n')
    loop.run_until_complete(srv._request_handler)

    assert srv.handle_error.called
    assert 500 == srv.handle_error.call_args[0][0]


def test_handle_error_no_handle_task(srv):
    transport = mock.Mock()
    srv.keep_alive(True)
    srv.connection_made(transport)
    srv.connection_lost(None)

    srv.handle_error(300)
    assert not srv._keep_alive


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
    srv = make_srv(keep_alive=0)
    srv.connection_made(transport)
    assert srv._keep_alive_handle is None

    srv._keep_alive_period = 15
    keep_alive_handle = srv._keep_alive_handle = mock.Mock()
    srv.handle_request = mock.Mock()
    srv.handle_request.return_value = helpers.create_future(loop)
    srv.handle_request.return_value.set_result(1)

    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'HOST: example.com\r\n\r\n')

    loop.run_until_complete(srv._request_handler)
    assert keep_alive_handle.cancel.called
    assert srv._keep_alive_handle is None
    assert transport.close.called


def test_cancel_not_connected_handler(srv):
    srv.cancel_slow_request()


def test_srv_process_request_without_timeout(make_srv, loop):
    transport = mock.Mock()
    srv = make_srv(timeout=0)
    srv.connection_made(transport)
    assert srv._timeout_handle is None

    srv.reader.feed_data(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n\r\n')

    loop.run_until_complete(srv._request_handler)
    assert transport.close.called
    assert srv._timeout_handle is None


def test_keep_alive_timeout_default(srv):
    assert 75 == srv.keep_alive_timeout


def test_keep_alive_timeout_nondefault(make_srv):
    srv = make_srv(keep_alive=10)
    assert 10 == srv.keep_alive_timeout


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
