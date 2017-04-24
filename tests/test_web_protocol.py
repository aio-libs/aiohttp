"""Tests for aiohttp/server.py"""

import asyncio
import socket
from functools import partial
from html import escape
from unittest import mock

import pytest

from aiohttp import helpers, http, streams, web


@pytest.yield_fixture
def make_srv(loop, manager):
    srv = None

    def maker(*, cls=web.RequestHandler, **kwargs):
        nonlocal srv
        m = kwargs.pop('manager', manager)
        srv = cls(m, loop=loop, access_log=None, **kwargs)
        return srv

    yield maker

    if srv is not None:
        if srv.transport is not None:
            srv.connection_lost(None)


@pytest.fixture
def manager(request_handler, loop):
    return web.Server(request_handler, loop=loop)


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
def request_handler():

    @asyncio.coroutine
    def handler(request):
        return web.Response()

    m = mock.Mock()
    m.side_effect = handler
    return m


@pytest.fixture
def handle_with_error():
    def wrapper(exc=ValueError):

        @asyncio.coroutine
        def handle(request):
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
def test_shutdown(srv, loop, transport):
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
    srv._max_concurrent_handlers = 2
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
    srv.data_received(
        b'GET / HTTP/1.0\r\n'
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
def test_simple(srv, loop, buf):
    srv.data_received(
        b'GET / HTTP/1.1\r\n\r\n')

    yield from asyncio.sleep(0, loop=loop)
    assert buf.startswith(b'HTTP/1.1 200 OK\r\n')


@asyncio.coroutine
def test_bad_method(srv, loop, buf):
    srv.data_received(
        b'!@#$ / HTTP/1.0\r\n'
        b'Host: example.com\r\n\r\n')

    yield from asyncio.sleep(0, loop=loop)
    assert buf.startswith(b'HTTP/1.0 400 Bad Request\r\n')


@asyncio.coroutine
def test_internal_error(srv, loop, buf):
    srv._request_parser = mock.Mock()
    srv._request_parser.feed_data.side_effect = TypeError

    srv.data_received(
        b'!@#$ / HTTP/1.0\r\n'
        b'Host: example.com\r\n\r\n')

    yield from asyncio.sleep(0, loop=loop)
    assert buf.startswith(b'HTTP/1.0 500 Internal Server Error\r\n')


@asyncio.coroutine
def test_line_too_long(srv, loop, buf):
    srv.data_received(b''.join([b'a' for _ in range(10000)]) + b'\r\n\r\n')

    yield from asyncio.sleep(0, loop=loop)
    assert buf.startswith(b'HTTP/1.0 400 Bad Request\r\n')


@asyncio.coroutine
def test_invalid_content_length(srv, loop, buf):
    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: sdgg\r\n\r\n')
    yield from asyncio.sleep(0, loop=loop)

    assert buf.startswith(b'HTTP/1.0 400 Bad Request\r\n')


@asyncio.coroutine
def test_handle_error__utf(make_srv, buf, transport, loop, request_handler):
    request_handler.side_effect = RuntimeError('что-то пошло не так')

    srv = make_srv(debug=True)
    srv.connection_made(transport)
    srv.keep_alive(True)
    srv.logger = mock.Mock()

    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 0\r\n\r\n')
    yield from asyncio.sleep(0, loop=loop)

    assert b'HTTP/1.0 500 Internal Server Error' in buf
    assert b'Content-Type: text/html; charset=utf-8' in buf
    pattern = escape("RuntimeError: что-то пошло не так")
    assert pattern.encode('utf-8') in buf
    assert not srv._keepalive

    srv.logger.exception.assert_called_with(
        "Error handling request", exc_info=mock.ANY)


@asyncio.coroutine
def test_unhandled_runtime_error(make_srv, loop, transport, request_handler):

    @asyncio.coroutine
    def handle(request):
        resp = web.Response()
        resp.write_eof = mock.Mock()
        resp.write_eof.side_effect = RuntimeError
        return resp

    srv = make_srv(lingering_time=0)
    srv.debug = True
    srv.connection_made(transport)
    srv.logger.exception = mock.Mock()
    request_handler.side_effect = handle

    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 0\r\n\r\n')

    yield from srv._request_handlers[0]
    assert request_handler.called
    srv.logger.exception.assert_called_with(
        "Unhandled runtime exception", exc_info=mock.ANY)


@asyncio.coroutine
def test_handle_uncompleted(
        make_srv, loop, transport, handle_with_error, request_handler):
    closed = False

    def close():
        nonlocal closed
        closed = True

    transport.close.side_effect = close

    srv = make_srv(lingering_time=0)
    srv.connection_made(transport)
    srv.logger.exception = mock.Mock()
    request_handler.side_effect = handle_with_error()

    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 50000\r\n\r\n')

    yield from srv._request_handlers[0]
    assert request_handler.called
    assert closed
    srv.logger.exception.assert_called_with(
        "Error handling request", exc_info=mock.ANY)


@asyncio.coroutine
def test_handle_uncompleted_pipe(
        make_srv, loop, transport, request_handler, handle_with_error):
    closed = False
    normal_completed = False

    def close():
        nonlocal closed
        closed = True

    transport.close.side_effect = close

    srv = make_srv(lingering_time=0, max_concurrent_handlers=2)
    srv.connection_made(transport)
    srv.logger.exception = mock.Mock()

    @asyncio.coroutine
    def handle(request):
        nonlocal normal_completed
        normal_completed = True
        yield from asyncio.sleep(0.05, loop=loop)
        return web.Response()

    # normal
    request_handler.side_effect = handle
    srv.data_received(
        b'GET / HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 0\r\n\r\n')
    yield from asyncio.sleep(0, loop=loop)

    # with exception
    request_handler.side_effect = handle_with_error()
    srv.data_received(
        b'GET / HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 50000\r\n\r\n')

    assert len(srv._request_handlers) == 2

    yield from asyncio.sleep(0, loop=loop)

    yield from srv._request_handlers[0]
    assert normal_completed
    assert request_handler.called
    assert closed
    srv.logger.exception.assert_called_with(
        "Error handling request", exc_info=mock.ANY)


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
def test_lingering_disabled(make_srv, loop, transport, request_handler):

    @asyncio.coroutine
    def handle_request(request):
        yield from asyncio.sleep(0, loop=loop)

    srv = make_srv(lingering_time=0)
    srv.connection_made(transport)
    request_handler.side_effect = handle_request

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
def test_lingering_timeout(make_srv, loop, transport, ceil, request_handler):

    @asyncio.coroutine
    def handle_request(request):
        yield from asyncio.sleep(0, loop=loop)

    srv = make_srv(lingering_time=1e-30)
    srv.connection_made(transport)
    request_handler.side_effect = handle_request

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


def test_handle_500(srv, loop, buf, transport, request_handler):
    request_handler.side_effect = ValueError

    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n\r\n')
    loop.run_until_complete(srv._request_handlers[0])

    assert b'500 Internal Server Error' in buf


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
def test_supports_connect_method(srv, loop, transport, request_handler):
    srv.data_received(
        b'CONNECT aiohttp.readthedocs.org:80 HTTP/1.0\r\n'
        b'Content-Length: 0\r\n\r\n')
    yield from asyncio.sleep(0.1, loop=loop)

    assert request_handler.called
    assert isinstance(
        request_handler.call_args[0][0].content,
        streams.FlowControlStreamReader)


@asyncio.coroutine
def test_content_length_0(srv, loop, request_handler):
    srv.data_received(
        b'GET / HTTP/1.1\r\n'
        b'Host: example.org\r\n'
        b'Content-Length: 0\r\n\r\n')
    yield from asyncio.sleep(0, loop=loop)

    assert request_handler.called
    assert request_handler.call_args[0][0].content == streams.EMPTY_PAYLOAD


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
def test_pipeline_multiple_messages(srv, loop, transport, request_handler):
    transport.close.side_effect = partial(srv.connection_lost, None)
    srv._max_concurrent_handlers = 1

    processed = 0

    @asyncio.coroutine
    def handle(request):
        nonlocal processed
        processed += 1
        return web.Response()

    request_handler.side_effect = handle

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
def test_pipeline_response_order(srv, loop, buf, transport, request_handler):
    transport.close.side_effect = partial(srv.connection_lost, None)
    srv._keepalive = True
    srv._max_concurrent_handlers = 2

    processed = []

    @asyncio.coroutine
    def handle1(request):
        nonlocal processed
        yield from asyncio.sleep(0.01, loop=loop)
        resp = web.StreamResponse()
        yield from resp.prepare(request)
        yield from resp.write(b'test1')
        yield from resp.write_eof()
        processed.append(1)
        return resp

    request_handler.side_effect = handle1
    srv.data_received(
        b'GET / HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 0\r\n\r\n')
    yield from asyncio.sleep(0, loop=loop)

    # second
    @asyncio.coroutine
    def handle2(request):
        nonlocal processed
        resp = web.StreamResponse()
        yield from resp.prepare(request)
        resp.write(b'test2')
        yield from resp.write_eof()
        processed.append(2)
        return resp

    request_handler.side_effect = handle2
    srv.data_received(
        b'GET / HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 0\r\n\r\n')
    yield from asyncio.sleep(0, loop=loop)

    assert len(srv._request_handlers) == 2

    yield from asyncio.sleep(0.1, loop=loop)
    assert processed == [1, 2]
