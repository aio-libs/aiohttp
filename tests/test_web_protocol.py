"""Tests for aiohttp/server.py"""

import asyncio
import socket
from functools import partial
from html import escape
from unittest import mock

import pytest

from aiohttp import helpers, http, streams, web


@pytest.fixture
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
    srv._drain_helper = mock.Mock()
    srv._drain_helper.side_effect = helpers.noop
    return srv


@pytest.fixture
def buf():
    return bytearray()


@pytest.fixture
def request_handler():

    async def handler(request):
        return web.Response()

    m = mock.Mock()
    m.side_effect = handler
    return m


@pytest.fixture
def handle_with_error():
    def wrapper(exc=ValueError):

        async def handle(request):
            raise exc

        h = mock.Mock()
        h.side_effect = handle
        return h
    return wrapper


@pytest.fixture
def writer(srv):
    return http.StreamWriter(srv, srv.transport, srv._loop)


@pytest.fixture
def transport(buf):
    transport = mock.Mock()

    def write(chunk):
        buf.extend(chunk)

    transport.write.side_effect = write
    transport.is_closing.return_value = False

    return transport


@pytest.fixture
def ceil(mocker):
    def ceil(val):
        return val

    mocker.patch('aiohttp.helpers.ceil').side_effect = ceil


async def test_shutdown(srv, loop, transport):
    assert transport is srv.transport

    srv._keepalive = True
    task_handler = srv._task_handler

    assert srv._waiter is not None
    assert srv._task_handler is not None

    t0 = loop.time()
    await srv.shutdown()
    t1 = loop.time()

    assert t1 - t0 < 0.05, t1-t0

    assert transport.close.called
    assert srv.transport is None

    assert not srv._task_handler
    await asyncio.sleep(0.1, loop=loop)
    assert task_handler.done()


async def test_double_shutdown(srv, transport):
    await srv.shutdown()
    assert transport.close.called
    assert srv.transport is None

    transport.reset_mock()
    await srv.shutdown()
    assert not transport.close.called
    assert srv.transport is None


async def test_shutdown_wait_error_handler(loop, srv, transport):

    async def _error_handle():
        pass

    srv._error_handler = loop.create_task(_error_handle())
    await srv.shutdown()
    assert srv._error_handler.done()


async def test_close_after_response(srv, loop, transport):
    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 0\r\n\r\n')
    h = srv._task_handler

    await asyncio.sleep(0.1, loop=loop)
    assert srv._waiter is None
    assert srv._task_handler is None

    assert transport.close.called
    assert srv.transport is None

    assert h.done()


def test_connection_made(make_srv):
    srv = make_srv()
    srv.connection_made(mock.Mock())
    assert not srv._force_close


def test_connection_made_with_tcp_keepaplive(make_srv, transport):
    srv = make_srv()

    sock = mock.Mock()
    transport.get_extra_info.return_value = sock
    srv.connection_made(transport)
    sock.setsockopt.assert_called_with(socket.SOL_SOCKET,
                                       socket.SO_KEEPALIVE, 1)


def test_connection_made_without_tcp_keepaplive(make_srv):
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


async def test_connection_lost(srv, loop):
    srv.data_received(
        b'GET / HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 0\r\n\r\n')
    srv._keepalive = True

    handle = srv._task_handler
    await asyncio.sleep(0, loop=loop)  # wait for .start() starting
    srv.connection_lost(None)

    assert srv._force_close

    await handle

    assert not srv._task_handler


def test_srv_keep_alive(srv):
    assert not srv._keepalive

    srv.keep_alive(True)
    assert srv._keepalive

    srv.keep_alive(False)
    assert not srv._keepalive


def test_srv_keep_alive_disable(srv):
    handle = srv._keepalive_handle = mock.Mock()

    srv.keep_alive(False)
    assert not srv._keepalive
    assert srv._keepalive_handle is None
    handle.cancel.assert_called_with()


async def test_simple(srv, loop, buf):
    srv.data_received(
        b'GET / HTTP/1.1\r\n\r\n')

    await asyncio.sleep(0, loop=loop)
    assert buf.startswith(b'HTTP/1.1 200 OK\r\n')


async def test_bad_method(srv, loop, buf):
    srv.data_received(
        b'!@#$ / HTTP/1.0\r\n'
        b'Host: example.com\r\n\r\n')

    await asyncio.sleep(0, loop=loop)
    assert buf.startswith(b'HTTP/1.0 400 Bad Request\r\n')


async def test_data_received_error(srv, loop, buf):
    transport = srv.transport
    srv._request_parser = mock.Mock()
    srv._request_parser.feed_data.side_effect = TypeError

    srv.data_received(
        b'!@#$ / HTTP/1.0\r\n'
        b'Host: example.com\r\n\r\n')

    await asyncio.sleep(0, loop=loop)
    assert buf.startswith(b'HTTP/1.0 500 Internal Server Error\r\n')
    assert transport.close.called
    assert srv._error_handler is None


async def test_line_too_long(srv, loop, buf):
    srv.data_received(b''.join([b'a' for _ in range(10000)]) + b'\r\n\r\n')

    await asyncio.sleep(0, loop=loop)
    assert buf.startswith(b'HTTP/1.0 400 Bad Request\r\n')


async def test_invalid_content_length(srv, loop, buf):
    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: sdgg\r\n\r\n')
    await asyncio.sleep(0, loop=loop)

    assert buf.startswith(b'HTTP/1.0 400 Bad Request\r\n')


async def test_handle_error__utf(
    make_srv, buf, transport, loop, request_handler
):
    request_handler.side_effect = RuntimeError('что-то пошло не так')

    srv = make_srv(debug=True)
    srv.connection_made(transport)
    srv.keep_alive(True)
    srv.logger = mock.Mock()

    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 0\r\n\r\n')
    await asyncio.sleep(0, loop=loop)

    assert b'HTTP/1.0 500 Internal Server Error' in buf
    assert b'Content-Type: text/html; charset=utf-8' in buf
    pattern = escape("RuntimeError: что-то пошло не так")
    assert pattern.encode('utf-8') in buf
    assert not srv._keepalive

    srv.logger.exception.assert_called_with(
        "Error handling request", exc_info=mock.ANY)


async def test_unhandled_runtime_error(
    make_srv, loop, transport, request_handler
):

    async def handle(request):
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

    await srv._task_handler
    assert request_handler.called
    srv.logger.exception.assert_called_with(
        "Unhandled runtime exception", exc_info=mock.ANY)


async def test_handle_uncompleted(
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

    await srv._task_handler
    assert request_handler.called
    assert closed
    srv.logger.exception.assert_called_with(
        "Error handling request", exc_info=mock.ANY)


async def test_handle_uncompleted_pipe(
        make_srv, loop, transport, request_handler, handle_with_error):
    closed = False
    normal_completed = False

    def close():
        nonlocal closed
        closed = True

    transport.close.side_effect = close

    srv = make_srv(lingering_time=0)
    srv.connection_made(transport)
    srv.logger.exception = mock.Mock()

    async def handle(request):
        nonlocal normal_completed
        normal_completed = True
        await asyncio.sleep(0.05, loop=loop)
        return web.Response()

    # normal
    request_handler.side_effect = handle
    srv.data_received(
        b'GET / HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 0\r\n\r\n')
    await asyncio.sleep(0, loop=loop)

    # with exception
    request_handler.side_effect = handle_with_error()
    srv.data_received(
        b'GET / HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 50000\r\n\r\n')

    assert srv._task_handler

    await asyncio.sleep(0, loop=loop)

    await srv._task_handler
    assert normal_completed
    assert request_handler.called
    assert closed
    srv.logger.exception.assert_called_with(
        "Error handling request", exc_info=mock.ANY)


async def test_lingering(srv, loop, transport):
    assert not transport.close.called

    async def handle(message, request, writer):
        pass

    srv.handle_request = handle
    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 3\r\n\r\n')

    await asyncio.sleep(0.05, loop=loop)
    assert not transport.close.called

    srv.data_received(b'123')

    await asyncio.sleep(0, loop=loop)
    transport.close.assert_called_with()


async def test_lingering_disabled(make_srv, loop, transport, request_handler):

    async def handle_request(request):
        await asyncio.sleep(0, loop=loop)

    srv = make_srv(lingering_time=0)
    srv.connection_made(transport)
    request_handler.side_effect = handle_request

    await asyncio.sleep(0, loop=loop)
    assert not transport.close.called

    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 50\r\n\r\n')
    await asyncio.sleep(0, loop=loop)
    assert not transport.close.called
    await asyncio.sleep(0, loop=loop)
    transport.close.assert_called_with()


async def test_lingering_timeout(
    make_srv, loop, transport, ceil, request_handler
):

    async def handle_request(request):
        await asyncio.sleep(0, loop=loop)

    srv = make_srv(lingering_time=1e-30)
    srv.connection_made(transport)
    request_handler.side_effect = handle_request

    await asyncio.sleep(0, loop=loop)
    assert not transport.close.called

    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 50\r\n\r\n')
    await asyncio.sleep(0, loop=loop)
    assert not transport.close.called

    await asyncio.sleep(0, loop=loop)
    transport.close.assert_called_with()


async def test_handle_payload_access_error(
    make_srv, loop, transport, request_handler
):
    srv = make_srv(lingering_time=0)
    srv.connection_made(transport)
    srv.data_received(
        b'POST /test HTTP/1.1\r\n'
        b'Content-Length: 9\r\n\r\n'
        b'some data'
    )
    # start request_handler task
    await asyncio.sleep(0, loop=loop)

    with pytest.raises(web.PayloadAccessError):
        await request_handler.call_args[0][0].content.read()


def test_handle_cancel(make_srv, loop, transport):
    log = mock.Mock()

    srv = make_srv(logger=log, debug=True)
    srv.connection_made(transport)

    async def handle_request(message, payload, writer):
        await asyncio.sleep(10, loop=loop)

    srv.handle_request = handle_request

    async def cancel():
        srv._task_handler.cancel()

    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'Content-Length: 10\r\n'
        b'Host: example.com\r\n\r\n')

    loop.run_until_complete(
        asyncio.gather(srv._task_handler, cancel(), loop=loop))
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

    r_handler = srv._task_handler
    assert loop.run_until_complete(r_handler) is None


async def test_handle_400(srv, loop, buf, transport):
    srv.data_received(b'GET / HT/asd\r\n\r\n')

    await asyncio.sleep(0, loop=loop)
    assert b'400 Bad Request' in buf


def test_handle_500(srv, loop, buf, transport, request_handler):
    request_handler.side_effect = ValueError

    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n\r\n')
    loop.run_until_complete(srv._task_handler)

    assert b'500 Internal Server Error' in buf


async def test_keep_alive(make_srv, loop, transport, ceil):
    srv = make_srv(keepalive_timeout=0.05)
    srv.KEEPALIVE_RESCHEDULE_DELAY = 0.1
    srv.connection_made(transport)

    srv.keep_alive(True)
    srv.handle_request = mock.Mock()
    srv.handle_request.return_value = loop.create_future()
    srv.handle_request.return_value.set_result(1)

    srv.data_received(
        b'GET / HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 0\r\n\r\n')

    await asyncio.sleep(0, loop=loop)
    waiter = srv._waiter
    assert waiter
    assert srv._keepalive_handle is not None
    assert not transport.close.called

    await asyncio.sleep(0.2, loop=loop)
    assert transport.close.called
    assert waiter.cancelled


def test_srv_process_request_without_timeout(make_srv, loop, transport):
    srv = make_srv()
    srv.connection_made(transport)

    srv.data_received(
        b'GET / HTTP/1.0\r\n'
        b'Host: example.com\r\n\r\n')

    loop.run_until_complete(srv._task_handler)
    assert transport.close.called


def test_keep_alive_timeout_default(srv):
    assert 75 == srv.keepalive_timeout


def test_keep_alive_timeout_nondefault(make_srv):
    srv = make_srv(keepalive_timeout=10)
    assert 10 == srv.keepalive_timeout


async def test_supports_connect_method(srv, loop, transport, request_handler):
    srv.data_received(
        b'CONNECT aiohttp.readthedocs.org:80 HTTP/1.0\r\n'
        b'Content-Length: 0\r\n\r\n')
    await asyncio.sleep(0.1, loop=loop)

    assert request_handler.called
    assert isinstance(
        request_handler.call_args[0][0].content,
        streams.StreamReader)


async def test_content_length_0(srv, loop, request_handler):
    srv.data_received(
        b'GET / HTTP/1.1\r\n'
        b'Host: example.org\r\n'
        b'Content-Length: 0\r\n\r\n')
    await asyncio.sleep(0, loop=loop)

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


async def test_close(srv, loop, transport):
    transport.close.side_effect = partial(srv.connection_lost, None)
    srv.connection_made(transport)
    await asyncio.sleep(0, loop=loop)

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

    await asyncio.sleep(0, loop=loop)
    assert srv._task_handler
    assert srv._waiter

    srv.close()
    await asyncio.sleep(0, loop=loop)
    assert srv._task_handler is None
    assert srv.transport is None
    assert transport.close.called


async def test_pipeline_multiple_messages(
    srv, loop, transport, request_handler
):
    transport.close.side_effect = partial(srv.connection_lost, None)

    processed = 0

    async def handle(request):
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

    assert srv._task_handler is not None
    assert len(srv._messages) == 2
    assert srv._waiter is not None

    await asyncio.sleep(0, loop=loop)
    assert srv._task_handler is not None
    assert srv._waiter is not None
    assert processed == 2


async def test_pipeline_response_order(
    srv, loop, buf, transport, request_handler
):
    transport.close.side_effect = partial(srv.connection_lost, None)
    srv._keepalive = True

    processed = []

    async def handle1(request):
        nonlocal processed
        await asyncio.sleep(0.01, loop=loop)
        resp = web.StreamResponse()
        await resp.prepare(request)
        await resp.write(b'test1')
        await resp.write_eof()
        processed.append(1)
        return resp

    request_handler.side_effect = handle1
    srv.data_received(
        b'GET / HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 0\r\n\r\n')
    await asyncio.sleep(0, loop=loop)

    # second

    async def handle2(request):
        nonlocal processed
        resp = web.StreamResponse()
        await resp.prepare(request)
        await resp.write(b'test2')
        await resp.write_eof()
        processed.append(2)
        return resp

    request_handler.side_effect = handle2
    srv.data_received(
        b'GET / HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 0\r\n\r\n')
    await asyncio.sleep(0, loop=loop)

    assert srv._task_handler is not None

    await asyncio.sleep(0.1, loop=loop)
    assert processed == [1, 2]


def test_data_received_close(srv):
    srv.close()
    srv.data_received(
        b'GET / HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 0\r\n\r\n')

    assert not srv._messages


def test_data_received_force_close(srv):
    srv.force_close()
    srv.data_received(
        b'GET / HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Length: 0\r\n\r\n')

    assert not srv._messages


async def test__process_keepalive(loop, srv):
    # wait till the waiter is waiting
    await asyncio.sleep(0)

    assert srv._waiter is not None

    srv._keepalive_time = 1
    srv._keepalive = True
    srv._keepalive_timeout = 1
    expired_time = srv._keepalive_time + srv._keepalive_timeout + 1
    with mock.patch.object(loop, "time", return_value=expired_time):
        srv._process_keepalive()
        assert srv._force_close


async def test__process_keepalive_schedule_next(loop, srv):
    # wait till the waiter is waiting
    await asyncio.sleep(0)

    srv._keepalive = True
    srv._keepalive_time = 1
    srv._keepalive_timeout = 1
    expire_time = srv._keepalive_time + srv._keepalive_timeout
    with mock.patch.object(loop, "time", return_value=expire_time):
        with mock.patch.object(loop, "call_later") as call_later_patched:
            srv._process_keepalive()
            call_later_patched.assert_called_with(
                1,
                srv._process_keepalive
            )


def test__process_keepalive_force_close(loop, srv):
    srv._force_close = True
    with mock.patch.object(loop, "call_at") as call_at_patched:
        srv._process_keepalive()
        assert not call_at_patched.called


def test_two_data_received_without_waking_up_start_task(srv, loop):
    # make a chance to srv.start() method start waiting for srv._waiter
    loop.run_until_complete(asyncio.sleep(0.01))
    assert srv._waiter is not None

    srv.data_received(
        b'GET / HTTP/1.1\r\n'
        b'Host: ex.com\r\n'
        b'Content-Length: 1\r\n\r\n'
        b'a')
    srv.data_received(
        b'GET / HTTP/1.1\r\n'
        b'Host: ex.com\r\n'
        b'Content-Length: 1\r\n\r\n'
        b'b')

    assert len(srv._messages) == 2
    assert srv._waiter.done()
