# Tests for aiohttp/server.py

import asyncio
import platform
import socket
from functools import partial
from unittest import mock

import pytest

from aiohttp import helpers, http, streams, web

IS_MACOS = platform.system() == "Darwin"


@pytest.fixture
def make_srv(loop, manager):
    srv = None

    def maker(*, cls=web.RequestHandler, **kwargs):
        nonlocal srv
        m = kwargs.pop("manager", manager)
        srv = cls(m, loop=loop, access_log=None, **kwargs)
        return srv

    yield maker

    if srv is not None:
        if srv.transport is not None:
            srv.connection_lost(None)


@pytest.fixture
def manager(request_handler, loop):
    async def maker():
        return web.Server(request_handler)

    return loop.run_until_complete(maker())


@pytest.fixture
def srv(make_srv, transport):
    srv = make_srv()
    srv.connection_made(transport)
    transport.close.side_effect = partial(srv.connection_lost, None)
    with mock.patch.object(
        web.RequestHandler, "_drain_helper", side_effect=helpers.noop
    ):
        yield srv


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


async def test_shutdown(srv, transport) -> None:
    loop = asyncio.get_event_loop()
    assert transport is srv.transport

    srv._keepalive = True
    task_handler = srv._task_handler

    assert srv._waiter is not None
    assert srv._task_handler is not None

    t0 = loop.time()
    await srv.shutdown()
    t1 = loop.time()

    assert t1 - t0 < 0.05, t1 - t0

    assert transport.close.called
    assert srv.transport is None

    assert not srv._task_handler
    await asyncio.sleep(0.1)
    assert task_handler.done()


async def test_double_shutdown(srv, transport) -> None:
    await srv.shutdown()
    assert transport.close.called
    assert srv.transport is None

    transport.reset_mock()
    await srv.shutdown()
    assert not transport.close.called
    assert srv.transport is None


async def test_shutdown_wait_error_handler(srv, transport) -> None:
    loop = asyncio.get_event_loop()

    async def _error_handle():
        pass

    srv._error_handler = loop.create_task(_error_handle())
    await srv.shutdown()
    assert srv._error_handler.done()


async def test_close_after_response(srv, transport) -> None:
    srv.data_received(
        b"GET / HTTP/1.0\r\n" b"Host: example.com\r\n" b"Content-Length: 0\r\n\r\n"
    )
    h = srv._task_handler

    await asyncio.sleep(0.1)
    assert srv._waiter is None
    assert srv._task_handler is None

    assert transport.close.called
    assert srv.transport is None

    assert h.done()


def test_connection_made(make_srv) -> None:
    srv = make_srv()
    srv.connection_made(mock.Mock())
    assert not srv._force_close


def test_connection_made_with_tcp_keepaplive(make_srv, transport) -> None:
    srv = make_srv()

    sock = mock.Mock()
    transport.get_extra_info.return_value = sock
    srv.connection_made(transport)
    sock.setsockopt.assert_called_with(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)


def test_connection_made_without_tcp_keepaplive(make_srv) -> None:
    srv = make_srv(tcp_keepalive=False)

    sock = mock.Mock()
    transport = mock.Mock()
    transport.get_extra_info.return_value = sock
    srv.connection_made(transport)
    assert not sock.setsockopt.called


def test_eof_received(make_srv) -> None:
    srv = make_srv()
    srv.connection_made(mock.Mock())
    srv.eof_received()
    # assert srv.reader._eof


async def test_connection_lost(srv) -> None:
    srv.data_received(
        b"GET / HTTP/1.1\r\n" b"Host: example.com\r\n" b"Content-Length: 0\r\n\r\n"
    )
    srv._keepalive = True

    handle = srv._task_handler
    await asyncio.sleep(0)  # wait for .start() starting
    srv.connection_lost(None)

    assert srv._force_close

    await handle

    assert not srv._task_handler


def test_srv_keep_alive(srv) -> None:
    assert not srv._keepalive

    srv.keep_alive(True)
    assert srv._keepalive

    srv.keep_alive(False)
    assert not srv._keepalive


def test_srv_keep_alive_disable(srv) -> None:
    handle = srv._keepalive_handle = mock.Mock()

    srv.keep_alive(False)
    assert not srv._keepalive
    assert srv._keepalive_handle is None
    handle.cancel.assert_called_with()


async def test_simple(srv, buf) -> None:
    srv.data_received(b"GET / HTTP/1.1\r\n\r\n")

    await asyncio.sleep(0.05)
    assert buf.startswith(b"HTTP/1.1 200 OK\r\n")


async def test_bad_method(srv, buf) -> None:
    srv.data_received(b":BAD; / HTTP/1.0\r\n" b"Host: example.com\r\n\r\n")

    await asyncio.sleep(0)
    assert buf.startswith(b"HTTP/1.0 400 Bad Request\r\n")


async def test_line_too_long(srv, buf) -> None:
    srv.data_received(b"".join([b"a" for _ in range(10000)]) + b"\r\n\r\n")

    await asyncio.sleep(0)
    assert buf.startswith(b"HTTP/1.0 400 Bad Request\r\n")


async def test_invalid_content_length(srv, buf) -> None:
    srv.data_received(
        b"GET / HTTP/1.0\r\n" b"Host: example.com\r\n" b"Content-Length: sdgg\r\n\r\n"
    )
    await asyncio.sleep(0)

    assert buf.startswith(b"HTTP/1.0 400 Bad Request\r\n")


async def test_unhandled_runtime_error(make_srv, transport, request_handler):
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
        b"GET / HTTP/1.0\r\n" b"Host: example.com\r\n" b"Content-Length: 0\r\n\r\n"
    )

    await srv._task_handler
    assert request_handler.called
    srv.logger.exception.assert_called_with(
        "Unhandled runtime exception", exc_info=mock.ANY
    )


async def test_handle_uncompleted(
    make_srv, transport, handle_with_error, request_handler
):
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
        b"GET / HTTP/1.0\r\n" b"Host: example.com\r\n" b"Content-Length: 50000\r\n\r\n"
    )

    await srv._task_handler
    assert request_handler.called
    assert closed
    srv.logger.exception.assert_called_with("Error handling request", exc_info=mock.ANY)


@pytest.mark.xfail(
    IS_MACOS,
    raises=TypeError,
    reason="Intermittently fails on macOS",
    strict=False,
)
async def test_handle_uncompleted_pipe(
    make_srv, transport, request_handler, handle_with_error
):
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
        await asyncio.sleep(0.05)
        return web.Response()

    # normal
    request_handler.side_effect = handle
    srv.data_received(
        b"GET / HTTP/1.1\r\n" b"Host: example.com\r\n" b"Content-Length: 0\r\n\r\n"
    )
    await asyncio.sleep(0.01)

    # with exception
    request_handler.side_effect = handle_with_error()
    srv.data_received(
        b"GET / HTTP/1.1\r\n" b"Host: example.com\r\n" b"Content-Length: 50000\r\n\r\n"
    )

    assert srv._task_handler

    await asyncio.sleep(0.01)

    await srv._task_handler
    assert normal_completed
    assert request_handler.called
    assert closed
    srv.logger.exception.assert_called_with("Error handling request", exc_info=mock.ANY)


async def test_lingering(srv, transport) -> None:
    assert not transport.close.called

    async def handle(message, request, writer):
        pass

    with mock.patch.object(
        web.RequestHandler, "handle_request", create=True, new=handle
    ):
        srv.data_received(
            b"GET / HTTP/1.0\r\n" b"Host: example.com\r\n" b"Content-Length: 3\r\n\r\n"
        )

        await asyncio.sleep(0.05)
        assert not transport.close.called

        srv.data_received(b"123")

        await asyncio.sleep(0)
        transport.close.assert_called_with()


async def test_lingering_disabled(make_srv, transport, request_handler) -> None:
    async def handle_request(request):
        await asyncio.sleep(0)

    srv = make_srv(lingering_time=0)
    srv.connection_made(transport)
    request_handler.side_effect = handle_request

    await asyncio.sleep(0)
    assert not transport.close.called

    srv.data_received(
        b"GET / HTTP/1.0\r\n" b"Host: example.com\r\n" b"Content-Length: 50\r\n\r\n"
    )
    await asyncio.sleep(0)
    assert not transport.close.called
    await asyncio.sleep(0.05)
    transport.close.assert_called_with()


async def test_lingering_timeout(make_srv, transport, request_handler):
    async def handle_request(request):
        await asyncio.sleep(0)

    srv = make_srv(lingering_time=1e-30)
    srv.connection_made(transport)
    request_handler.side_effect = handle_request

    await asyncio.sleep(0.05)
    assert not transport.close.called

    srv.data_received(
        b"GET / HTTP/1.0\r\n" b"Host: example.com\r\n" b"Content-Length: 50\r\n\r\n"
    )
    await asyncio.sleep(0)
    assert not transport.close.called

    await asyncio.sleep(0.05)
    transport.close.assert_called_with()


async def test_handle_payload_access_error(make_srv, transport, request_handler):
    srv = make_srv(lingering_time=0)
    srv.connection_made(transport)
    srv.data_received(
        b"POST /test HTTP/1.1\r\n" b"Content-Length: 9\r\n\r\n" b"some data"
    )
    # start request_handler task
    await asyncio.sleep(0.05)

    with pytest.raises(web.PayloadAccessError):
        await request_handler.call_args[0][0].content.read()


async def test_handle_cancel(make_srv, transport) -> None:
    log = mock.Mock()

    srv = make_srv(logger=log, debug=True)
    srv.connection_made(transport)

    async def handle_request(message, payload, writer):
        await asyncio.sleep(10)

    async def cancel():
        srv._task_handler.cancel()

    with mock.patch.object(
        web.RequestHandler, "handle_request", create=True, new=handle_request
    ):
        srv.data_received(
            b"GET / HTTP/1.0\r\n" b"Content-Length: 10\r\n" b"Host: example.com\r\n\r\n"
        )

        await asyncio.gather(srv._task_handler, cancel())
        assert log.debug.called


async def test_handle_cancelled(make_srv, transport) -> None:
    log = mock.Mock()

    srv = make_srv(logger=log, debug=True)
    srv.connection_made(transport)

    # start request_handler task
    await asyncio.sleep(0)

    srv.data_received(b"GET / HTTP/1.0\r\n" b"Host: example.com\r\n\r\n")

    r_handler = srv._task_handler
    assert (await r_handler) is None


async def test_handle_400(srv, buf, transport) -> None:
    srv.data_received(b"GET / HT/asd\r\n\r\n")

    await asyncio.sleep(0)
    assert b"400 Bad Request" in buf


async def test_keep_alive(make_srv, transport) -> None:
    loop = asyncio.get_event_loop()
    srv = make_srv(keepalive_timeout=0.05)
    future = loop.create_future()
    future.set_result(1)

    with mock.patch.object(
        web.RequestHandler, "KEEPALIVE_RESCHEDULE_DELAY", new=0.1
    ), mock.patch.object(
        web.RequestHandler, "handle_request", create=True, return_value=future
    ):
        srv.connection_made(transport)
        srv.keep_alive(True)
        srv.data_received(
            b"GET / HTTP/1.1\r\n" b"Host: example.com\r\n" b"Content-Length: 0\r\n\r\n"
        )

        waiter = None
        while waiter is None:
            await asyncio.sleep(0)
            waiter = srv._waiter
        assert srv._keepalive_handle is not None
        assert not transport.close.called

        await asyncio.sleep(0.2)
        assert transport.close.called
        assert waiter.cancelled


async def test_srv_process_request_without_timeout(make_srv, transport) -> None:
    srv = make_srv()
    srv.connection_made(transport)

    srv.data_received(b"GET / HTTP/1.0\r\n" b"Host: example.com\r\n\r\n")

    await srv._task_handler
    assert transport.close.called


def test_keep_alive_timeout_default(srv) -> None:
    assert 75 == srv.keepalive_timeout


def test_keep_alive_timeout_nondefault(make_srv) -> None:
    srv = make_srv(keepalive_timeout=10)
    assert 10 == srv.keepalive_timeout


async def test_supports_connect_method(srv, transport, request_handler) -> None:
    srv.data_received(
        b"CONNECT aiohttp.readthedocs.org:80 HTTP/1.0\r\n" b"Content-Length: 0\r\n\r\n"
    )
    await asyncio.sleep(0.1)

    assert request_handler.called
    assert isinstance(request_handler.call_args[0][0].content, streams.StreamReader)


async def test_content_length_0(srv, request_handler) -> None:
    srv.data_received(
        b"GET / HTTP/1.1\r\n" b"Host: example.org\r\n" b"Content-Length: 0\r\n\r\n"
    )
    await asyncio.sleep(0.01)

    assert request_handler.called
    assert request_handler.call_args[0][0].content == streams.EMPTY_PAYLOAD


def test_rudimentary_transport(srv) -> None:
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


async def test_pipeline_multiple_messages(srv, transport, request_handler):
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
        b"GET / HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Content-Length: 0\r\n\r\n"
        b"GET / HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Content-Length: 0\r\n\r\n"
    )

    assert srv._task_handler is not None
    assert len(srv._messages) == 2
    assert srv._waiter is not None

    await asyncio.sleep(0.05)
    assert srv._task_handler is not None
    assert srv._waiter is not None
    assert processed == 2


async def test_pipeline_response_order(srv, buf, transport, request_handler):
    transport.close.side_effect = partial(srv.connection_lost, None)
    srv._keepalive = True

    processed = []

    async def handle1(request):
        nonlocal processed
        await asyncio.sleep(0.01)
        resp = web.StreamResponse()
        await resp.prepare(request)
        await resp.write(b"test1")
        await resp.write_eof()
        processed.append(1)
        return resp

    request_handler.side_effect = handle1
    srv.data_received(
        b"GET / HTTP/1.1\r\n" b"Host: example.com\r\n" b"Content-Length: 0\r\n\r\n"
    )
    await asyncio.sleep(0.01)

    # second

    async def handle2(request):
        nonlocal processed
        resp = web.StreamResponse()
        await resp.prepare(request)
        await resp.write(b"test2")
        await resp.write_eof()
        processed.append(2)
        return resp

    request_handler.side_effect = handle2
    srv.data_received(
        b"GET / HTTP/1.1\r\n" b"Host: example.com\r\n" b"Content-Length: 0\r\n\r\n"
    )
    await asyncio.sleep(0.01)

    assert srv._task_handler is not None

    await asyncio.sleep(0.1)
    assert processed == [1, 2]


def test_data_received_close(srv) -> None:
    srv.close()
    srv.data_received(
        b"GET / HTTP/1.1\r\n" b"Host: example.com\r\n" b"Content-Length: 0\r\n\r\n"
    )

    assert not srv._messages


def test_data_received_force_close(srv) -> None:
    srv.force_close()
    srv.data_received(
        b"GET / HTTP/1.1\r\n" b"Host: example.com\r\n" b"Content-Length: 0\r\n\r\n"
    )

    assert not srv._messages


async def test__process_keepalive(srv) -> None:
    loop = asyncio.get_event_loop()
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


async def test__process_keepalive_schedule_next(srv) -> None:
    loop = asyncio.get_event_loop()
    # wait till the waiter is waiting
    await asyncio.sleep(0)

    srv._keepalive = True
    srv._keepalive_time = 1
    srv._keepalive_timeout = 1
    expire_time = srv._keepalive_time + srv._keepalive_timeout
    with mock.patch.object(loop, "time", return_value=expire_time):
        with mock.patch.object(loop, "call_later") as call_later_patched:
            srv._process_keepalive()
            call_later_patched.assert_called_with(1, srv._process_keepalive)


async def test__process_keepalive_force_close(srv) -> None:
    loop = asyncio.get_event_loop()
    srv._force_close = True
    with mock.patch.object(loop, "call_at") as call_at_patched:
        srv._process_keepalive()
        assert not call_at_patched.called


async def test_two_data_received_without_waking_up_start_task(srv) -> None:
    # make a chance to srv.start() method start waiting for srv._waiter
    await asyncio.sleep(0.01)
    assert srv._waiter is not None

    srv.data_received(
        b"GET / HTTP/1.1\r\n" b"Host: ex.com\r\n" b"Content-Length: 1\r\n\r\n" b"a"
    )
    srv.data_received(
        b"GET / HTTP/1.1\r\n" b"Host: ex.com\r\n" b"Content-Length: 1\r\n\r\n" b"b"
    )

    assert len(srv._messages) == 2
    assert srv._waiter.done()
    await asyncio.sleep(0.01)


async def test_client_disconnect(aiohttp_server) -> None:
    async def handler(request):
        buf = b""
        with pytest.raises(ConnectionError):
            while len(buf) < 10:
                buf += await request.content.read(10)
        # return with closed transport means premature client disconnection
        return web.Response()

    logger = mock.Mock()
    app = web.Application()
    app._debug = True
    app.router.add_route("POST", "/", handler)
    server = await aiohttp_server(app, logger=logger)

    _, writer = await asyncio.open_connection("127.0.0.1", server.port)
    writer.write(
        """POST / HTTP/1.1\r
Connection: keep-alive\r
Content-Length: 10\r
Host: localhost:{port}\r
\r
""".format(
            port=server.port
        ).encode(
            "ascii"
        )
    )
    await writer.drain()
    await asyncio.sleep(0.1)
    writer.write(b"x")
    writer.close()
    await asyncio.sleep(0.1)
    logger.debug.assert_called_with("Ignored premature client disconnection")
