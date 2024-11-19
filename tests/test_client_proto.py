import asyncio
from unittest import mock

from yarl import URL

from aiohttp import http
from aiohttp.client_exceptions import ClientOSError, ServerDisconnectedError
from aiohttp.client_proto import ResponseHandler
from aiohttp.client_reqrep import ClientResponse
from aiohttp.helpers import TimerNoop


async def test_force_close(loop: asyncio.AbstractEventLoop) -> None:
    """Ensure that the force_close method sets the should_close attribute to True.

    This is used externally in aiodocker
    https://github.com/aio-libs/aiodocker/issues/920
    """
    proto = ResponseHandler(loop=loop)
    proto.force_close()
    assert proto.should_close


async def test_oserror(loop: asyncio.AbstractEventLoop) -> None:
    proto = ResponseHandler(loop=loop)
    transport = mock.Mock()
    proto.connection_made(transport)
    proto.connection_lost(OSError())

    assert proto.should_close
    assert isinstance(proto.exception(), ClientOSError)


async def test_pause_resume_on_error(loop) -> None:
    proto = ResponseHandler(loop=loop)
    transport = mock.Mock()
    proto.connection_made(transport)

    proto.pause_reading()
    assert proto._reading_paused

    proto.resume_reading()
    assert not proto._reading_paused


async def test_client_proto_bad_message(loop) -> None:
    proto = ResponseHandler(loop=loop)
    transport = mock.Mock()
    proto.connection_made(transport)
    proto.set_response_params()

    proto.data_received(b"HTTP\r\n\r\n")
    assert proto.should_close
    assert transport.close.called
    assert isinstance(proto.exception(), http.HttpProcessingError)


async def test_uncompleted_message(loop) -> None:
    proto = ResponseHandler(loop=loop)
    transport = mock.Mock()
    proto.connection_made(transport)
    proto.set_response_params(read_until_eof=True)

    proto.data_received(
        b"HTTP/1.1 301 Moved Permanently\r\nLocation: http://python.org/"
    )
    proto.connection_lost(None)

    exc = proto.exception()
    assert isinstance(exc, ServerDisconnectedError)
    assert exc.message.code == 301
    assert dict(exc.message.headers) == {"Location": "http://python.org/"}


async def test_client_protocol_readuntil_eof(loop) -> None:
    proto = ResponseHandler(loop=loop)
    transport = mock.Mock()
    proto.connection_made(transport)
    conn = mock.Mock()
    conn.protocol = proto

    proto.data_received(b"HTTP/1.1 200 Ok\r\n\r\n")

    response = ClientResponse(
        "get",
        URL("http://def-cl-resp.org"),
        writer=mock.Mock(),
        continue100=None,
        timer=TimerNoop(),
        request_info=mock.Mock(),
        traces=[],
        loop=loop,
        session=mock.Mock(),
    )
    proto.set_response_params(read_until_eof=True)
    await response.start(conn)

    assert not response.content.is_eof()

    proto.data_received(b"0000")
    data = await response.content.readany()
    assert data == b"0000"

    proto.data_received(b"1111")
    data = await response.content.readany()
    assert data == b"1111"

    proto.connection_lost(None)
    assert response.content.is_eof()


async def test_empty_data(loop) -> None:
    proto = ResponseHandler(loop=loop)
    proto.data_received(b"")

    # do nothing


async def test_schedule_timeout(loop) -> None:
    proto = ResponseHandler(loop=loop)
    proto.set_response_params(read_timeout=1)
    assert proto._read_timeout_handle is None
    proto.start_timeout()
    assert proto._read_timeout_handle is not None


async def test_drop_timeout(loop) -> None:
    proto = ResponseHandler(loop=loop)
    proto.set_response_params(read_timeout=1)
    proto.start_timeout()
    assert proto._read_timeout_handle is not None
    proto._drop_timeout()
    assert proto._read_timeout_handle is None


async def test_reschedule_timeout(loop) -> None:
    proto = ResponseHandler(loop=loop)
    proto.set_response_params(read_timeout=1)
    proto.start_timeout()
    assert proto._read_timeout_handle is not None
    h = proto._read_timeout_handle
    proto._reschedule_timeout()
    assert proto._read_timeout_handle is not None
    assert proto._read_timeout_handle is not h


async def test_eof_received(loop) -> None:
    proto = ResponseHandler(loop=loop)
    proto.set_response_params(read_timeout=1)
    proto.start_timeout()
    assert proto._read_timeout_handle is not None
    proto.eof_received()
    assert proto._read_timeout_handle is None


async def test_connection_lost_sets_transport_to_none(loop, mocker) -> None:
    """Ensure that the transport is set to None when the connection is lost.

    This ensures the writer knows that the connection is closed.
    """
    proto = ResponseHandler(loop=loop)
    proto.connection_made(mocker.Mock())
    assert proto.transport is not None

    proto.connection_lost(OSError())

    assert proto.transport is None
