import asyncio
from unittest import mock

from pytest_mock import MockerFixture
from yarl import URL

from aiohttp import http
from aiohttp.client_exceptions import ClientOSError, ServerDisconnectedError
from aiohttp.client_proto import ResponseHandler
from aiohttp.client_reqrep import ClientResponse
from aiohttp.helpers import TimerNoop
from aiohttp.http_parser import RawResponseMessage


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


async def test_pause_resume_on_error(loop: asyncio.AbstractEventLoop) -> None:
    proto = ResponseHandler(loop=loop)
    transport = mock.Mock()
    proto.connection_made(transport)

    proto.pause_reading()
    assert proto._reading_paused

    proto.resume_reading()
    assert not proto._reading_paused


async def test_client_proto_bad_message(loop: asyncio.AbstractEventLoop) -> None:
    proto = ResponseHandler(loop=loop)
    transport = mock.Mock()
    proto.connection_made(transport)
    proto.set_response_params()

    proto.data_received(b"HTTP\r\n\r\n")
    assert proto.should_close
    assert transport.close.called
    assert isinstance(proto.exception(), http.HttpProcessingError)


async def test_uncompleted_message(loop: asyncio.AbstractEventLoop) -> None:
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
    assert isinstance(exc.message, RawResponseMessage)
    assert exc.message.code == 301
    assert dict(exc.message.headers) == {"Location": "http://python.org/"}


async def test_data_received_after_close(loop: asyncio.AbstractEventLoop) -> None:
    proto = ResponseHandler(loop=loop)
    transport = mock.Mock()
    proto.connection_made(transport)
    proto.set_response_params(read_until_eof=True)
    proto.close()
    assert transport.close.called
    transport.close.reset_mock()
    proto.data_received(b"HTTP\r\n\r\n")
    assert proto.should_close
    assert not transport.close.called
    assert isinstance(proto.exception(), http.HttpProcessingError)


async def test_multiple_responses_one_byte_at_a_time(
    loop: asyncio.AbstractEventLoop,
) -> None:
    proto = ResponseHandler(loop=loop)
    proto.connection_made(mock.Mock())
    conn = mock.Mock(protocol=proto)
    proto.set_response_params(read_until_eof=True)

    for _ in range(2):
        messages = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nab"
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\ncd"
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nef"
        )
        for i in range(len(messages)):
            proto.data_received(messages[i : i + 1])

        expected = [b"ab", b"cd", b"ef"]
        for payload in expected:
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
            await response.start(conn)
            await response.read() == payload


async def test_unexpected_exception_during_data_received(
    loop: asyncio.AbstractEventLoop,
) -> None:
    proto = ResponseHandler(loop=loop)

    class PatchableHttpResponseParser(http.HttpResponseParser):
        """Subclass of HttpResponseParser to make it patchable."""

    with mock.patch(
        "aiohttp.client_proto.HttpResponseParser", PatchableHttpResponseParser
    ):
        proto.connection_made(mock.Mock())
        conn = mock.Mock(protocol=proto)
        proto.set_response_params(read_until_eof=True)
        proto.data_received(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nab")
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
        await response.start(conn)
        await response.read() == b"ab"
        with mock.patch.object(proto._parser, "feed_data", side_effect=ValueError):
            proto.data_received(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\ncd")

    assert isinstance(proto.exception(), http.HttpProcessingError)


async def test_client_protocol_readuntil_eof(loop: asyncio.AbstractEventLoop) -> None:
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


async def test_empty_data(loop: asyncio.AbstractEventLoop) -> None:
    proto = ResponseHandler(loop=loop)
    proto.data_received(b"")

    # do nothing


async def test_schedule_timeout(loop: asyncio.AbstractEventLoop) -> None:
    proto = ResponseHandler(loop=loop)
    proto.set_response_params(read_timeout=1)
    assert proto._read_timeout_handle is None
    proto.start_timeout()
    assert proto._read_timeout_handle is not None


async def test_drop_timeout(loop: asyncio.AbstractEventLoop) -> None:
    proto = ResponseHandler(loop=loop)
    proto.set_response_params(read_timeout=1)
    proto.start_timeout()
    assert proto._read_timeout_handle is not None
    proto._drop_timeout()
    assert proto._read_timeout_handle is None


async def test_reschedule_timeout(loop: asyncio.AbstractEventLoop) -> None:
    proto = ResponseHandler(loop=loop)
    proto.set_response_params(read_timeout=1)
    proto.start_timeout()
    assert proto._read_timeout_handle is not None
    h = proto._read_timeout_handle
    proto._reschedule_timeout()
    assert proto._read_timeout_handle is not None
    assert proto._read_timeout_handle is not h


async def test_eof_received(loop: asyncio.AbstractEventLoop) -> None:
    proto = ResponseHandler(loop=loop)
    proto.set_response_params(read_timeout=1)
    proto.start_timeout()
    assert proto._read_timeout_handle is not None
    proto.eof_received()
    assert proto._read_timeout_handle is None


async def test_connection_lost_sets_transport_to_none(
    loop: asyncio.AbstractEventLoop, mocker: MockerFixture
) -> None:
    """Ensure that the transport is set to None when the connection is lost.

    This ensures the writer knows that the connection is closed.
    """
    proto = ResponseHandler(loop=loop)
    proto.connection_made(mocker.Mock())
    assert proto.transport is not None

    proto.connection_lost(OSError())

    assert proto.transport is None


async def test_connection_lost_exception_is_marked_retrieved(
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Test that connection_lost properly handles exceptions without warnings."""
    proto = ResponseHandler(loop=loop)
    proto.connection_made(mock.Mock())

    # Access closed property before connection_lost to ensure future is created
    closed_future = proto.closed
    assert closed_future is not None

    # Simulate an SSL shutdown timeout error
    ssl_error = TimeoutError("SSL shutdown timed out")
    proto.connection_lost(ssl_error)

    # Verify the exception was set on the closed future
    assert closed_future.done()
    exc = closed_future.exception()
    assert exc is not None
    assert "Connection lost: SSL shutdown timed out" in str(exc)
    assert exc.__cause__ is ssl_error


async def test_closed_property_lazy_creation(
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Test that closed future is created lazily."""
    proto = ResponseHandler(loop=loop)

    # Initially, the closed future should not be created
    assert proto._closed is None

    # Accessing the property should create the future
    closed_future = proto.closed
    assert closed_future is not None
    assert isinstance(closed_future, asyncio.Future)
    assert not closed_future.done()

    # Subsequent access should return the same future
    assert proto.closed is closed_future


async def test_closed_property_after_connection_lost(
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Test that closed property returns None after connection_lost if never accessed."""
    proto = ResponseHandler(loop=loop)
    proto.connection_made(mock.Mock())

    # Don't access proto.closed before connection_lost
    proto.connection_lost(None)

    # After connection_lost, closed should return None if it was never accessed
    assert proto.closed is None


async def test_abort(loop: asyncio.AbstractEventLoop) -> None:
    """Test the abort() method."""
    proto = ResponseHandler(loop=loop)

    # Create a mock transport
    transport = mock.Mock()
    proto.connection_made(transport)

    # Set up some state
    proto._payload = mock.Mock()

    # Mock _drop_timeout method using patch.object
    with mock.patch.object(proto, "_drop_timeout") as mock_drop_timeout:
        # Call abort
        proto.abort()

        # Verify transport.abort() was called
        transport.abort.assert_called_once()

        # Verify cleanup
        assert proto.transport is None
        assert proto._payload is None
        assert proto._exception is None  # type: ignore[unreachable]
        mock_drop_timeout.assert_called_once()


async def test_abort_without_transport(loop: asyncio.AbstractEventLoop) -> None:
    """Test abort() when transport is None."""
    proto = ResponseHandler(loop=loop)

    # Mock _drop_timeout method using patch.object
    with mock.patch.object(proto, "_drop_timeout") as mock_drop_timeout:
        # Call abort without transport
        proto.abort()

        # Should not raise and should still clean up
        assert proto._exception is None
        mock_drop_timeout.assert_not_called()
