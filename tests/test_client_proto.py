import asyncio
from unittest import mock

import pytest
from multidict import CIMultiDict
from pytest_mock import MockerFixture
from yarl import URL

from aiohttp import http
from aiohttp.abc import AbstractStreamWriter
from aiohttp.base_protocol import PAUSE_RESUME_READING_ERRORS
from aiohttp.client_exceptions import ClientOSError, ServerDisconnectedError
from aiohttp.client_proto import ResponseHandler
from aiohttp.client_reqrep import ClientResponse
from aiohttp.helpers import TimerNoop
from aiohttp.http_parser import HttpParser, RawResponseMessage


async def test_force_close() -> None:
    """Ensure that the force_close method sets the should_close attribute to True.

    This is used externally in aiodocker
    https://github.com/aio-libs/aiodocker/issues/920
    """
    proto = ResponseHandler(loop=asyncio.get_running_loop())
    proto.force_close()
    assert proto.should_close


async def test_oserror() -> None:
    proto = ResponseHandler(loop=asyncio.get_running_loop())
    transport = mock.Mock()
    proto.connection_made(transport)
    proto.connection_lost(OSError())

    assert proto.should_close
    assert isinstance(proto.exception(), ClientOSError)


async def test_pause_resume_on_error() -> None:
    parser = mock.create_autospec(HttpParser, spec_set=True, instance=True)
    proto = ResponseHandler(loop=asyncio.get_running_loop())
    proto._parser = parser
    transport = mock.Mock()
    proto.connection_made(transport)

    proto.pause_reading()
    assert proto._reading_paused

    proto.resume_reading()
    assert not proto._reading_paused


async def test_client_proto_bad_message() -> None:
    proto = ResponseHandler(loop=asyncio.get_running_loop())
    transport = mock.Mock()
    proto.connection_made(transport)
    proto.set_response_params()

    proto.data_received(b"HTTP\r\n\r\n")
    assert proto.should_close
    assert transport.close.called
    assert isinstance(proto.exception(), http.HttpProcessingError)


async def test_uncompleted_message() -> None:
    proto = ResponseHandler(loop=asyncio.get_running_loop())
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


async def test_data_received_after_close() -> None:
    proto = ResponseHandler(loop=asyncio.get_running_loop())
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


async def test_multiple_responses_one_byte_at_a_time() -> None:
    loop = asyncio.get_running_loop()
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
        url = URL("http://def-cl-resp.org")
        for payload in expected:
            response = ClientResponse(
                "get",
                url,
                writer=mock.Mock(),
                continue100=None,
                timer=TimerNoop(),
                traces=[],
                loop=loop,
                session=mock.Mock(),
                request_headers=CIMultiDict[str](),
                original_url=url,
                stream_writer=mock.create_autospec(
                    AbstractStreamWriter, spec_set=True, instance=True
                ),
            )
            await response.start(conn)
            await response.read() == payload


async def test_unexpected_exception_during_data_received() -> None:
    loop = asyncio.get_running_loop()
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
        url = URL("http://def-cl-resp.org")
        response = ClientResponse(
            "get",
            url,
            writer=mock.Mock(),
            continue100=None,
            timer=TimerNoop(),
            traces=[],
            loop=loop,
            session=mock.Mock(),
            request_headers=CIMultiDict[str](),
            original_url=url,
            stream_writer=mock.create_autospec(
                AbstractStreamWriter, spec_set=True, instance=True
            ),
        )
        await response.start(conn)
        await response.read() == b"ab"
        with mock.patch.object(proto._parser, "feed_data", side_effect=ValueError):
            proto.data_received(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\ncd")

    assert isinstance(proto.exception(), http.HttpProcessingError)


async def test_base_exception_during_data_received_closes_transport() -> None:
    loop = asyncio.get_running_loop()
    proto = ResponseHandler(loop=loop)

    class PatchableHttpResponseParser(http.HttpResponseParser):
        """Subclass of HttpResponseParser to make it patchable."""

    with mock.patch(
        "aiohttp.client_proto.HttpResponseParser", PatchableHttpResponseParser
    ):
        transport = mock.create_autospec(
            asyncio.Transport, spec_set=True, instance=True
        )
        proto.connection_made(transport)
        proto.set_response_params(read_until_eof=True)
        # Prime the parser so feed_data has been called once with valid data.
        proto.data_received(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nab")
        transport.close.reset_mock()

        with mock.patch.object(
            proto._parser, "feed_data", side_effect=asyncio.CancelledError
        ):
            with pytest.raises(asyncio.CancelledError):
                proto.data_received(b"more")

        assert transport.close.called


async def test_client_protocol_readuntil_eof() -> None:
    loop = asyncio.get_running_loop()
    proto = ResponseHandler(loop=loop)
    transport = mock.Mock()
    proto.connection_made(transport)
    conn = mock.Mock()
    conn.protocol = proto

    proto.data_received(b"HTTP/1.1 200 Ok\r\n\r\n")

    url = URL("http://def-cl-resp.org")
    response = ClientResponse(
        "get",
        url,
        writer=mock.Mock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=mock.Mock(),
        request_headers=CIMultiDict[str](),
        original_url=url,
        stream_writer=mock.create_autospec(
            AbstractStreamWriter, spec_set=True, instance=True
        ),
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


async def test_empty_data() -> None:
    proto = ResponseHandler(loop=asyncio.get_running_loop())
    proto.data_received(b"")

    # do nothing


async def test_schedule_timeout() -> None:
    proto = ResponseHandler(loop=asyncio.get_running_loop())
    proto.set_response_params(read_timeout=1)
    assert proto._read_timeout_handle is None
    proto.start_timeout()
    assert proto._read_timeout_handle is not None


async def test_drop_timeout() -> None:
    proto = ResponseHandler(loop=asyncio.get_running_loop())
    proto.set_response_params(read_timeout=1)
    proto.start_timeout()
    assert proto._read_timeout_handle is not None
    proto._drop_timeout()
    assert proto._read_timeout_handle is None


async def test_reschedule_timeout() -> None:
    proto = ResponseHandler(loop=asyncio.get_running_loop())
    proto.set_response_params(read_timeout=1)
    proto.start_timeout()
    assert proto._read_timeout_handle is not None
    h = proto._read_timeout_handle
    proto._reschedule_timeout()
    assert proto._read_timeout_handle is not None
    assert proto._read_timeout_handle is not h


async def test_eof_received() -> None:
    proto = ResponseHandler(loop=asyncio.get_running_loop())
    proto.set_response_params(read_timeout=1)
    proto.start_timeout()
    assert proto._read_timeout_handle is not None
    proto.eof_received()
    assert proto._read_timeout_handle is None


async def test_connection_lost_sets_transport_to_none(mocker: MockerFixture) -> None:
    """Ensure that the transport is set to None when the connection is lost.

    This ensures the writer knows that the connection is closed.
    """
    proto = ResponseHandler(loop=asyncio.get_running_loop())
    proto.connection_made(mocker.Mock())
    assert proto.transport is not None

    proto.connection_lost(OSError())

    assert proto.transport is None


async def test_connection_lost_exception_is_marked_retrieved() -> None:
    """Test that connection_lost properly handles exceptions without warnings."""
    proto = ResponseHandler(loop=asyncio.get_running_loop())
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


async def test_closed_property_lazy_creation() -> None:
    """Test that closed future is created lazily."""
    proto = ResponseHandler(loop=asyncio.get_running_loop())

    # Initially, the closed future should not be created
    assert proto._closed is None

    # Accessing the property should create the future
    closed_future = proto.closed
    assert closed_future is not None
    assert isinstance(closed_future, asyncio.Future)
    assert not closed_future.done()

    # Subsequent access should return the same future
    assert proto.closed is closed_future


async def test_closed_property_after_connection_lost() -> None:
    """Test that closed property returns None after connection_lost if never accessed."""
    proto = ResponseHandler(loop=asyncio.get_running_loop())
    proto.connection_made(mock.Mock())

    # Don't access proto.closed before connection_lost
    proto.connection_lost(None)

    # After connection_lost, closed should return None if it was never accessed
    assert proto.closed is None


async def test_abort() -> None:
    """Test the abort() method."""
    proto = ResponseHandler(loop=asyncio.get_running_loop())

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


async def test_abort_without_transport() -> None:
    """Test abort() when transport is None."""
    proto = ResponseHandler(loop=asyncio.get_running_loop())

    # Mock _drop_timeout method using patch.object
    with mock.patch.object(proto, "_drop_timeout") as mock_drop_timeout:
        # Call abort without transport
        proto.abort()

        # Should not raise and should still clean up
        assert proto._exception is None
        mock_drop_timeout.assert_not_called()


@pytest.mark.parametrize(
    ("connection", "expected"),
    [(b"upgrade, keep-alive", True), (b"keep-alive", False)],
)
async def test_response_start_records_upgrade(
    connection: bytes, expected: bool
) -> None:
    """ClientResponse.start() preserves the parser's Connection upgrade flag."""
    loop = asyncio.get_running_loop()
    proto = ResponseHandler(loop=loop)
    proto.connection_made(mock.Mock())
    conn = mock.Mock(protocol=proto)
    proto.set_response_params(read_until_eof=True)
    proto.data_received(
        b"HTTP/1.1 101 Switching Protocols\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: " + connection + b"\r\n\r\n"
    )

    url = URL("http://ws-upgrade.org")
    response = ClientResponse(
        "get",
        url,
        writer=mock.Mock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=mock.Mock(),
        request_headers=CIMultiDict[str](),
        original_url=url,
        stream_writer=mock.create_autospec(
            AbstractStreamWriter, spec_set=True, instance=True
        ),
    )
    await response.start(conn)
    assert response._upgraded is expected
    response.close()


def _upgraded_proto(
    loop: asyncio.AbstractEventLoop, transport: mock.Mock, read_bufsize: int = 1024
) -> ResponseHandler:
    """A protocol that has completed the upgrade but has no parser installed."""
    proto = ResponseHandler(loop=loop)
    proto.connection_made(transport)
    proto.set_response_params(read_bufsize=read_bufsize)
    proto._upgraded = True
    return proto


async def test_tail_pauses_reading_at_read_bufsize() -> None:
    """The tail is bounded while no parser is installed to drain it."""
    transport = mock.Mock()
    proto = _upgraded_proto(asyncio.get_running_loop(), transport)

    proto.data_received(b"x" * 1023)
    transport.pause_reading.assert_not_called()

    proto.data_received(b"x")
    assert proto._tail_paused
    transport.pause_reading.assert_called_once_with()


@pytest.mark.parametrize("read_bufsize", [1024, 0])
async def test_set_parser_drains_tail_and_resumes_reading(read_bufsize: int) -> None:
    """Installing the parser drains the tail and lifts the pause.

    A ``read_bufsize`` of 0 pauses on any data at all, so the resume has to be
    driven by the drained tail rather than by the limit, or the connection
    would wedge.
    """
    transport = mock.Mock()
    proto = _upgraded_proto(
        asyncio.get_running_loop(), transport, read_bufsize=read_bufsize
    )
    proto.data_received(b"x" * 2048)
    transport.pause_reading.assert_called_once_with()

    parser = mock.Mock()
    parser.feed_data.return_value = (False, b"")
    proto.set_parser(parser, mock.Mock())

    parser.feed_data.assert_called_once_with(b"x" * 2048)
    assert proto._tail == b""
    assert not proto._tail_paused
    transport.resume_reading.assert_called_once_with()


async def test_websocket_parser_error_pauses_reading() -> None:
    """A WebSocket protocol error stops reading instead of growing the tail.

    ``WebSocketReader.feed_data()`` only ever reports EOF for a protocol error,
    and the connection stays upgraded afterwards, so without this the peer can
    stream unbounded data into ``_tail``.
    """
    transport = mock.Mock()
    loop = asyncio.get_running_loop()
    proto = _upgraded_proto(loop, transport)
    parser = mock.Mock()
    parser.feed_data.return_value = (False, b"")
    proto.set_parser(parser, mock.Mock())

    parser.feed_data.return_value = (True, b"")
    proto.data_received(b"bad frame")

    assert proto._payload_parser is None
    assert proto.should_close
    assert proto._tail_paused
    transport.pause_reading.assert_called_once_with()


async def test_queue_drain_does_not_resume_paused_tail() -> None:
    """WebSocketDataQueue draining must not lift a pause taken for the tail."""
    transport = mock.Mock()
    proto = _upgraded_proto(asyncio.get_running_loop(), transport)
    proto.data_received(b"x" * 2048)
    transport.pause_reading.assert_called_once_with()

    # This is what WebSocketDataQueue._read_from_buffer() does as it drains.
    proto.resume_reading()

    assert proto._tail_paused
    transport.resume_reading.assert_not_called()


async def test_pause_tail_reading_without_transport() -> None:
    """Pausing after the transport is gone is a no-op, not a crash."""
    proto = ResponseHandler(loop=asyncio.get_running_loop())
    proto._upgraded = True

    proto._pause_tail_reading()

    assert proto._tail_paused


@pytest.mark.parametrize("exc_type", PAUSE_RESUME_READING_ERRORS)
async def test_tail_pause_resume_on_transport_without_flow_control(
    exc_type: type[BaseException],
) -> None:
    """A transport that cannot pause or resume is tolerated."""
    transport = mock.Mock()
    transport.pause_reading.side_effect = exc_type()
    transport.resume_reading.side_effect = exc_type()
    proto = _upgraded_proto(asyncio.get_running_loop(), transport)

    proto.data_received(b"x" * 2048)
    assert proto._tail_paused

    parser = mock.Mock()
    parser.feed_data.return_value = (False, b"")
    proto.set_parser(parser, mock.Mock())

    assert not proto._tail_paused


async def test_tail_stays_paused_when_drain_refills_it() -> None:
    """A drain that refills the tail past the limit leaves reading paused."""
    transport = mock.Mock()
    proto = _upgraded_proto(asyncio.get_running_loop(), transport)
    proto.data_received(b"x" * 2048)
    transport.pause_reading.assert_called_once_with()

    # Still upgraded with no parser, so the drain feeds the tail back to itself.
    proto._drain_tail()

    assert proto._tail == b"x" * 2048
    assert proto._tail_paused
    transport.resume_reading.assert_not_called()


async def test_tail_resume_leaves_transport_paused_for_the_queue() -> None:
    """Draining the tail must not resume a transport the queue also paused."""
    transport = mock.Mock()
    proto = _upgraded_proto(asyncio.get_running_loop(), transport)
    proto.data_received(b"x" * 2048)
    # What WebSocketDataQueue.feed_data() does when it hits its high-water mark.
    proto.pause_reading()

    parser = mock.Mock()
    parser.feed_data.return_value = (False, b"")
    proto.set_parser(parser, mock.Mock())

    assert not proto._tail_paused
    assert proto._reading_paused
    transport.resume_reading.assert_not_called()


async def test_websocket_parser_error_replays_tail() -> None:
    """A tail returned alongside EOF is still fed back through data_received."""
    transport = mock.Mock()
    proto = _upgraded_proto(asyncio.get_running_loop(), transport)
    parser = mock.Mock()
    parser.feed_data.return_value = (False, b"")
    proto.set_parser(parser, mock.Mock())

    parser.feed_data.return_value = (True, b"leftover")
    proto.data_received(b"bad frame")

    assert proto._tail == b"leftover"
    assert proto._tail_paused


async def test_parser_error_while_draining_tail_stays_paused() -> None:
    """A parser that errors on the drained tail leaves reading paused.

    The bad frame usually arrives with the handshake, so it is already in
    ``_tail`` when ``set_parser()`` runs and the error fires during the drain
    rather than on a later read.
    """
    transport = mock.Mock()
    proto = _upgraded_proto(asyncio.get_running_loop(), transport)
    proto._tail = b"bad frame"

    parser = mock.Mock()
    parser.feed_data.return_value = (True, b"")
    proto.set_parser(parser, mock.Mock())

    assert proto._tail_paused
    assert proto.should_close
    transport.pause_reading.assert_called_once_with()
    transport.resume_reading.assert_not_called()
