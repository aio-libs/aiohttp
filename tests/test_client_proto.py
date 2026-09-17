import asyncio
from unittest import mock

import pytest
from yarl import URL

from aiohttp import http
from aiohttp.abc import AbstractStreamWriter
from aiohttp.client_exceptions import ClientOSError, ServerDisconnectedError
from aiohttp.client_proto import ResponseHandler
from aiohttp.client_reqrep import ClientResponse
from aiohttp.helpers import DEFAULT_CHUNK_SIZE, TimerNoop
from aiohttp.http_parser import HttpParser


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
    parser = mock.create_autospec(HttpParser, spec_set=True, instance=True)
    proto = ResponseHandler(loop=loop)
    proto._parser = parser
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
                stream_writer=mock.create_autospec(
                    AbstractStreamWriter, spec_set=True, instance=True
                ),
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


def _upgraded_proto(
    loop: asyncio.AbstractEventLoop,
    transport: mock.Mock,
    read_bufsize: int = DEFAULT_CHUNK_SIZE,
) -> ResponseHandler:
    """A protocol that has completed the upgrade but has no parser installed."""
    proto = ResponseHandler(loop=loop)
    proto.connection_made(transport)
    proto.set_response_params(read_bufsize=read_bufsize)
    proto._upgraded = True
    return proto


def _failed_proto(
    loop: asyncio.AbstractEventLoop, transport: mock.Mock
) -> ResponseHandler:
    """An upgraded protocol whose reader has reported a protocol error."""
    proto = _upgraded_proto(loop, transport)
    parser = mock.Mock()
    parser.feed_data.return_value = (False, b"")
    proto.set_parser(parser, mock.Mock())
    parser.feed_data.return_value = (True, b"")
    proto.data_received(b"bad frame")
    return proto


async def test_websocket_parser_error_discards_later_data() -> None:
    """A WebSocket protocol error drops what follows instead of buffering it.

    EOF is only ever reported for a protocol error, and the connection stays
    upgraded, so without this the peer can stream unbounded data into ``_tail``.
    """
    transport = mock.Mock()
    proto = _failed_proto(asyncio.get_running_loop(), transport)

    assert proto._payload_parser_failed

    # The peer keeps streaming; none of it is kept.
    proto.data_received(b"x" * 65536)
    assert proto._tail == b""
    transport.close.assert_not_called()
    transport.pause_reading.assert_not_called()


async def test_parser_error_while_draining_tail_discards_data() -> None:
    """A parser that errors on the drained tail still discards what follows.

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

    assert proto.should_close
    assert proto._payload_parser_failed
    proto.data_received(b"y" * 65536)
    assert proto._tail == b""
    transport.close.assert_not_called()


@pytest.mark.parametrize("parser_eof", [False, True])
async def test_tail_bounded_until_parser_is_installed(parser_eof: bool) -> None:
    """Data buffered before ``set_parser()`` pauses reading, and always resumes.

    An await after the 101, such as a tracing callback doing I/O, holds off
    ``set_parser()`` while the peer keeps sending, so this buffer needs a bound.
    The resume must happen whether the parser then accepts the drained bytes or
    fails on them, or the transport is left paused with nothing to restart it.
    """
    transport = mock.Mock()
    proto = _upgraded_proto(asyncio.get_running_loop(), transport, read_bufsize=1024)

    proto.data_received(b"x" * 2048)
    transport.pause_reading.assert_called_once_with()

    parser = mock.Mock()
    parser.feed_data.return_value = (parser_eof, b"")
    proto.set_parser(parser, mock.Mock())

    assert not proto._buffer_paused
    transport.resume_reading.assert_called_once_with()
    # Whatever arrives next is parsed or discarded, never accumulated.
    proto.data_received(b"z" * 65536)
    assert proto._tail == b""


async def test_drain_elsewhere_does_not_lift_the_tail_pause() -> None:
    """A resume from elsewhere must not lift the pause the tail bound took.

    ``WebSocketDataQueue`` and ``StreamReader`` both call ``resume_reading()``
    as they drain. Nothing would re-arm the bound afterwards, since it checks
    ``_buffer_paused``, so the peer could refill the buffer it paused for.
    """
    transport = mock.Mock()
    proto = _upgraded_proto(asyncio.get_running_loop(), transport, read_bufsize=1024)
    proto.data_received(b"x" * 2048)
    transport.pause_reading.assert_called_once_with()

    proto.resume_reading()

    assert proto._buffer_paused
    transport.resume_reading.assert_not_called()


async def test_discarded_data_does_not_hold_off_the_read_timeout() -> None:
    """Bytes dropped after a protocol error are not progress.

    Rescheduling on them would let a peer flood a dead connection forever
    without ``sock_read`` ever reaping it.
    """
    transport = mock.Mock()
    proto = _upgraded_proto(asyncio.get_running_loop(), transport)
    parser = mock.Mock()
    parser.feed_data.return_value = (False, b"")
    proto.set_parser(parser, mock.Mock())
    parser.feed_data.return_value = (True, b"")
    proto.data_received(b"bad frame")
    assert proto._payload_parser_failed

    with mock.patch.object(proto, "_reschedule_timeout") as reschedule:
        proto.data_received(b"x" * 65536)

    reschedule.assert_not_called()


async def test_tail_resume_leaves_the_timeout_stopped_for_another_pause() -> None:
    """Draining the tail must not restart sock_read for someone else's pause.

    The drain runs through ``data_received()``, which reschedules, so the
    resume has to undo that while the queue still holds the transport.
    """
    transport = mock.Mock()
    proto = _upgraded_proto(asyncio.get_running_loop(), transport, read_bufsize=1024)
    proto.read_timeout = 30
    proto.data_received(b"x" * 2048)
    transport.pause_reading.assert_called_once_with()

    # What WebSocketDataQueue does when it hits its high-water mark.
    proto.pause_reading()

    parser = mock.Mock()
    parser.feed_data.return_value = (False, b"")
    proto.set_parser(parser, mock.Mock())

    assert proto._reading_paused
    assert proto._read_timeout_handle is None
    transport.resume_reading.assert_not_called()


async def test_drain_that_refills_the_tail_stays_paused() -> None:
    """A drain that cannot empty the buffer must leave the bound in force.

    ``set_response_params()`` drains through ``data_received()``, which can
    hand an upgraded tail straight back to the buffer it came from.
    """
    transport = mock.Mock()
    proto = _upgraded_proto(asyncio.get_running_loop(), transport, read_bufsize=1024)
    proto.read_timeout = 30
    proto.data_received(b"x" * 2048)
    transport.pause_reading.assert_called_once_with()

    # No parser is installed, so the drain feeds the tail back to itself.
    proto._drain_tail()

    assert proto._tail == b"x" * 2048
    assert proto._buffer_paused
    transport.resume_reading.assert_not_called()
    # The drain restarted sock_read on the way through; the pause is ours.
    assert proto._read_timeout_handle is None


async def test_drain_that_completes_a_response_leaves_the_clock_stopped() -> None:
    """Resuming must not revive a timeout the drain deliberately dropped.

    ``data_received()`` owns the read clock: it stops it when a response
    completes with no body. Re-arming here would leave ``sock_read`` running
    against a connection with nothing outstanding.
    """
    transport = mock.Mock()
    proto = ResponseHandler(loop=asyncio.get_running_loop())
    proto.connection_made(transport)
    # A peer that speaks before the request fills the tail past the bound.
    proto._read_bufsize = 64
    proto.data_received(b"z" * 128)
    assert proto._buffer_paused

    # The drain then parses a complete, body-less response out of that tail.
    proto._tail = b"HTTP/1.1 204 No Content\r\n\r\n"
    proto.set_response_params(read_timeout=30)

    assert proto._read_timeout_handle is None


async def test_drain_leaves_the_clock_stopped_for_a_flow_control_pause() -> None:
    """The drain restarts sock_read; any hold on the transport must stop it.

    The tail bound is not the only reason reading can be held, so the rule is
    about the transport rather than about which pause the drain just lifted.
    """
    transport = mock.Mock()
    proto = _upgraded_proto(asyncio.get_running_loop(), transport)
    proto.read_timeout = 30
    proto._tail = b"frames"
    # Held by flow control rather than the bound, so nothing here lifts it.
    proto._reading_paused = True

    parser = mock.Mock()
    parser.feed_data.return_value = (False, b"")
    proto.set_parser(parser, mock.Mock())

    assert proto._read_timeout_handle is None
