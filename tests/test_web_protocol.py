import asyncio
from unittest import mock

import pytest

from aiohttp.http import WebSocketReader
from aiohttp.web_protocol import RequestHandler
from aiohttp.web_request import BaseRequest
from aiohttp.web_response import StreamResponse
from aiohttp.web_server import Server


@pytest.fixture
def dummy_manager() -> Server[BaseRequest]:
    return mock.create_autospec(Server[BaseRequest], request_handler=mock.Mock(), request_factory=mock.Mock(), instance=True)  # type: ignore[no-any-return]


@pytest.fixture
def dummy_reader() -> tuple[WebSocketReader, mock.Mock]:
    m = mock.create_autospec(WebSocketReader, spec_set=True, instance=True)
    m.feed_data.return_value = False, b""
    return m, m


def test_set_parser_does_not_call_data_received_cb_for_tail(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
    dummy_reader: tuple[WebSocketReader, mock.Mock],
) -> None:
    handler = RequestHandler(dummy_manager, loop=event_loop)
    handler._message_tail = b"tail"
    cb = mock.Mock()

    handler.set_parser(dummy_reader[0], data_received_cb=cb)

    cb.assert_not_called()
    dummy_reader[1].feed_data.assert_called_once_with(b"tail")


def test_data_received_calls_data_received_cb(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
    dummy_reader: tuple[WebSocketReader, mock.Mock],
) -> None:
    handler = RequestHandler(dummy_manager, loop=event_loop)
    cb = mock.Mock()

    handler.set_parser(dummy_reader[0], data_received_cb=cb)
    handler.data_received(b"x")

    cb.assert_called_once()
    dummy_reader[1].feed_data.assert_called_once_with(b"x")


def test_pause_reading_for_buffer_without_transport(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """Pausing with no transport still records the paused state."""
    handler = RequestHandler(dummy_manager, loop=event_loop)
    handler.transport = None

    handler._pause_reading_for_buffer()

    assert handler._buffer_paused is True


def test_resume_reading_if_drained_after_upgrade_skips_reparse(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """Resume after an upgrade clears the pause and resumes without reparsing."""
    handler = RequestHandler(dummy_manager, loop=event_loop)
    transport = mock.Mock()
    handler.transport = transport
    handler._upgraded = True
    handler._buffer_paused = True
    handler._reading_paused = False

    with mock.patch.object(RequestHandler, "data_received") as data_received:
        handler._resume_reading_if_drained()

    data_received.assert_not_called()
    assert handler._buffer_paused is False
    transport.resume_reading.assert_called_once_with()


def test_resume_reading_if_drained_without_transport(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """Resume clears the pause but does not touch a missing transport."""
    handler = RequestHandler(dummy_manager, loop=event_loop)
    handler.transport = None
    handler._upgraded = True  # skip the reparse branch
    handler._buffer_paused = True

    handler._resume_reading_if_drained()

    assert handler._buffer_paused is False


def test_resume_reading_if_drained_stays_paused_for_full_tail(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """Resume is refused while an in-flight upgrade holds read_bufsize of tail.

    The tail is drained by set_parser()/finish_response(), so resuming before
    then would let the buffer grow past its ceiling one read at a time.
    """
    handler = RequestHandler(dummy_manager, loop=event_loop, read_bufsize=1024)
    transport = mock.create_autospec(asyncio.Transport, spec_set=True, instance=True)
    handler.transport = transport
    handler._upgraded = True
    handler._buffer_paused = True
    handler._message_tail = b"x" * 1024

    handler._resume_reading_if_drained()

    assert handler._buffer_paused is True
    transport.resume_reading.assert_not_called()


def test_resume_reading_if_drained_with_room_left_in_tail(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """A tail under read_bufsize does not hold the transport paused."""
    handler = RequestHandler(dummy_manager, loop=event_loop, read_bufsize=1024)
    transport = mock.create_autospec(asyncio.Transport, spec_set=True, instance=True)
    handler.transport = transport
    handler._upgraded = True
    handler._buffer_paused = True
    handler._message_tail = b"x" * 1023

    handler._resume_reading_if_drained()

    assert handler._buffer_paused is False
    transport.resume_reading.assert_called_once_with()


def test_resume_reading_if_drained_with_zero_read_bufsize(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """An empty tail resumes even when read_bufsize leaves it no room.

    Guards the degenerate ``read_bufsize=0`` case: comparing sizes alone would
    match an empty tail and wedge the connection paused for good.
    """
    handler = RequestHandler(dummy_manager, loop=event_loop, read_bufsize=0)
    transport = mock.create_autospec(asyncio.Transport, spec_set=True, instance=True)
    handler.transport = transport
    handler._upgraded = True
    handler._buffer_paused = True

    handler._resume_reading_if_drained()

    assert handler._buffer_paused is False
    transport.resume_reading.assert_called_once_with()


def test_set_parser_resumes_reading_paused_for_tail(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
    dummy_reader: tuple[WebSocketReader, mock.Mock],
) -> None:
    """Handing a full tail to the upgraded protocol resumes reading."""
    handler = RequestHandler(dummy_manager, loop=event_loop, read_bufsize=1024)
    transport = mock.create_autospec(asyncio.Transport, spec_set=True, instance=True)
    handler.transport = transport
    handler._upgraded = True
    handler._buffer_paused = True
    handler._message_tail = b"x" * 1024

    handler.set_parser(dummy_reader[0])

    dummy_reader[1].feed_data.assert_called_once_with(b"x" * 1024)
    assert handler._message_tail == b""
    assert handler._buffer_paused is False
    transport.resume_reading.assert_called_once_with()


def test_resume_reading_stays_paused_for_msg_queue(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """Base resume_reading must not un-pause the transport while queue-paused."""
    handler = RequestHandler(dummy_manager, loop=event_loop)
    transport = mock.Mock()
    handler.transport = transport
    handler._buffer_paused = True

    handler.resume_reading()

    transport.resume_reading.assert_not_called()


def test_pause_reading_for_buffer_ignores_unsupported_transport(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """A transport without flow control raising on pause is ignored."""
    handler = RequestHandler(dummy_manager, loop=event_loop)
    # Bare asyncio.Transport.pause_reading() raises NotImplementedError.
    handler.transport = asyncio.Transport()

    handler._pause_reading_for_buffer()

    assert handler._buffer_paused is True


def test_resume_reading_if_drained_ignores_unsupported_transport(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """A transport without flow control raising on resume is ignored."""
    handler = RequestHandler(dummy_manager, loop=event_loop)
    # Bare asyncio.Transport.resume_reading() raises NotImplementedError.
    handler.transport = asyncio.Transport()
    handler._upgraded = True  # skip the reparse branch
    handler._buffer_paused = True

    handler._resume_reading_if_drained()

    assert handler._buffer_paused is False


async def test_request_racing_connection_lost_is_not_dispatched() -> None:
    """A request delivered in the same iteration as connection_lost() is dropped.

    connection_lost() forces the close and clears the request factory, so
    start() must notice that instead of building a request for the connection
    that is already gone.
    """
    handler = mock.AsyncMock(return_value=StreamResponse())
    proto = Server(handler)()
    transport = mock.Mock()
    transport.is_closing.return_value = False
    transport.get_extra_info.return_value = None
    proto.connection_made(transport)
    task = proto._task_handler
    assert task is not None
    await asyncio.sleep(0)

    # Same event-loop iteration: a request arrives, then the peer disconnects.
    proto.data_received(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    proto.connection_lost(None)

    await task
    handler.assert_not_called()


async def test_request_after_waiting_on_live_connection_is_dispatched() -> None:
    handler = mock.AsyncMock(return_value=StreamResponse())
    proto = Server(handler)()
    transport = mock.Mock()
    transport.is_closing.return_value = False
    transport.get_extra_info.return_value = None
    proto.connection_made(transport)
    task = proto._task_handler
    assert task is not None
    await asyncio.sleep(0)

    proto.data_received(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    await task

    handler.assert_awaited_once()
    proto.connection_lost(None)
