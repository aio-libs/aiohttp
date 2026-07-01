import asyncio
from unittest import mock

import pytest

from aiohttp.http import WebSocketReader
from aiohttp.web_protocol import RequestHandler
from aiohttp.web_request import BaseRequest
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


def test_pause_msg_queue_reading_without_transport(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """Pausing with no transport still records the paused state."""
    handler = RequestHandler(dummy_manager, loop=event_loop)
    handler.transport = None

    handler._pause_msg_queue_reading()

    assert handler._msg_queue_paused is True


def test_resume_msg_queue_reading_after_upgrade_skips_reparse(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """Resume after an upgrade clears the pause and resumes without reparsing."""
    handler = RequestHandler(dummy_manager, loop=event_loop)
    transport = mock.Mock()
    handler.transport = transport
    handler._upgraded = True
    handler._msg_queue_paused = True
    handler._reading_paused = False

    with mock.patch.object(RequestHandler, "data_received") as data_received:
        handler._resume_msg_queue_reading()

    data_received.assert_not_called()
    assert handler._msg_queue_paused is False
    transport.resume_reading.assert_called_once_with()


def test_resume_msg_queue_reading_without_transport(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """Resume clears the pause but does not touch a missing transport."""
    handler = RequestHandler(dummy_manager, loop=event_loop)
    handler.transport = None
    handler._upgraded = True  # skip the reparse branch
    handler._msg_queue_paused = True

    handler._resume_msg_queue_reading()

    assert handler._msg_queue_paused is False


def test_resume_reading_stays_paused_for_msg_queue(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """Base resume_reading must not un-pause the transport while queue-paused."""
    handler = RequestHandler(dummy_manager, loop=event_loop)
    transport = mock.Mock()
    handler.transport = transport
    handler._msg_queue_paused = True

    handler.resume_reading()

    transport.resume_reading.assert_not_called()


def test_pause_msg_queue_reading_ignores_unsupported_transport(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """A transport without flow control raising on pause is ignored."""
    handler = RequestHandler(dummy_manager, loop=event_loop)
    # Bare asyncio.Transport.pause_reading() raises NotImplementedError.
    handler.transport = asyncio.Transport()

    handler._pause_msg_queue_reading()

    assert handler._msg_queue_paused is True


def test_resume_msg_queue_reading_ignores_unsupported_transport(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """A transport without flow control raising on resume is ignored."""
    handler = RequestHandler(dummy_manager, loop=event_loop)
    # Bare asyncio.Transport.resume_reading() raises NotImplementedError.
    handler.transport = asyncio.Transport()
    handler._upgraded = True  # skip the reparse branch
    handler._msg_queue_paused = True

    handler._resume_msg_queue_reading()

    assert handler._msg_queue_paused is False
