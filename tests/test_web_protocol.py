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
    """Resume clears the pause but does not touch a missing transport."""
    handler = RequestHandler(dummy_manager, loop=event_loop)
    # Bare asyncio.Transport.resume_reading() raises NotImplementedError.
    handler.transport = asyncio.Transport()
    handler._upgraded = True  # skip the reparse branch
    handler._msg_queue_paused = True

    handler._resume_msg_queue_reading()

    assert handler._msg_queue_paused is False


async def test_finish_response_re_feeding_parser_tail_wakes_waiter(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """Re-feeding the parser tail in ``finish_response`` (the path taken when
    an HTTP upgrade such as WebSocket is rejected with 4xx) must queue the
    decoded messages and wake the ``start()`` loop's waiter, so a request that
    was pipelined after the failed upgrade is not silently dropped.

    Regression test for issue #12734.
    """
    handler = RequestHandler(dummy_manager, loop=event_loop)

    # Parser returns one new message and consumes the whole tail.
    new_msg = mock.Mock()
    new_payload = mock.Mock()
    parser = mock.Mock()
    # ``HttpParser.feed_data`` returns (messages, upgraded, tail).
    parser.feed_data.return_value = ([(new_msg, new_payload)], False, b"")
    handler._parser = parser
    handler._message_tail = b"GET /pipelined HTTP/1.1\r\nHost: example.com\r\n\r\n"

    # ``start()`` parks here waiting for the next message.
    waiter: asyncio.Future[None] = event_loop.create_future()
    handler._waiter = waiter
    assert not waiter.done()

    # Drive the real ``finish_response`` code path. ``request._finish`` and
    # ``resp.prepare``/``resp.write_eof`` are no-ops, but the parser-tail
    # re-feed runs in between, and that's what we want to exercise.
    request = mock.Mock()
    request._finish = mock.Mock()
    resp = mock.Mock()
    resp.prepare = mock.AsyncMock()
    resp.write_eof = mock.AsyncMock()
    # ``finish_response`` returns ``(resp, disconnected)``.
    result_resp, disconnected = await handler.finish_response(request, resp, None)
    assert result_resp is resp
    assert disconnected is False

    # The pipelined message must be queued and the waiter must be woken.
    assert list(handler._messages) == [(new_msg, new_payload)]
    assert handler._message_tail == b""
    assert waiter.done()
    assert waiter.result() is None
