import asyncio
from unittest import mock

import pytest

from aiohttp.http import HttpProcessingError, RawRequestMessage, WebSocketReader
from aiohttp.streams import EMPTY_PAYLOAD, StreamReader
from aiohttp.web_protocol import RequestHandler, _ErrInfo
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


# ---------------------------------------------------------------------------
# Tests for finish_response message-tail replay (regression for #12734)
# ---------------------------------------------------------------------------


def _make_handler(event_loop: asyncio.AbstractEventLoop) -> RequestHandler:  # type: ignore[type-arg]
    manager = mock.create_autospec(
        Server[BaseRequest],
        request_handler=mock.Mock(),
        request_factory=mock.Mock(),
        instance=True,
    )
    return RequestHandler(manager, loop=event_loop)


def _make_mock_request() -> mock.Mock:
    req = mock.Mock()
    req._finish = mock.Mock()
    return req


def _make_mock_resp() -> mock.Mock:
    resp = mock.AsyncMock()
    resp.prepare = mock.AsyncMock()
    resp.write_eof = mock.AsyncMock()
    return resp


async def test_finish_response_replays_message_tail_into_messages(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """finish_response must replay _message_tail so the next pipelined
    request is queued in _messages and the waiter is signalled."""
    handler = _make_handler(event_loop)

    raw_msg = mock.create_autospec(RawRequestMessage, instance=True)
    payload = mock.create_autospec(StreamReader, instance=True)

    parser = mock.Mock()
    parser.set_upgraded = mock.Mock()
    parser.feed_data = mock.Mock(return_value=([(raw_msg, payload)], False, b""))
    handler._parser = parser
    handler._upgraded = True
    handler._message_tail = b"GET /next HTTP/1.1\r\n\r\n"

    waiter: asyncio.Future[None] = event_loop.create_future()
    handler._waiter = waiter

    request = _make_mock_request()
    resp = _make_mock_resp()

    await handler.finish_response(request, resp, None)

    # The parser must have been called with the tail bytes.
    parser.feed_data.assert_called_once_with(b"GET /next HTTP/1.1\r\n\r\n")
    # The parsed message must have been queued.
    assert len(handler._messages) == 1
    assert handler._messages[0] == (raw_msg, payload)
    # The tail must be cleared.
    assert handler._message_tail == b""
    # The waiter must have been resolved so the start() loop can proceed.
    assert waiter.done()


async def test_finish_response_handles_parse_error_in_message_tail(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """If feed_data raises HttpProcessingError while replaying the tail,
    finish_response must queue a 400 _ErrInfo instead of propagating the
    exception, and still signal the waiter."""
    handler = _make_handler(event_loop)

    parse_error = HttpProcessingError(code=400, message="Bad request")
    parser = mock.Mock()
    parser.set_upgraded = mock.Mock()
    parser.feed_data = mock.Mock(side_effect=parse_error)
    handler._parser = parser
    handler._upgraded = True
    handler._message_tail = b"BADREQUEST\r\n"

    waiter: asyncio.Future[None] = event_loop.create_future()
    handler._waiter = waiter

    request = _make_mock_request()
    resp = _make_mock_resp()

    await handler.finish_response(request, resp, None)

    # A single error message must be queued.
    assert len(handler._messages) == 1
    err_msg, err_payload = handler._messages[0]
    assert isinstance(err_msg, _ErrInfo)
    assert err_msg.status == 400
    assert err_payload is EMPTY_PAYLOAD
    # Tail must be cleared.
    assert handler._message_tail == b""
    # Waiter must be resolved.
    assert waiter.done()
