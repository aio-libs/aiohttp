import asyncio
from collections import deque
from unittest import mock

import pytest

from aiohttp.http import HttpRequestParser, RawRequestMessage, WebSocketReader
from aiohttp.streams import StreamReader
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


def test_finish_response_replays_message_tail(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """Replay pipelined requests after a failed websocket upgrade.

    When a websocket upgrade fails and _message_tail contains a pipelined
    HTTP request, finish_response must parse the tail and queue the message
    so the connection does not hang forever.
    """
    handler = RequestHandler(dummy_manager, loop=event_loop)

    # Build a mock parser whose feed_data returns a synthetic message
    mock_parser = mock.create_autospec(HttpRequestParser, spec_set=True, instance=True)
    mock_msg = mock.create_autospec(RawRequestMessage, spec_set=True, instance=True)
    mock_payload = mock.create_autospec(StreamReader, spec_set=True, instance=True)
    mock_parser.feed_data.return_value = [(mock_msg, mock_payload)], False, b""
    handler._parser = mock_parser
    handler._messages = deque()
    handler._message_tail = b"GET /second HTTP/1.1\r\nHost: localhost\r\n\r\n"

    # _waiter must exist so finish_response can signal it
    handler._waiter = event_loop.create_future()

    # Build a minimal request/response pair
    request = mock.create_autospec(BaseRequest, spec_set=True, instance=True)
    response = mock.Mock()
    response.prepare = mock.AsyncMock()
    response.write_eof = mock.AsyncMock()

    async def _run() -> None:
        await handler.finish_response(request, response, None)

    event_loop.run_until_complete(_run())

    # The tail should have been fed to the parser
    mock_parser.feed_data.assert_called_once_with(
        b"GET /second HTTP/1.1\r\nHost: localhost\r\n\r\n"
    )
    # The parsed message must be queued
    assert len(handler._messages) == 1
    assert handler._messages[0] == (mock_msg, mock_payload)
    # The waiter must be resolved so the main loop can proceed
    assert handler._waiter.done()
    assert handler._message_tail == b""
    assert handler._upgraded is False
    assert mock_parser.set_upgraded.called
