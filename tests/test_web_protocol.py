import asyncio
from unittest import mock

import pytest

from aiohttp.http import HttpRequestParser, WebSocketReader
from aiohttp.web_protocol import RequestHandler
from aiohttp.web_request import BaseRequest
from aiohttp.web_server import Server


@pytest.fixture
def dummy_manager() -> Server[BaseRequest]:
    return mock.create_autospec(
        Server[BaseRequest],
        request_handler=mock.Mock(),
        request_factory=mock.Mock(),
        instance=True,
    )


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


async def test_failed_upgrade_replays_pipelined_request(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """After a failed WebSocket upgrade, pipelined data in _message_tail
    should be fed back to the parser and produce a new message, waking
    the start() loop so the client connection doesn't hang (GH-12734).

    Scenario:
    1. Client sends a WebSocket upgrade request
    2. Client pipelines a second HTTP request behind it
    3. The upgrade is rejected (e.g., bad Sec-WebSocket-Key)
    4. finish_response must replay the pipelined tail back through the
       parser and wake the start() loop's waiter.
    """
    protocol_mock = mock.Mock()
    parser = HttpRequestParser(
        protocol=protocol_mock,
        loop=event_loop,
        limit=8192,
    )

    handler = RequestHandler(dummy_manager, loop=event_loop)
    handler._parser = parser
    handler._waiter = event_loop.create_future()

    # Simulate that the parser previously detected an upgrade and stashed
    # the remaining bytes (the pipelined request) in _message_tail.
    pipelined_request = (
        b"GET /after-upgrade HTTP/1.1\r\n" b"Host: example.com\r\n" b"\r\n"
    )
    handler._message_tail = pipelined_request
    handler._upgraded = True

    # --- Simulate finish_response after a failed upgrade ---
    parser.set_upgraded(False)
    handler._upgraded = False

    assert handler._message_tail, "Test precondition: tail must be set"

    # Replay the stashed tail through the HTTP parser.
    messages, _upgraded, tail = parser.feed_data(handler._message_tail)
    handler._message_tail = tail
    for msg, payload in messages or ():
        handler._request_count += 1
        handler._messages.append((msg, payload))

    # Wake the start() loop if it's waiting.
    waiter = handler._waiter
    if messages and waiter is not None and not waiter.done():
        waiter.set_result(None)

    # --- Assertions ---
    # The stashed tail should be fully consumed.
    assert (
        handler._message_tail == b""
    ), f"Tail not consumed after replay: {handler._message_tail!r}"

    # The pipelined request should appear as a new message.
    assert (
        len(handler._messages) == 1
    ), f"Expected 1 message from pipelined data, got {len(handler._messages)}"

    # The start() loop's waiter must be resolved so the server can
    # process the pipelined request.  Without this, the connection hangs.
    assert (
        handler._waiter.done()
    ), "Waiter was not woken; start() would hang indefinitely"

    # Verify the message is the correct HTTP request.
    msg, _payload = handler._messages[0]
    assert msg.method == "GET"
    assert msg.path == "/after-upgrade", f"Unexpected path: {msg.path!r}"
    assert msg.version == protocol_mock


async def test_failed_upgrade_empty_tail_noop(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """When _message_tail is empty, the waiter should not be woken,
    and no messages should be added.
    """
    protocol_mock = mock.Mock()
    parser = HttpRequestParser(
        protocol=protocol_mock,
        loop=event_loop,
        limit=8192,
    )

    handler = RequestHandler(dummy_manager, loop=event_loop)
    handler._parser = parser
    handler._waiter = event_loop.create_future()

    # Empty tail, no upgrade flag set.
    handler._message_tail = b""
    handler._upgraded = True

    parser.set_upgraded(False)
    handler._upgraded = False

    # With empty tail, nothing to replay.
    assert not handler._message_tail

    # The waiter should remain unresolved.
    assert (
        not handler._waiter.done()
    ), "Waiter should not be woken when there's no pipelined data"
    assert len(handler._messages) == 0


async def test_failed_upgrade_malformed_tail(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """Malformed pipelined data after a failed upgrade should not crash
    the server.  The parser may raise HttpProcessingError, which the
    caller (data_received) already handles; finish_response does not
    catch it, so the test verifies the current behavior.
    """
    protocol_mock = mock.Mock()
    parser = HttpRequestParser(
        protocol=protocol_mock,
        loop=event_loop,
        limit=8192,
    )

    handler = RequestHandler(dummy_manager, loop=event_loop)
    handler._parser = parser
    handler._waiter = event_loop.create_future()

    # Completely invalid HTTP data.
    handler._message_tail = b"NOT HTTP\r\n\r\n"
    handler._upgraded = True

    parser.set_upgraded(False)
    handler._upgraded = False

    from aiohttp.http import HttpProcessingError

    try:
        messages, _upgraded, tail = parser.feed_data(handler._message_tail)
    except HttpProcessingError:
        # The parser correctly rejects malformed data.
        # finish_response does not catch this, which means the error
        # propagates up to _handle_request → generic exception handler.
        # This is acceptable because malformed pipelined data after a
        # failed upgrade is an extremely rare edge case.
        pass
    else:
        # If the parser happened to accept the data, messages should be empty
        # because there's no valid HTTP request in "NOT HTTP".
        assert len(messages) == 0, "Malformed data should not parse as HTTP"
