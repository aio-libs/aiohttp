import asyncio
from typing import Any, cast
from unittest import mock

from aiohttp.web_protocol import RequestHandler


class _DummyManager:
    def __init__(self) -> None:
        self.request_handler = mock.Mock()
        self.request_factory = mock.Mock()


class _DummyParser:
    def __init__(self) -> None:
        self.received: list[bytes] = []

    def feed_data(self, data: bytes) -> tuple[bool, bytes]:
        self.received.append(data)
        return False, b""


def test_set_parser_does_not_call_data_received_cb_for_tail(
    loop: asyncio.AbstractEventLoop,
) -> None:
    handler: RequestHandler[Any] = RequestHandler(cast(Any, _DummyManager()), loop=loop)
    handler._message_tail = b"tail"
    cb = mock.Mock()
    parser = _DummyParser()

    handler.set_parser(parser, data_received_cb=cb)

    cb.assert_not_called()
    assert parser.received == [b"tail"]


def test_data_received_calls_data_received_cb(
    loop: asyncio.AbstractEventLoop,
) -> None:
    handler: RequestHandler[Any] = RequestHandler(cast(Any, _DummyManager()), loop=loop)
    cb = mock.Mock()
    parser = _DummyParser()

    handler.set_parser(parser, data_received_cb=cb)
    handler.data_received(b"x")

    assert cb.call_count == 1
    assert parser.received == [b"x"]
