import asyncio
from unittest import mock

import pytest

from aiohttp.http import WebSocketReader
from aiohttp.web_protocol import RequestHandler
from aiohttp.web_request import BaseRequest
from aiohttp.web_server import Server


@pytest.fixture
def dummy_manager() -> Server[BaseRequest]:
    return mock.create_autospec(Server[BaseRequest], spec_set=True, instance=True)


@pytest.fixture
def dummy_reader() -> tuple[WebSocketReader, mock.Mock]:
    m = mock.create_autospec(WebSocketReader, spec_set=True, instance=True)
    return m, m


def test_set_parser_does_not_call_data_received_cb_for_tail(
    loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
    dummy_reader: tuple[WebSocketReader, mock.Mock],
) -> None:
    handler = RequestHandler(dummy_manager, loop=loop)
    handler._message_tail = b"tail"
    cb = mock.Mock()

    handler.set_parser(dummy_reader[0], data_received_cb=cb)

    cb.assert_not_called()
    assert dummy_reader[1].feed_data.assert_called_once_with(b"tail")


def test_data_received_calls_data_received_cb(
    loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
    dummy_reader: tuple[WebSocketReader, mock.Mock],
) -> None:
    handler = RequestHandler(dummy_manager, loop=loop)
    cb = mock.Mock()

    handler.set_parser(dummy_reader[0], data_received_cb=cb)
    handler.data_received(b"x")

    assert cb.assert_called_once()
    assert dummy_reader[1].received.assert_called_once_with(b"x")
