import asyncio
from unittest import mock

import pytest

from aiohttp._websocket.models import WSMessageBinary
from aiohttp._websocket.reader import WebSocketDataQueue
from aiohttp.base_protocol import BaseProtocol


@pytest.fixture
def protocol() -> BaseProtocol:
    return mock.create_autospec(BaseProtocol, spec_set=True, instance=True, _reading_paused=False)  # type: ignore[no-any-return]


@pytest.fixture
def buffer(
    loop: asyncio.AbstractEventLoop, protocol: BaseProtocol
) -> WebSocketDataQueue:
    return WebSocketDataQueue(protocol, limit=1, loop=loop)


class TestWebSocketDataQueue:
    def test_feed_pause(self, buffer: WebSocketDataQueue) -> None:
        buffer._protocol._reading_paused = False
        for _ in range(3):
            buffer.feed_data(WSMessageBinary(b"x", size=1), 1)

        assert buffer._protocol.pause_reading.called  # type: ignore[attr-defined]

    async def test_resume_on_read(self, buffer: WebSocketDataQueue) -> None:
        buffer.feed_data(WSMessageBinary(b"x", size=1), 1)

        buffer._protocol._reading_paused = True
        await buffer.read()
        assert buffer._protocol.resume_reading.called  # type: ignore[attr-defined]
