"""codspeed benchmarks for http websocket."""

import asyncio
from typing import Union

from pytest_codspeed import BenchmarkFixture

from aiohttp import DataQueue
from aiohttp._websocket.helpers import MSG_SIZE
from aiohttp.base_protocol import BaseProtocol
from aiohttp.http_websocket import (
    WebSocketReader,
    WebSocketWriter,
    WSMessage,
    WSMsgType,
)


def test_read_one_hundred_websocket_text_messages(
    loop: asyncio.AbstractEventLoop, benchmark: BenchmarkFixture
) -> None:
    """Benchmark reading 100 WebSocket text messages."""
    queue: DataQueue[WSMessage] = DataQueue(loop=loop)
    reader = WebSocketReader(queue, max_msg_size=2**16)
    raw_message = (
        b'\x81~\x01!{"id":1,"src":"shellyplugus-c049ef8c30e4","dst":"aios-1453812500'
        b'8","result":{"name":null,"id":"shellyplugus-c049ef8c30e4","mac":"C049EF8C30E'
        b'4","slot":1,"model":"SNPL-00116US","gen":2,"fw_id":"20231219-133953/1.1.0-g3'
        b'4b5d4f","ver":"1.1.0","app":"PlugUS","auth_en":false,"auth_domain":null}}'
    )
    feed_data = reader.feed_data

    @benchmark
    def _run() -> None:
        for _ in range(100):
            feed_data(raw_message)


class MockTransport(asyncio.Transport):
    """Mock transport for testing that do no real I/O."""

    def is_closing(self) -> bool:
        """Swallow is_closing."""
        return False

    def write(self, data: Union[bytes, bytearray, memoryview]) -> None:
        """Swallow writes."""


class MockProtocol(BaseProtocol):

    async def _drain_helper(self) -> None:
        """Swallow drain."""


def test_send_one_hundred_websocket_text_messages(
    loop: asyncio.AbstractEventLoop, benchmark: BenchmarkFixture
) -> None:
    """Benchmark sending 100 WebSocket text messages."""
    writer = WebSocketWriter(MockProtocol(loop=loop), MockTransport())
    raw_message = b"Hello, World!" * 100

    async def _send_one_hundred_websocket_text_messages() -> None:
        for _ in range(100):
            await writer.send_frame(raw_message, WSMsgType.TEXT)

    benchmark(loop.run_until_complete(_send_one_hundred_websocket_text_messages()))


def test_send_one_hundred_large_websocket_text_messages(
    loop: asyncio.AbstractEventLoop, benchmark: BenchmarkFixture
) -> None:
    """Benchmark sending 100 WebSocket text messages."""
    writer = WebSocketWriter(MockProtocol(loop=loop), MockTransport())
    raw_message = b"x" * MSG_SIZE * 4

    async def _send_one_hundred_websocket_text_messages() -> None:
        for _ in range(100):
            await writer.send_frame(raw_message, WSMsgType.TEXT)

    @benchmark
    def _run() -> None:
        loop.run_until_complete(_send_one_hundred_websocket_text_messages())


def test_send_one_hundred_websocket_text_messages_with_mask(
    loop: asyncio.AbstractEventLoop, benchmark: BenchmarkFixture
) -> None:
    """Benchmark sending 100 masked WebSocket text messages."""
    writer = WebSocketWriter(MockProtocol(loop=loop), MockTransport(), use_mask=True)
    raw_message = b"Hello, World!" * 100

    async def _send_one_hundred_websocket_text_messages() -> None:
        for _ in range(100):
            await writer.send_frame(raw_message, WSMsgType.TEXT)

    @benchmark
    def _run() -> None:
        loop.run_until_complete(_send_one_hundred_websocket_text_messages())
