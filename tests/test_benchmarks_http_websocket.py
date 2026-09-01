"""codspeed benchmarks for http websocket."""

import asyncio
from typing import TYPE_CHECKING

import pytest

from aiohttp._websocket.helpers import MSG_SIZE, PACK_LEN1, PACK_LEN3, websocket_mask
from aiohttp._websocket.reader import WebSocketDataQueue
from aiohttp.base_protocol import BaseProtocol
from aiohttp.helpers import DEFAULT_CHUNK_SIZE
from aiohttp.http_websocket import WebSocketReader, WebSocketWriter, WSMsgType

if TYPE_CHECKING:
    from pytest_codspeed import BenchmarkFixture
else:
    pytest_codspeed = pytest.importorskip("pytest_codspeed")
    BenchmarkFixture = pytest_codspeed.BenchmarkFixture


# Large enough that a benchmark run never crosses the queue limit; hitting it
# would engage read backpressure and silently stop the parser mid-benchmark.
READ_QUEUE_LIMIT = 2**24
MASK = b"\x9a\x3c\x71\xe5"
TEXT_MESSAGE_FRAME = (
    b'\x81~\x01!{"id":1,"src":"shellyplugus-c049ef8c30e4","dst":"aios-1453812500'
    b'8","result":{"name":null,"id":"shellyplugus-c049ef8c30e4","mac":"C049EF8C30E'
    b'4","slot":1,"model":"SNPL-00116US","gen":2,"fw_id":"20231219-133953/1.1.0-g3'
    b'4b5d4f","ver":"1.1.0","app":"PlugUS","auth_en":false,"auth_domain":null}}'
)


def _make_queue(event_loop: asyncio.AbstractEventLoop) -> WebSocketDataQueue:
    protocol = BaseProtocol(event_loop)
    # A WebSocket connection is always upgraded; without this, backpressure
    # would hit ``assert self._parser is not None`` in pause_reading().
    protocol._upgraded = True
    return WebSocketDataQueue(protocol, READ_QUEUE_LIMIT, loop=event_loop)


def _make_reader(
    event_loop: asyncio.AbstractEventLoop, queue: WebSocketDataQueue | None = None
) -> WebSocketReader:
    if queue is None:
        queue = _make_queue(event_loop)
    return WebSocketReader(
        queue, max_msg_size=DEFAULT_CHUNK_SIZE, compress=True, decode_text=True
    )


def _masked_frame(opcode: WSMsgType, payload: bytes) -> bytes:
    """Build a client-to-server frame with a masked payload."""
    masked = bytearray(payload)
    websocket_mask(MASK, masked)
    first_byte = 0x80 | opcode.value
    length = len(payload)
    assert length < 126 or length > 2**16
    if length < 126:
        header = PACK_LEN1(first_byte, 0x80 | length)
    else:
        header = PACK_LEN3(first_byte, 0x80 | 127, length)
    return header + MASK + bytes(masked)


def test_read_large_binary_websocket_messages(
    event_loop: asyncio.AbstractEventLoop, benchmark: BenchmarkFixture
) -> None:
    """Read one hundred large binary websocket messages."""
    # PACK3 has a minimum message length of 2**16 bytes.
    message = b"x" * ((2**16) + 1)
    msg_length = len(message)
    first_byte = 0x80 | 0 | WSMsgType.BINARY.value
    header = PACK_LEN3(first_byte, 127, msg_length)
    raw_message = header + message

    @benchmark
    def _run() -> None:
        feed_data = _make_reader(event_loop).feed_data
        for _ in range(100):
            feed_data(raw_message)


def test_read_one_hundred_websocket_text_messages(
    event_loop: asyncio.AbstractEventLoop, benchmark: BenchmarkFixture
) -> None:
    """Benchmark reading 100 WebSocket text messages."""
    raw_message = TEXT_MESSAGE_FRAME

    @benchmark
    def _run() -> None:
        feed_data = _make_reader(event_loop).feed_data
        for _ in range(100):
            feed_data(raw_message)


def test_read_one_hundred_masked_websocket_text_messages(
    event_loop: asyncio.AbstractEventLoop, benchmark: BenchmarkFixture
) -> None:
    """Read 100 small masked text messages, as a server receives them."""
    raw_message = _masked_frame(WSMsgType.TEXT, b'{"id":1,"type":"ping"}')

    @benchmark
    def _run() -> None:
        feed_data = _make_reader(event_loop).feed_data
        for _ in range(100):
            feed_data(raw_message)


def test_read_one_hundred_masked_large_binary_websocket_messages(
    event_loop: asyncio.AbstractEventLoop, benchmark: BenchmarkFixture
) -> None:
    """Read 100 large masked binary messages, as a server receives them."""
    raw_message = _masked_frame(WSMsgType.BINARY, b"x" * ((2**16) + 1))

    @benchmark
    def _run() -> None:
        feed_data = _make_reader(event_loop).feed_data
        for _ in range(100):
            feed_data(raw_message)


def test_read_and_drain_one_hundred_websocket_text_messages(
    event_loop: asyncio.AbstractEventLoop, benchmark: BenchmarkFixture
) -> None:
    """Feed 100 text messages and drain them through WebSocketDataQueue.read()."""

    async def _feed_and_drain() -> None:
        queue = _make_queue(event_loop)
        feed_data = _make_reader(event_loop, queue).feed_data
        read = queue.read
        for _ in range(100):
            feed_data(TEXT_MESSAGE_FRAME)
        for _ in range(100):
            await read()

    @benchmark
    def _run() -> None:
        event_loop.run_until_complete(_feed_and_drain())


class MockTransport(asyncio.Transport):
    """Mock transport for testing that do no real I/O."""

    def is_closing(self) -> bool:
        """Swallow is_closing."""
        return False

    def write(self, data: bytes | bytearray | memoryview) -> None:
        """Swallow writes."""


class MockProtocol(BaseProtocol):

    async def _drain_helper(self) -> None:
        """Swallow drain."""


def test_send_one_hundred_websocket_text_messages(
    event_loop: asyncio.AbstractEventLoop, benchmark: BenchmarkFixture
) -> None:
    """Benchmark sending 100 WebSocket text messages."""
    writer = WebSocketWriter(MockProtocol(loop=event_loop), MockTransport())
    raw_message = b"Hello, World!" * 100

    async def _send_one_hundred_websocket_text_messages() -> None:
        for _ in range(100):
            await writer.send_frame(raw_message, WSMsgType.TEXT)

    @benchmark
    def _run() -> None:
        event_loop.run_until_complete(_send_one_hundred_websocket_text_messages())


def test_send_one_hundred_large_websocket_text_messages(
    event_loop: asyncio.AbstractEventLoop, benchmark: BenchmarkFixture
) -> None:
    """Benchmark sending 100 WebSocket text messages."""
    writer = WebSocketWriter(MockProtocol(loop=event_loop), MockTransport())
    raw_message = b"x" * MSG_SIZE * 4

    async def _send_one_hundred_websocket_text_messages() -> None:
        for _ in range(100):
            await writer.send_frame(raw_message, WSMsgType.TEXT)

    @benchmark
    def _run() -> None:
        event_loop.run_until_complete(_send_one_hundred_websocket_text_messages())


def test_send_one_hundred_websocket_text_messages_with_mask(
    event_loop: asyncio.AbstractEventLoop, benchmark: BenchmarkFixture
) -> None:
    """Benchmark sending 100 masked WebSocket text messages."""
    writer = WebSocketWriter(
        MockProtocol(loop=event_loop), MockTransport(), use_mask=True
    )
    raw_message = b"Hello, World!" * 100

    async def _send_one_hundred_websocket_text_messages() -> None:
        for _ in range(100):
            await writer.send_frame(raw_message, WSMsgType.TEXT)

    @benchmark
    def _run() -> None:
        event_loop.run_until_complete(_send_one_hundred_websocket_text_messages())


@pytest.mark.usefixtures("parametrize_zlib_backend")
def test_send_one_hundred_websocket_compressed_messages(
    event_loop: asyncio.AbstractEventLoop, benchmark: BenchmarkFixture
) -> None:
    """Benchmark sending 100 WebSocket compressed messages."""
    writer = WebSocketWriter(
        MockProtocol(loop=event_loop), MockTransport(), compress=15
    )
    raw_message = b"Hello, World!" * 100

    async def _send_one_hundred_websocket_compressed_messages() -> None:
        for _ in range(100):
            await writer.send_frame(raw_message, WSMsgType.BINARY)

    @benchmark
    def _run() -> None:
        event_loop.run_until_complete(_send_one_hundred_websocket_compressed_messages())
