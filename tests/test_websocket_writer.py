import asyncio
import random
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from unittest import mock

import pytest

from aiohttp import WSMsgType
from aiohttp._websocket.reader import WebSocketDataQueue
from aiohttp.base_protocol import BaseProtocol
from aiohttp.compression_utils import ZLibBackend
from aiohttp.http import WebSocketReader, WebSocketWriter


@pytest.fixture
def protocol() -> mock.Mock:
    ret = mock.Mock()
    ret._drain_helper = mock.AsyncMock()
    return ret


@pytest.fixture
def transport() -> mock.Mock:
    ret = mock.Mock()
    ret.is_closing.return_value = False
    return ret


@pytest.fixture
def writer(protocol: BaseProtocol, transport: asyncio.Transport) -> WebSocketWriter:
    return WebSocketWriter(protocol, transport, use_mask=False)


async def test_pong(writer: WebSocketWriter) -> None:
    await writer.send_frame(b"", WSMsgType.PONG)
    writer.transport.write.assert_called_with(b"\x8a\x00")  # type: ignore[attr-defined]


async def test_ping(writer: WebSocketWriter) -> None:
    await writer.send_frame(b"", WSMsgType.PING)
    writer.transport.write.assert_called_with(b"\x89\x00")  # type: ignore[attr-defined]


async def test_send_text(writer: WebSocketWriter) -> None:
    await writer.send_frame(b"text", WSMsgType.TEXT)
    writer.transport.write.assert_called_with(b"\x81\x04text")  # type: ignore[attr-defined]


async def test_send_binary(writer: WebSocketWriter) -> None:
    await writer.send_frame(b"binary", WSMsgType.BINARY)
    writer.transport.write.assert_called_with(b"\x82\x06binary")  # type: ignore[attr-defined]


async def test_send_binary_long(writer: WebSocketWriter) -> None:
    await writer.send_frame(b"b" * 127, WSMsgType.BINARY)
    assert writer.transport.write.call_args[0][0].startswith(b"\x82~\x00\x7fb")  # type: ignore[attr-defined]


async def test_send_binary_very_long(writer: WebSocketWriter) -> None:
    await writer.send_frame(b"b" * 65537, WSMsgType.BINARY)
    assert (
        writer.transport.write.call_args_list[0][0][0]  # type: ignore[attr-defined]
        == b"\x82\x7f\x00\x00\x00\x00\x00\x01\x00\x01"
    )
    assert writer.transport.write.call_args_list[1][0][0] == b"b" * 65537  # type: ignore[attr-defined]


async def test_close(writer: WebSocketWriter) -> None:
    await writer.close(1001, "msg")
    writer.transport.write.assert_called_with(b"\x88\x05\x03\xe9msg")  # type: ignore[attr-defined]

    await writer.close(1001, b"msg")
    writer.transport.write.assert_called_with(b"\x88\x05\x03\xe9msg")  # type: ignore[attr-defined]

    # Test that Service Restart close code is also supported
    await writer.close(1012, b"msg")
    writer.transport.write.assert_called_with(b"\x88\x05\x03\xf4msg")  # type: ignore[attr-defined]


async def test_send_text_masked(
    protocol: BaseProtocol, transport: asyncio.Transport
) -> None:
    writer = WebSocketWriter(
        protocol, transport, use_mask=True, random=random.Random(123)
    )
    await writer.send_frame(b"text", WSMsgType.TEXT)
    writer.transport.write.assert_called_with(b"\x81\x84\rg\xb3fy\x02\xcb\x12")  # type: ignore[attr-defined]


@pytest.mark.usefixtures("parametrize_zlib_backend")
async def test_send_compress_text(
    protocol: BaseProtocol, transport: asyncio.Transport
) -> None:
    compress_obj = ZLibBackend.compressobj(level=ZLibBackend.Z_BEST_SPEED, wbits=-15)
    writer = WebSocketWriter(protocol, transport, compress=15)

    msg = (
        compress_obj.compress(b"text") + compress_obj.flush(ZLibBackend.Z_SYNC_FLUSH)
    ).removesuffix(b"\x00\x00\xff\xff")
    await writer.send_frame(b"text", WSMsgType.TEXT)
    writer.transport.write.assert_called_with(  # type: ignore[attr-defined]
        b"\xc1" + len(msg).to_bytes(1, "big") + msg
    )

    msg = (
        compress_obj.compress(b"text") + compress_obj.flush(ZLibBackend.Z_SYNC_FLUSH)
    ).removesuffix(b"\x00\x00\xff\xff")
    await writer.send_frame(b"text", WSMsgType.TEXT)
    writer.transport.write.assert_called_with(  # type: ignore[attr-defined]
        b"\xc1" + len(msg).to_bytes(1, "big") + msg
    )


@pytest.mark.usefixtures("parametrize_zlib_backend")
async def test_send_compress_text_notakeover(
    protocol: BaseProtocol, transport: asyncio.Transport
) -> None:
    compress_obj = ZLibBackend.compressobj(level=ZLibBackend.Z_BEST_SPEED, wbits=-15)
    writer = WebSocketWriter(protocol, transport, compress=15, notakeover=True)

    msg = (
        compress_obj.compress(b"text") + compress_obj.flush(ZLibBackend.Z_FULL_FLUSH)
    ).removesuffix(b"\x00\x00\xff\xff")
    await writer.send_frame(b"text", WSMsgType.TEXT)
    writer.transport.write.assert_called_with(  # type: ignore[attr-defined]
        b"\xc1" + len(msg).to_bytes(1, "big") + msg
    )
    await writer.send_frame(b"text", WSMsgType.TEXT)
    writer.transport.write.assert_called_with(  # type: ignore[attr-defined]
        b"\xc1" + len(msg).to_bytes(1, "big") + msg
    )


async def test_send_compress_text_per_message(
    protocol: BaseProtocol, transport: asyncio.Transport
) -> None:
    writer = WebSocketWriter(protocol, transport)
    await writer.send_frame(b"text", WSMsgType.TEXT, compress=15)
    writer.transport.write.assert_called_with(b"\xc1\x06*I\xad(\x01\x00")  # type: ignore[attr-defined]
    await writer.send_frame(b"text", WSMsgType.TEXT)
    writer.transport.write.assert_called_with(b"\x81\x04text")  # type: ignore[attr-defined]
    await writer.send_frame(b"text", WSMsgType.TEXT, compress=15)
    writer.transport.write.assert_called_with(b"\xc1\x06*I\xad(\x01\x00")  # type: ignore[attr-defined]


@pytest.mark.usefixtures("parametrize_zlib_backend")
async def test_send_compress_cancelled(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    slow_executor: ThreadPoolExecutor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that cancelled compression doesn't corrupt subsequent sends.

    Regression test for https://github.com/aio-libs/aiohttp/issues/11725
    """
    monkeypatch.setattr("aiohttp._websocket.writer.WEBSOCKET_MAX_SYNC_CHUNK_SIZE", 1024)
    writer = WebSocketWriter(protocol, transport, compress=15)
    loop = asyncio.get_running_loop()
    queue = WebSocketDataQueue(mock.Mock(_reading_paused=False), 2**16, loop=loop)
    reader = WebSocketReader(queue, 50000)

    # Replace executor with slow one to make race condition reproducible
    writer._compressobj = writer._get_compressor(None)
    writer._compressobj._executor = slow_executor

    # Create large data that will trigger executor-based compression
    large_data_1 = b"A" * 10000
    large_data_2 = b"B" * 10000

    # Start first send and cancel it during compression
    async def send_and_cancel() -> None:
        await writer.send_frame(large_data_1, WSMsgType.BINARY)

    task = asyncio.create_task(send_and_cancel())
    # Give it a moment to start compression
    await asyncio.sleep(0.01)
    task.cancel()

    # Await task cancellation (expected and intentionally ignored)
    with suppress(asyncio.CancelledError):
        await task

    # Send second message - this should NOT be corrupted
    await writer.send_frame(large_data_2, WSMsgType.BINARY)

    # Verify the second send produced correct data
    last_call = writer.transport.write.call_args_list[-1]  # type: ignore[attr-defined]
    call_bytes = last_call[0][0]
    result, _ = reader.feed_data(call_bytes)
    assert result is False
    msg = await queue.read()
    assert msg.type is WSMsgType.BINARY
    # The data should be all B's, not mixed with A's from the cancelled send
    assert msg.data == large_data_2


@pytest.mark.usefixtures("parametrize_zlib_backend")
async def test_send_compress_multiple_cancelled(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    slow_executor: ThreadPoolExecutor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that multiple compressed sends all complete despite cancellation.

    Regression test for https://github.com/aio-libs/aiohttp/issues/11725
    This verifies that once a send operation enters the shield, it completes
    even if cancelled. The lock serializes sends, so they process one at a time.
    """
    monkeypatch.setattr("aiohttp._websocket.writer.WEBSOCKET_MAX_SYNC_CHUNK_SIZE", 1024)
    writer = WebSocketWriter(protocol, transport, compress=15)
    loop = asyncio.get_running_loop()
    queue = WebSocketDataQueue(mock.Mock(_reading_paused=False), 2**16, loop=loop)
    reader = WebSocketReader(queue, 50000)

    # Replace executor with slow one
    writer._compressobj = writer._get_compressor(None)
    writer._compressobj._executor = slow_executor

    # Create 5 large messages with different content
    messages = [bytes([ord("A") + i]) * 10000 for i in range(5)]

    # Start sending all 5 messages - they'll queue due to the lock
    tasks = [
        asyncio.create_task(writer.send_frame(msg, WSMsgType.BINARY))
        for msg in messages
    ]

    # Cancel all tasks during execution
    # Tasks in the shield will complete, tasks waiting for lock will cancel
    await asyncio.sleep(0.03)  # Let one or two enter the shield
    for task in tasks:
        task.cancel()

    # Collect results
    cancelled_count = 0
    for task in tasks:
        try:
            await task
        except asyncio.CancelledError:
            cancelled_count += 1

    # At least one message should have been sent (the one in the shield)
    sent_count = len(writer.transport.write.call_args_list)  # type: ignore[attr-defined]
    assert sent_count >= 1, "At least one send should complete due to shield"
    assert sent_count <= 5, "Can't send more than 5 messages"

    # Verify all sent messages are correct (no corruption)
    for i in range(sent_count):
        call = writer.transport.write.call_args_list[i]  # type: ignore[attr-defined]
        call_bytes = call[0][0]
        result, _ = reader.feed_data(call_bytes)
        assert result is False
        msg = await queue.read()
        assert msg.type is WSMsgType.BINARY
        # Verify the data matches the expected message
        expected_byte = bytes([ord("A") + i])
        assert msg.data == expected_byte * 10000, f"Message {i} corrupted"


@pytest.mark.parametrize(
    ("max_sync_chunk_size", "payload_point_generator"),
    (
        (16, lambda count: count),
        (4096, lambda count: count),
        (32, lambda count: 64 + count if count % 2 else count),
    ),
)
@pytest.mark.usefixtures("parametrize_zlib_backend")
async def test_concurrent_messages(
    protocol: BaseProtocol,
    transport: asyncio.Transport,
    max_sync_chunk_size: int,
    payload_point_generator: Callable[[int], int],
) -> None:
    """Ensure messages are compressed correctly when there are multiple concurrent writers.

    This test generates is parametrized to

    - Generate messages that are larger than patch
      WEBSOCKET_MAX_SYNC_CHUNK_SIZE of 16
      where compression will run in the executor

    - Generate messages that are smaller than patch
      WEBSOCKET_MAX_SYNC_CHUNK_SIZE of 4096
      where compression will run in the event loop

    - Interleave generated messages with a
      WEBSOCKET_MAX_SYNC_CHUNK_SIZE of 32
      where compression will run in the event loop
      and in the executor
    """
    with mock.patch(
        "aiohttp._websocket.writer.WEBSOCKET_MAX_SYNC_CHUNK_SIZE", max_sync_chunk_size
    ):
        writer = WebSocketWriter(protocol, transport, compress=15)
        loop = asyncio.get_running_loop()
        queue = WebSocketDataQueue(mock.Mock(_reading_paused=False), 2**16, loop=loop)
        reader = WebSocketReader(queue, 50000)
        writers = []
        payloads = []
        for count in range(1, 64 + 1):
            point = payload_point_generator(count)
            payload = bytes((point,)) * point
            payloads.append(payload)
            writers.append(writer.send_frame(payload, WSMsgType.BINARY))
        await asyncio.gather(*writers)

    for call in writer.transport.write.call_args_list:  # type: ignore[attr-defined]
        call_bytes = call[0][0]
        result, _ = reader.feed_data(call_bytes)
        assert result is False
        msg = await queue.read()
        assert msg.type is WSMsgType.BINARY
        bytes_data = msg.data
        first_char = bytes_data[0:1]
        char_val = ord(first_char)
        assert len(bytes_data) == char_val
        # If we have a concurrency problem, the data
        # tends to get mixed up between messages so
        # we want to validate that all the bytes are
        # the same value
        assert bytes_data == bytes_data[0:1] * char_val
