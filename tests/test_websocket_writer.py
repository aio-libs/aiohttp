# type: ignore
import asyncio
import random
from typing import Any
from unittest import mock

import pytest

from aiohttp import DataQueue, WSMessage
from aiohttp.http import WebSocketReader, WebSocketWriter
from aiohttp.test_utils import make_mocked_coro


@pytest.fixture
def protocol():
    ret = mock.Mock()
    ret._drain_helper = make_mocked_coro()
    return ret


@pytest.fixture
def transport():
    ret = mock.Mock()
    ret.is_closing.return_value = False
    return ret


@pytest.fixture
def writer(protocol: Any, transport: Any):
    return WebSocketWriter(protocol, transport, use_mask=False)


async def test_pong(writer: Any) -> None:
    await writer.pong()
    writer.transport.write.assert_called_with(b"\x8a\x00")


async def test_ping(writer: Any) -> None:
    await writer.ping()
    writer.transport.write.assert_called_with(b"\x89\x00")


async def test_send_text(writer: Any) -> None:
    await writer.send(b"text")
    writer.transport.write.assert_called_with(b"\x81\x04text")


async def test_send_binary(writer: Any) -> None:
    await writer.send("binary", True)
    writer.transport.write.assert_called_with(b"\x82\x06binary")


async def test_send_binary_long(writer: Any) -> None:
    await writer.send(b"b" * 127, True)
    assert writer.transport.write.call_args[0][0].startswith(b"\x82~\x00\x7fb")


async def test_send_binary_very_long(writer: Any) -> None:
    await writer.send(b"b" * 65537, True)
    assert (
        writer.transport.write.call_args_list[0][0][0]
        == b"\x82\x7f\x00\x00\x00\x00\x00\x01\x00\x01"
    )
    assert writer.transport.write.call_args_list[1][0][0] == b"b" * 65537


async def test_close(writer: Any) -> None:
    await writer.close(1001, "msg")
    writer.transport.write.assert_called_with(b"\x88\x05\x03\xe9msg")

    await writer.close(1001, b"msg")
    writer.transport.write.assert_called_with(b"\x88\x05\x03\xe9msg")

    # Test that Service Restart close code is also supported
    await writer.close(1012, b"msg")
    writer.transport.write.assert_called_with(b"\x88\x05\x03\xf4msg")


async def test_send_text_masked(protocol: Any, transport: Any) -> None:
    writer = WebSocketWriter(
        protocol, transport, use_mask=True, random=random.Random(123)
    )
    await writer.send(b"text")
    writer.transport.write.assert_called_with(b"\x81\x84\rg\xb3fy\x02\xcb\x12")


async def test_send_compress_text(protocol: Any, transport: Any) -> None:
    writer = WebSocketWriter(protocol, transport, compress=15)
    await writer.send(b"text")
    writer.transport.write.assert_called_with(b"\xc1\x06*I\xad(\x01\x00")
    await writer.send(b"text")
    writer.transport.write.assert_called_with(b"\xc1\x05*\x01b\x00\x00")


async def test_send_compress_text_notakeover(protocol: Any, transport: Any) -> None:
    writer = WebSocketWriter(protocol, transport, compress=15, notakeover=True)
    await writer.send(b"text")
    writer.transport.write.assert_called_with(b"\xc1\x06*I\xad(\x01\x00")
    await writer.send(b"text")
    writer.transport.write.assert_called_with(b"\xc1\x06*I\xad(\x01\x00")


async def test_send_compress_text_per_message(protocol: Any, transport: Any) -> None:
    writer = WebSocketWriter(protocol, transport)
    await writer.send(b"text", compress=15)
    writer.transport.write.assert_called_with(b"\xc1\x06*I\xad(\x01\x00")
    await writer.send(b"text")
    writer.transport.write.assert_called_with(b"\x81\x04text")
    await writer.send(b"text", compress=15)
    writer.transport.write.assert_called_with(b"\xc1\x06*I\xad(\x01\x00")


@mock.patch("aiohttp.http_websocket.WEBSOCKET_MAX_SYNC_CHUNK_SIZE", 16)
async def test_concurrent_messages_with_executor(protocol: Any, transport: Any) -> None:
    """Ensure messages are compressed correctly when there are multiple concurrent writers.

    This test generates messages large enough that they will
    be compressed in the executor.
    """
    writer = WebSocketWriter(protocol, transport, compress=15)
    queue: DataQueue[WSMessage] = DataQueue(asyncio.get_running_loop())
    reader = WebSocketReader(queue, 50000)
    writers = []
    payloads = []
    msg_length = 16 + 1
    for count in range(1, 64 + 1):
        payload = bytes((count,)) * msg_length
        payloads.append(payload)
        writers.append(writer.send(payload, binary=True))
    await asyncio.gather(*writers)
    for call in writer.transport.write.call_args_list:
        call_bytes = call[0][0]
        result, _ = reader.feed_data(call_bytes)
        assert result is False
        msg = await queue.read()
        bytes_data: bytes = msg.data
        assert len(bytes_data) == msg_length
        assert bytes_data == bytes_data[0:1] * msg_length


async def test_concurrent_messages_without_executor(
    protocol: Any, transport: Any
) -> None:
    """Ensure messages are compressed correctly when there are multiple concurrent writers.

    This test generates messages that are small enough that
    they will not be compressed in the executor.
    """
    writer = WebSocketWriter(protocol, transport, compress=15)
    queue: DataQueue[WSMessage] = DataQueue(asyncio.get_running_loop())
    reader = WebSocketReader(queue, 50000)
    writers = []
    payloads = []
    msg_length = 16 + 1
    for count in range(1, 64 + 1):
        payload = bytes((count,)) * msg_length
        payloads.append(payload)
        writers.append(writer.send(payload, binary=True))
    await asyncio.gather(*writers)
    for call in writer.transport.write.call_args_list:
        call_bytes = call[0][0]
        result, _ = reader.feed_data(call_bytes)
        assert result is False
        msg = await queue.read()
        bytes_data: bytes = msg.data
        assert len(bytes_data) == msg_length
        assert bytes_data == bytes_data[0:1] * msg_length


@mock.patch("aiohttp.http_websocket.WEBSOCKET_MAX_SYNC_CHUNK_SIZE", 32)
async def test_concurrent_messages_with_and_with_out_executor(
    protocol: Any, transport: Any
) -> None:
    """Ensure messages are compressed correctly when there are multiple concurrent writers.

    This test generates messages mixes messages that
    are small enough to not be compressed in the executor
    with messages that need to be compressed in the executor.
    """
    writer = WebSocketWriter(protocol, transport, compress=15)
    queue: DataQueue[WSMessage] = DataQueue(asyncio.get_running_loop())
    reader = WebSocketReader(queue, 50000)
    writers = []
    payloads = []
    for count in range(1, 64 + 1):
        payload = bytes((count,)) * count
        payloads.append(payload)
        writers.append(writer.send(payload, binary=True))
    await asyncio.gather(*writers)
    for call in writer.transport.write.call_args_list:
        call_bytes = call[0][0]
        result, _ = reader.feed_data(call_bytes)
        assert result is False
        msg = await queue.read()
        bytes_data: bytes = msg.data
        first_char = bytes_data[0:1]
        char_val = ord(first_char)
        assert len(bytes_data) == char_val
        assert bytes_data == bytes_data[0:1] * char_val
