import random
from unittest import mock

import pytest

from aiohttp.http import WebSocketWriter
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
def writer(protocol, transport):
    return WebSocketWriter(protocol, transport, use_mask=False)


async def test_pong(writer) -> None:
    await writer.pong()
    writer.transport.write.assert_called_with(b"\x8a\x00")


async def test_ping(writer) -> None:
    await writer.ping()
    writer.transport.write.assert_called_with(b"\x89\x00")


async def test_send_text(writer) -> None:
    await writer.send(b"text")
    writer.transport.write.assert_called_with(b"\x81\x04text")


async def test_send_binary(writer) -> None:
    await writer.send("binary", True)
    writer.transport.write.assert_called_with(b"\x82\x06binary")


async def test_send_binary_long(writer) -> None:
    await writer.send(b"b" * 127, True)
    assert writer.transport.write.call_args[0][0].startswith(b"\x82~\x00\x7fb")


async def test_send_binary_very_long(writer) -> None:
    await writer.send(b"b" * 65537, True)
    assert (
        writer.transport.write.call_args_list[0][0][0]
        == b"\x82\x7f\x00\x00\x00\x00\x00\x01\x00\x01"
    )
    assert writer.transport.write.call_args_list[1][0][0] == b"b" * 65537


async def test_close(writer) -> None:
    await writer.close(1001, "msg")
    writer.transport.write.assert_called_with(b"\x88\x05\x03\xe9msg")

    await writer.close(1001, b"msg")
    writer.transport.write.assert_called_with(b"\x88\x05\x03\xe9msg")

    # Test that Service Restart close code is also supported
    await writer.close(1012, b"msg")
    writer.transport.write.assert_called_with(b"\x88\x05\x03\xf4msg")


async def test_send_text_masked(protocol, transport) -> None:
    writer = WebSocketWriter(
        protocol, transport, use_mask=True, random=random.Random(123)
    )
    await writer.send(b"text")
    writer.transport.write.assert_called_with(b"\x81\x84\rg\xb3fy\x02\xcb\x12")


async def test_send_compress_text(protocol, transport) -> None:
    writer = WebSocketWriter(protocol, transport, compress=15)
    await writer.send(b"text")
    writer.transport.write.assert_called_with(b"\xc1\x06*I\xad(\x01\x00")
    await writer.send(b"text")
    writer.transport.write.assert_called_with(b"\xc1\x05*\x01b\x00\x00")


async def test_send_compress_text_notakeover(protocol, transport) -> None:
    writer = WebSocketWriter(protocol, transport, compress=15, notakeover=True)
    await writer.send(b"text")
    writer.transport.write.assert_called_with(b"\xc1\x06*I\xad(\x01\x00")
    await writer.send(b"text")
    writer.transport.write.assert_called_with(b"\xc1\x06*I\xad(\x01\x00")


async def test_send_compress_text_per_message(protocol, transport) -> None:
    writer = WebSocketWriter(protocol, transport)
    await writer.send(b"text", compress=15)
    writer.transport.write.assert_called_with(b"\xc1\x06*I\xad(\x01\x00")
    await writer.send(b"text")
    writer.transport.write.assert_called_with(b"\x81\x04text")
    await writer.send(b"text", compress=15)
    writer.transport.write.assert_called_with(b"\xc1\x06*I\xad(\x01\x00")
