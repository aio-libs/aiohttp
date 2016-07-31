import random
from unittest import mock

import pytest

from aiohttp._ws_impl import WebSocketWriter


@pytest.fixture
def transport():
    return mock.Mock()


@pytest.fixture
def writer(transport):
    return WebSocketWriter(transport, use_mask=False)


def test_pong(transport, writer):
    writer.pong()
    transport.write.assert_called_with(b'\x8a\x00')


def test_ping(transport, writer):
    writer.ping()
    transport.write.assert_called_with(b'\x89\x00')


def test_send_text(transport, writer):
    writer.send(b'text')
    transport.write.assert_called_with(b'\x81\x04text')


def test_send_binary(transport, writer):
    writer.send('binary', True)
    transport.write.assert_called_with(b'\x82\x06binary')


def test_send_binary_long(transport, writer):
    writer.send(b'b' * 127, True)
    assert transport.write.call_args[0][0].startswith(b'\x82~\x00\x7fb')


def test_send_binary_very_long(transport, writer):
    writer.send(b'b' * 65537, True)
    assert (transport.write.call_args_list[0][0][0] ==
            b'\x82\x7f\x00\x00\x00\x00\x00\x01\x00\x01')
    assert transport.write.call_args_list[1][0][0] == b'b' * 65537


def test_close(transport, writer):
    writer.close(1001, 'msg')
    transport.write.assert_called_with(b'\x88\x05\x03\xe9msg')

    writer.close(1001, b'msg')
    transport.write.assert_called_with(b'\x88\x05\x03\xe9msg')

    # Test that Service Restart close code is also supported
    writer.close(1012, b'msg')
    transport.write.assert_called_with(b'\x88\x05\x03\xf4msg')


def test_send_text_masked(transport, writer):
    writer = WebSocketWriter(transport,
                             use_mask=True,
                             random=random.Random(123))
    writer.send(b'text')
    transport.write.assert_called_with(b'\x81\x84\rg\xb3fy\x02\xcb\x12')
