import random
from unittest import mock

import pytest

from aiohttp.http import WebSocketWriter


@pytest.fixture
def protocol():
    return mock.Mock()


@pytest.fixture
def transport():
    return mock.Mock()


@pytest.fixture
def writer(protocol, transport):
    return WebSocketWriter(protocol, transport, use_mask=False)


def test_pong(writer):
    writer.pong()
    writer.transport.write.assert_called_with(b'\x8a\x00')


def test_ping(writer):
    writer.ping()
    writer.transport.write.assert_called_with(b'\x89\x00')


def test_send_text(writer):
    writer.send(b'text')
    writer.transport.write.assert_called_with(b'\x81\x04text')


def test_send_binary(writer):
    writer.send('binary', True)
    writer.transport.write.assert_called_with(b'\x82\x06binary')


def test_send_binary_long(writer):
    writer.send(b'b' * 127, True)
    assert writer.transport.write.call_args[0][0].startswith(b'\x82~\x00\x7fb')


def test_send_binary_very_long(writer):
    writer.send(b'b' * 65537, True)
    assert (writer.transport.write.call_args_list[0][0][0] ==
            b'\x82\x7f\x00\x00\x00\x00\x00\x01\x00\x01')
    assert writer.transport.write.call_args_list[1][0][0] == b'b' * 65537


def test_close(writer):
    writer.close(1001, 'msg')
    writer.transport.write.assert_called_with(b'\x88\x05\x03\xe9msg')

    writer.close(1001, b'msg')
    writer.transport.write.assert_called_with(b'\x88\x05\x03\xe9msg')

    # Test that Service Restart close code is also supported
    writer.close(1012, b'msg')
    writer.transport.write.assert_called_with(b'\x88\x05\x03\xf4msg')


def test_send_text_masked(protocol, transport):
    writer = WebSocketWriter(protocol,
                             transport,
                             use_mask=True,
                             random=random.Random(123))
    writer.send(b'text')
    writer.transport.write.assert_called_with(b'\x81\x84\rg\xb3fy\x02\xcb\x12')


def test_send_compress_text(protocol, transport):
    writer = WebSocketWriter(protocol, transport, compress=15)
    writer.send(b'text')
    writer.transport.write.assert_called_with(b'\xc1\x06*I\xad(\x01\x00')
    writer.send(b'text')
    writer.transport.write.assert_called_with(b'\xc1\x05*\x01b\x00\x00')


def test_send_compress_text_notakeover(protocol, transport):
    writer = WebSocketWriter(protocol,
                             transport,
                             compress=15,
                             notakeover=True)
    writer.send(b'text')
    writer.transport.write.assert_called_with(b'\xc1\x06*I\xad(\x01\x00')
    writer.send(b'text')
    writer.transport.write.assert_called_with(b'\xc1\x06*I\xad(\x01\x00')


def test_send_compress_text_per_message(protocol, transport):
    writer = WebSocketWriter(protocol, transport)
    writer.send(b'text', compress=15)
    writer.transport.write.assert_called_with(b'\xc1\x06*I\xad(\x01\x00')
    writer.send(b'text')
    writer.transport.write.assert_called_with(b'\x81\x04text')
    writer.send(b'text', compress=15)
    writer.transport.write.assert_called_with(b'\xc1\x06*I\xad(\x01\x00')
