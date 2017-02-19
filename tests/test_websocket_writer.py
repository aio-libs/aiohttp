import random
from unittest import mock

import pytest

from aiohttp.http import WebSocketWriter


@pytest.fixture
def stream():
    return mock.Mock()


@pytest.fixture
def writer(stream):
    return WebSocketWriter(stream, use_mask=False)


def test_pong(stream, writer):
    writer.pong()
    stream.transport.write.assert_called_with(b'\x8a\x00')


def test_ping(stream, writer):
    writer.ping()
    stream.transport.write.assert_called_with(b'\x89\x00')


def test_send_text(stream, writer):
    writer.send(b'text')
    stream.transport.write.assert_called_with(b'\x81\x04text')


def test_send_binary(stream, writer):
    writer.send('binary', True)
    stream.transport.write.assert_called_with(b'\x82\x06binary')


def test_send_binary_long(stream, writer):
    writer.send(b'b' * 127, True)
    assert stream.transport.write.call_args[0][0].startswith(b'\x82~\x00\x7fb')


def test_send_binary_very_long(stream, writer):
    writer.send(b'b' * 65537, True)
    assert (stream.transport.write.call_args_list[0][0][0] ==
            b'\x82\x7f\x00\x00\x00\x00\x00\x01\x00\x01')
    assert stream.transport.write.call_args_list[1][0][0] == b'b' * 65537


def test_close(stream, writer):
    writer.close(1001, 'msg')
    stream.transport.write.assert_called_with(b'\x88\x05\x03\xe9msg')

    writer.close(1001, b'msg')
    stream.transport.write.assert_called_with(b'\x88\x05\x03\xe9msg')

    # Test that Service Restart close code is also supported
    writer.close(1012, b'msg')
    stream.transport.write.assert_called_with(b'\x88\x05\x03\xf4msg')


def test_send_text_masked(stream, writer):
    writer = WebSocketWriter(stream,
                             use_mask=True,
                             random=random.Random(123))
    writer.send(b'text')
    stream.transport.write.assert_called_with(b'\x81\x84\rg\xb3fy\x02\xcb\x12')
