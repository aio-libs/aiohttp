import random
import struct
from unittest import mock

import pytest

import aiohttp
from aiohttp import http_websocket
from aiohttp.http import WebSocketError, WSCloseCode, WSMessage, WSMsgType
from aiohttp.http_websocket import (PACK_CLOSE_CODE, PACK_LEN1, PACK_LEN2,
                                    PACK_LEN3, WebSocketReader,
                                    _websocket_mask)


def build_frame(message, opcode, use_mask=False, noheader=False, is_fin=True):
    """Send a frame over the websocket with message as its payload."""
    msg_length = len(message)
    if use_mask:  # pragma: no cover
        mask_bit = 0x80
    else:
        mask_bit = 0

    if is_fin:
        header_first_byte = 0x80 | opcode
    else:
        header_first_byte = opcode

    if msg_length < 126:
        header = PACK_LEN1(
            header_first_byte, msg_length | mask_bit)
    elif msg_length < (1 << 16):  # pragma: no cover
        header = PACK_LEN2(
            header_first_byte, 126 | mask_bit, msg_length)
    else:
        header = PACK_LEN3(
            header_first_byte, 127 | mask_bit, msg_length)

    if use_mask:  # pragma: no cover
        mask = random.randrange(0, 0xffffffff)
        mask = mask.to_bytes(4, 'big')
        message = bytearray(message)
        _websocket_mask(mask, message)
        if noheader:
            return message
        else:
            return header + mask + message
    else:
        if noheader:
            return message
        else:
            return header + message


def build_close_frame(code=1000, message=b'', noheader=False):
    """Close the websocket, sending the specified code and message."""
    if isinstance(message, str):  # pragma: no cover
        message = message.encode('utf-8')
    return build_frame(
        PACK_CLOSE_CODE(code) + message,
        opcode=WSMsgType.CLOSE, noheader=noheader)


@pytest.fixture()
def out(loop):
    return aiohttp.DataQueue(loop=loop)


@pytest.fixture()
def parser(out):
    return WebSocketReader(out)


def test_parse_frame(parser):
    parser.parse_frame(struct.pack('!BB', 0b00000001, 0b00000001))
    res = parser.parse_frame(b'1')
    fin, opcode, payload = res[0]

    assert (0, 1, b'1') == (fin, opcode, payload)


def test_parse_frame_length0(parser):
    fin, opcode, payload = parser.parse_frame(
        struct.pack('!BB', 0b00000001, 0b00000000))[0]

    assert (0, 1, b'') == (fin, opcode, payload)


def test_parse_frame_length2(parser):
    parser.parse_frame(struct.pack('!BB', 0b00000001, 126))
    parser.parse_frame(struct.pack('!H', 4))
    res = parser.parse_frame(b'1234')
    fin, opcode, payload = res[0]

    assert (0, 1, b'1234') == (fin, opcode, payload)


def test_parse_frame_length4(parser):
    parser.parse_frame(struct.pack('!BB', 0b00000001, 127))
    parser.parse_frame(struct.pack('!Q', 4))
    fin, opcode, payload = parser.parse_frame(b'1234')[0]

    assert (0, 1, b'1234') == (fin, opcode, payload)


def test_parse_frame_mask(parser):
    parser.parse_frame(struct.pack('!BB', 0b00000001, 0b10000001))
    parser.parse_frame(b'0001')
    fin, opcode, payload = parser.parse_frame(b'1')[0]

    assert (0, 1, b'\x01') == (fin, opcode, payload)


def test_parse_frame_header_reversed_bits(out, parser):
    with pytest.raises(WebSocketError):
        parser.parse_frame(struct.pack('!BB', 0b01100000, 0b00000000))
        raise out.exception()


def test_parse_frame_header_control_frame(out, parser):
    with pytest.raises(WebSocketError):
        parser.parse_frame(struct.pack('!BB', 0b00001000, 0b00000000))
        raise out.exception()


def _test_parse_frame_header_new_data_err(out, parser):
    with pytest.raises(WebSocketError):
        parser.parse_frame(struct.pack('!BB', 0b000000000, 0b00000000))
        raise out.exception()


def test_parse_frame_header_payload_size(out, parser):
    with pytest.raises(WebSocketError):
        parser.parse_frame(struct.pack('!BB', 0b10001000, 0b01111110))
        raise out.exception()


def test_ping_frame(out, parser):
    parser.parse_frame = mock.Mock()
    parser.parse_frame.return_value = [(1, WSMsgType.PING, b'data')]

    parser.feed_data(b'')
    res = out._buffer[0]
    assert res == ((WSMsgType.PING, b'data', ''), 4)


def test_pong_frame(out, parser):
    parser.parse_frame = mock.Mock()
    parser.parse_frame.return_value = [(1, WSMsgType.PONG, b'data')]

    parser.feed_data(b'')
    res = out._buffer[0]
    assert res == ((WSMsgType.PONG, b'data', ''), 4)


def test_close_frame(out, parser):
    parser.parse_frame = mock.Mock()
    parser.parse_frame.return_value = [(1, WSMsgType.CLOSE, b'')]

    parser.feed_data(b'')
    res = out._buffer[0]
    assert res == ((WSMsgType.CLOSE, 0, ''), 0)


def test_close_frame_info(out, parser):
    parser.parse_frame = mock.Mock()
    parser.parse_frame.return_value = [(1, WSMsgType.CLOSE, b'0112345')]

    parser.feed_data(b'')
    res = out._buffer[0]
    assert res == (WSMessage(WSMsgType.CLOSE, 12337, '12345'), 0)


def test_close_frame_invalid(out, parser):
    parser.parse_frame = mock.Mock()
    parser.parse_frame.return_value = [(1, WSMsgType.CLOSE, b'1')]
    parser.feed_data(b'')

    assert isinstance(out.exception(), WebSocketError)
    assert out.exception().code == WSCloseCode.PROTOCOL_ERROR


def test_close_frame_invalid_2(out, parser):
    data = build_close_frame(code=1)

    with pytest.raises(WebSocketError) as ctx:
        parser._feed_data(data)

    assert ctx.value.code == WSCloseCode.PROTOCOL_ERROR


def test_close_frame_unicode_err(parser):
    data = build_close_frame(
        code=1000, message=b'\xf4\x90\x80\x80')

    with pytest.raises(WebSocketError) as ctx:
        parser._feed_data(data)

    assert ctx.value.code == WSCloseCode.INVALID_TEXT


def test_unknown_frame(out, parser):
    parser.parse_frame = mock.Mock()
    parser.parse_frame.return_value = [(1, WSMsgType.CONTINUATION, b'')]

    with pytest.raises(WebSocketError):
        parser.feed_data(b'')
        raise out.exception()


def test_simple_text(out, parser):
    data = build_frame(b'text', WSMsgType.TEXT)
    parser._feed_data(data)
    res = out._buffer[0]
    assert res == ((WSMsgType.TEXT, 'text', ''), 4)


def test_simple_text_unicode_err(parser):
    data = build_frame(b'\xf4\x90\x80\x80', WSMsgType.TEXT)

    with pytest.raises(WebSocketError) as ctx:
        parser._feed_data(data)

    assert ctx.value.code == WSCloseCode.INVALID_TEXT


def test_simple_binary(out, parser):
    parser.parse_frame = mock.Mock()
    parser.parse_frame.return_value = [(1, WSMsgType.BINARY, b'binary')]

    parser.feed_data(b'')
    res = out._buffer[0]
    assert res == ((WSMsgType.BINARY, b'binary', ''), 6)


def test_fragmentation_header(out, parser):
    data = build_frame(b'a', WSMsgType.TEXT)
    parser._feed_data(data[:1])
    parser._feed_data(data[1:])

    res = out._buffer[0]
    assert res == (WSMessage(WSMsgType.TEXT, 'a', ''), 1)


def test_continuation(out, parser):
    data1 = build_frame(b'line1', WSMsgType.TEXT, is_fin=False)
    parser._feed_data(data1)

    data2 = build_frame(b'line2', WSMsgType.CONTINUATION)
    parser._feed_data(data2)

    res = out._buffer[0]
    assert res == (WSMessage(WSMsgType.TEXT, 'line1line2', ''), 10)


def test_continuation_with_ping(out, parser):
    parser.parse_frame = mock.Mock()
    parser.parse_frame.return_value = [
        (0, WSMsgType.TEXT, b'line1'),
        (0, WSMsgType.PING, b''),
        (1, WSMsgType.CONTINUATION, b'line2'),
    ]

    data1 = build_frame(b'line1', WSMsgType.TEXT, is_fin=False)
    parser._feed_data(data1)

    data2 = build_frame(b'', WSMsgType.PING)
    parser._feed_data(data2)

    data3 = build_frame(b'line2', WSMsgType.CONTINUATION)
    parser._feed_data(data3)

    res = out._buffer[0]
    assert res == (WSMessage(WSMsgType.PING, b'', ''), 0)
    res = out._buffer[1]
    assert res == (WSMessage(WSMsgType.TEXT, 'line1line2', ''), 10)


def test_continuation_err(out, parser):
    parser.parse_frame = mock.Mock()
    parser.parse_frame.return_value = [
        (0, WSMsgType.TEXT, b'line1'),
        (1, WSMsgType.TEXT, b'line2')]

    with pytest.raises(WebSocketError):
        parser._feed_data(b'')


def test_continuation_with_close(out, parser):
    parser.parse_frame = mock.Mock()
    parser.parse_frame.return_value = [
        (0, WSMsgType.TEXT, b'line1'),
        (0, WSMsgType.CLOSE,
         build_close_frame(1002, b'test', noheader=True)),
        (1, WSMsgType.CONTINUATION, b'line2'),
    ]

    parser.feed_data(b'')
    res = out._buffer[0]
    assert res, (WSMessage(WSMsgType.CLOSE, 1002, 'test'), 0)
    res = out._buffer[1]
    assert res == (WSMessage(WSMsgType.TEXT, 'line1line2', ''), 10)


def test_continuation_with_close_unicode_err(out, parser):
    parser.parse_frame = mock.Mock()
    parser.parse_frame.return_value = [
        (0, WSMsgType.TEXT, b'line1'),
        (0, WSMsgType.CLOSE,
         build_close_frame(1000, b'\xf4\x90\x80\x80', noheader=True)),
        (1, WSMsgType.CONTINUATION, b'line2')]

    with pytest.raises(WebSocketError) as ctx:
        parser._feed_data(b'')

    assert ctx.value.code == WSCloseCode.INVALID_TEXT


def test_continuation_with_close_bad_code(out, parser):
    parser.parse_frame = mock.Mock()
    parser.parse_frame.return_value = [
        (0, WSMsgType.TEXT, b'line1'),
        (0, WSMsgType.CLOSE,
         build_close_frame(1, b'test', noheader=True)),
        (1, WSMsgType.CONTINUATION, b'line2')]

    with pytest.raises(WebSocketError) as ctx:
        parser._feed_data(b'')

    assert ctx.value.code == WSCloseCode.PROTOCOL_ERROR


def test_continuation_with_close_bad_payload(out, parser):
    parser.parse_frame = mock.Mock()
    parser.parse_frame.return_value = [
        (0, WSMsgType.TEXT, b'line1'),
        (0, WSMsgType.CLOSE, b'1'),
        (1, WSMsgType.CONTINUATION, b'line2')]

    with pytest.raises(WebSocketError) as ctx:
        parser._feed_data(b'')

    assert ctx.value.code, WSCloseCode.PROTOCOL_ERROR


def test_continuation_with_close_empty(out, parser):
    parser.parse_frame = mock.Mock()
    parser.parse_frame.return_value = [
        (0, WSMsgType.TEXT, b'line1'),
        (0, WSMsgType.CLOSE, b''),
        (1, WSMsgType.CONTINUATION, b'line2'),
    ]

    parser.feed_data(b'')
    res = out._buffer[0]
    assert res, (WSMessage(WSMsgType.CLOSE, 0, ''), 0)
    res = out._buffer[1]
    assert res == (WSMessage(WSMsgType.TEXT, 'line1line2', ''), 10)


websocket_mask_data = b'some very long data for masking by websocket'
websocket_mask_mask = b'1234'
websocket_mask_masked = (b'B]^Q\x11DVFH\x12_[_U\x13PPFR\x14W]A\x14\\S@_X'
                         b'\\T\x14SK\x13CTP@[RYV@')


def test_websocket_mask_python():
    message = bytearray(websocket_mask_data)
    http_websocket._websocket_mask_python(
        websocket_mask_mask, message)
    assert message == websocket_mask_masked


@pytest.mark.skipif(not hasattr(http_websocket, '_websocket_mask_cython'),
                    reason='Requires Cython')
def test_websocket_mask_cython():
    message = bytearray(websocket_mask_data)
    http_websocket._websocket_mask_cython(
        websocket_mask_mask, message)
    assert message == websocket_mask_masked


def test_websocket_mask_python_empty():
    message = bytearray()
    http_websocket._websocket_mask_python(
        websocket_mask_mask, message)
    assert message == bytearray()


@pytest.mark.skipif(not hasattr(http_websocket, '_websocket_mask_cython'),
                    reason='Requires Cython')
def test_websocket_mask_cython_empty():
    message = bytearray()
    http_websocket._websocket_mask_cython(
        websocket_mask_mask, message)
    assert message == bytearray()


def test_msgtype_aliases():
    assert aiohttp.WSMsgType.TEXT == aiohttp.WSMsgType.text
    assert aiohttp.WSMsgType.BINARY == aiohttp.WSMsgType.binary
    assert aiohttp.WSMsgType.PING == aiohttp.WSMsgType.ping
    assert aiohttp.WSMsgType.PONG == aiohttp.WSMsgType.pong
    assert aiohttp.WSMsgType.CLOSE == aiohttp.WSMsgType.close
    assert aiohttp.WSMsgType.CLOSED == aiohttp.WSMsgType.closed
    assert aiohttp.WSMsgType.ERROR == aiohttp.WSMsgType.error
