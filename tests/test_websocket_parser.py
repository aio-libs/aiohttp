import aiohttp
import pytest
import random
import struct
from unittest import mock
from aiohttp import Message, WebSocketError
from aiohttp import _ws_impl, MsgType
from aiohttp._ws_impl import (PACK_LEN1, PACK_LEN2, PACK_LEN3,
                              PACK_CLOSE_CODE,
                              CLOSE_PROTOCOL_ERROR,
                              CLOSE_INVALID_TEXT,
                              _websocket_mask,
                              WebSocketParser, parse_frame)


def build_frame(message, opcode, use_mask=False, noheader=False):
    """Send a frame over the websocket with message as its payload."""
    msg_length = len(message)
    if use_mask:  # pragma: no cover
        mask_bit = 0x80
    else:
        mask_bit = 0

    if msg_length < 126:
        header = PACK_LEN1(
            0x80 | opcode, msg_length | mask_bit)
    elif msg_length < (1 << 16):  # pragma: no cover
        header = PACK_LEN2(
            0x80 | opcode, 126 | mask_bit, msg_length)
    else:
        header = PACK_LEN3(
            0x80 | opcode, 127 | mask_bit, msg_length)

    if use_mask:  # pragma: no cover
        mask = random.randrange(0, 0xffffffff)
        mask = mask.to_bytes(4, 'big')
        message = _websocket_mask(mask, bytearray(message))
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
        opcode=MsgType.close, noheader=noheader)


@pytest.fixture()
def buf():
    return aiohttp.ParserBuffer()


@pytest.fixture()
def out(loop):
    return aiohttp.DataQueue(loop=loop)


@pytest.fixture()
def parser(buf, out):
    return WebSocketParser(out, buf)


def test_parse_frame(buf):
    p = parse_frame(buf)
    next(p)
    p.send(struct.pack('!BB', 0b00000001, 0b00000001))
    try:
        p.send(b'1')
    except StopIteration as exc:
        fin, opcode, payload = exc.value

    assert (0, 1, b'1') == (fin, opcode, payload)


def test_parse_frame_length0(buf):
    p = parse_frame(buf)
    next(p)
    try:
        p.send(struct.pack('!BB', 0b00000001, 0b00000000))
    except StopIteration as exc:
        fin, opcode, payload = exc.value

    assert (0, 1, b'') == (fin, opcode, payload)


def test_parse_frame_length2(buf):
    p = parse_frame(buf)
    next(p)
    p.send(struct.pack('!BB', 0b00000001, 126))
    p.send(struct.pack('!H', 4))
    try:
        p.send(b'1234')
    except StopIteration as exc:
        fin, opcode, payload = exc.value

    assert (0, 1, b'1234') == (fin, opcode, payload)


def test_parse_frame_length4(buf):
    p = parse_frame(buf)
    next(p)
    p.send(struct.pack('!BB', 0b00000001, 127))
    p.send(struct.pack('!Q', 4))
    try:
        p.send(b'1234')
    except StopIteration as exc:
        fin, opcode, payload = exc.value

    assert (0, 1, b'1234') == (fin, opcode, payload)


def test_parse_frame_mask(buf):
    p = parse_frame(buf)
    next(p)
    p.send(struct.pack('!BB', 0b00000001, 0b10000001))
    p.send(b'0001')
    try:
        p.send(b'1')
    except StopIteration as exc:
        fin, opcode, payload = exc.value

    assert (0, 1, b'\x01') == (fin, opcode, payload)


def test_parse_frame_header_reversed_bits(buf):
    p = parse_frame(buf)
    next(p)
    with pytest.raises(WebSocketError):
        p.send(struct.pack('!BB', 0b01100000, 0b00000000))


def test_parse_frame_header_control_frame(buf):
    p = parse_frame(buf)
    next(p)
    with pytest.raises(WebSocketError):
        p.send(struct.pack('!BB', 0b00001000, 0b00000000))


def test_parse_frame_header_continuation(buf):
    p = parse_frame(buf)
    next(p)
    with pytest.raises(WebSocketError):
        p.send(struct.pack('!BB', 0b00000000, 0b00000000))


def test_parse_frame_header_new_data_err(buf):
    p = parse_frame(buf)
    next(p)
    with pytest.raises(WebSocketError):
        p.send(struct.pack('!BB', 0b000000000, 0b00000000))


def test_parse_frame_header_payload_size(buf):
    p = parse_frame(buf)
    next(p)
    with pytest.raises(WebSocketError):
        p.send(struct.pack('!BB', 0b10001000, 0b01111110))


def test_ping_frame(out, parser):
    def parse_frame(buf):
        yield
        return (1, MsgType.ping, b'data')

    with mock.patch('aiohttp._ws_impl.parse_frame') as m_parse_frame:
        m_parse_frame.side_effect = parse_frame
        next(parser)
        parser.send(b'')
    res = out._buffer[0]
    assert res == ((MsgType.ping, b'data', ''), 4)


def test_pong_frame(out, parser):
    def parse_frame(buf):
        yield
        return (1, MsgType.pong, b'data')

    with mock.patch('aiohttp._ws_impl.parse_frame') as m_parse_frame:
        m_parse_frame.side_effect = parse_frame
        next(parser)
        parser.send(b'')
    res = out._buffer[0]
    assert res == ((MsgType.pong, b'data', ''), 4)


def test_close_frame(out, parser):
    def parse_frame(buf):
        yield
        return (1, MsgType.close, b'')

    with mock.patch('aiohttp._ws_impl.parse_frame') as m_parse_frame:
        m_parse_frame.side_effect = parse_frame
        next(parser)
        parser.send(b'')

    res = out._buffer[0]
    assert res == ((MsgType.close, 0, ''), 0)


def test_close_frame_info(out, parser):
    def parse_frame(buf):
        yield
        return (1, MsgType.close, b'0112345')

    with mock.patch('aiohttp._ws_impl.parse_frame') as m_parse_frame:
        m_parse_frame.side_effect = parse_frame
        next(parser)
        parser.send(b'')
    res = out._buffer[0]
    assert res == (Message(MsgType.close, 12337, '12345'), 0)


def test_close_frame_invalid(out, parser):
    def parse_frame(buf):
        yield
        return (1, MsgType.close, b'1')

    with mock.patch('aiohttp._ws_impl.parse_frame') as m_parse_frame:
        m_parse_frame.side_effect = parse_frame
        next(parser)
        with pytest.raises(WebSocketError) as ctx:
            next(parser)

        assert ctx.value.code == CLOSE_PROTOCOL_ERROR


def test_close_frame_invalid_2(buf, parser):
    buf.extend(build_close_frame(code=1))
    with pytest.raises(WebSocketError) as ctx:
        next(parser)

    assert ctx.value.code == CLOSE_PROTOCOL_ERROR


def test_close_frame_unicode_err(buf, parser):
    buf.extend(build_close_frame(
        code=1000, message=b'\xf4\x90\x80\x80'))
    with pytest.raises(WebSocketError) as ctx:
        next(parser)

    assert ctx.value.code == CLOSE_INVALID_TEXT


def test_unknown_frame(out, parser):
    def parse_frame(buf):
        yield
        return (1, MsgType.continuation, b'')

    with mock.patch('aiohttp._ws_impl.parse_frame') as m_parse_frame:
        m_parse_frame.side_effect = parse_frame
        next(parser)

        with pytest.raises(WebSocketError):
            parser.send(b'')


def test_simple_text(buf, out, parser):
    buf.extend(build_frame(b'text', MsgType.text))
    next(parser)
    parser.send(b'')
    res = out._buffer[0]
    assert res == ((MsgType.text, 'text', ''), 4)


def test_simple_text_unicode_err(buf, parser):
    buf.extend(
        build_frame(b'\xf4\x90\x80\x80', MsgType.text))
    with pytest.raises(WebSocketError) as ctx:
        next(parser)

    assert ctx.value.code == CLOSE_INVALID_TEXT


def test_simple_binary(out, parser):
    def parse_frame(buf):
        yield
        return (1, MsgType.binary, b'binary')
    with mock.patch('aiohttp._ws_impl.parse_frame') as m_parse_frame:
        m_parse_frame.side_effect = parse_frame
        next(parser)
        parser.send(b'')
    res = out._buffer[0]
    assert res == ((MsgType.binary, b'binary', ''), 6)


def test_continuation(out, parser):
    cur = 0

    def parse_frame(buf, cont=False):
        nonlocal cur
        yield
        if cur == 0:
            cur = 1
            return (0, MsgType.text, b'line1')
        else:
            return (1, MsgType.continuation, b'line2')

    with mock.patch('aiohttp._ws_impl.parse_frame') as m_parse_frame:
        m_parse_frame.side_effect = parse_frame
        next(parser)
        parser.send(b'')
        parser.send(b'')
    res = out._buffer[0]
    assert res == (Message(MsgType.text, 'line1line2', ''), 10)


def test_continuation_with_ping(out, parser):
    frames = [
        (0, MsgType.text, b'line1'),
        (0, MsgType.ping, b''),
        (1, MsgType.continuation, b'line2'),
    ]

    def parse_frame(buf, cont=False):
        yield
        return frames.pop(0)

    with mock.patch('aiohttp._ws_impl.parse_frame') as m_parse_frame:
        m_parse_frame.side_effect = parse_frame
        next(parser)
        parser.send(b'')
        parser.send(b'')
        parser.send(b'')
    res = out._buffer[0]
    assert res == (Message(MsgType.ping, b'', ''), 0)
    res = out._buffer[1]
    assert res == (Message(MsgType.text, 'line1line2', ''), 10)


def test_continuation_err(out, parser):
    cur = 0

    def parse_frame(buf, cont=False):
        nonlocal cur
        yield
        if cur == 0:
            cur = 1
            return (0, MsgType.text, b'line1')
        else:
            return (1, MsgType.text, b'line2')

    with mock.patch('aiohttp._ws_impl.parse_frame') as m_parse_frame:
        m_parse_frame.side_effect = parse_frame
        next(parser)
        parser.send(b'')
        with pytest.raises(WebSocketError):
            parser.send(b'')


def test_continuation_with_close(out, parser):
    frames = [
        (0, MsgType.text, b'line1'),
        (0, MsgType.close,
         build_close_frame(1002, b'test', noheader=True)),
        (1, MsgType.continuation, b'line2'),
    ]

    def parse_frame(buf, cont=False):
        yield
        return frames.pop(0)

    with mock.patch('aiohttp._ws_impl.parse_frame') as m_parse_frame:
        m_parse_frame.side_effect = parse_frame
        next(parser)
        parser.send(b'')
        parser.send(b'')
        parser.send(b'')
        res = out._buffer[0]
    assert res, (Message(MsgType.close, 1002, 'test'), 0)
    res = out._buffer[1]
    assert res == (Message(MsgType.text, 'line1line2', ''), 10)


def test_continuation_with_close_unicode_err(out, parser):
    frames = [
        (0, MsgType.text, b'line1'),
        (0, MsgType.close,
         build_close_frame(1000, b'\xf4\x90\x80\x80', noheader=True)),
        (1, MsgType.continuation, b'line2')]

    def parse_frame(buf, cont=False):
        yield
        return frames.pop(0)

    with mock.patch('aiohttp._ws_impl.parse_frame') as m_parse_frame:
        m_parse_frame.side_effect = parse_frame
        next(parser)
        parser.send(b'')
        with pytest.raises(WebSocketError) as ctx:
            parser.send(b'')

    assert ctx.value.code == CLOSE_INVALID_TEXT


def test_continuation_with_close_bad_code(out, parser):
    frames = [
        (0, MsgType.text, b'line1'),
        (0, MsgType.close,
         build_close_frame(1, b'test', noheader=True)),
        (1, MsgType.continuation, b'line2')]

    def parse_frame(buf, cont=False):
        yield
        return frames.pop(0)

    with mock.patch('aiohttp._ws_impl.parse_frame') as m_parse_frame:
        m_parse_frame.side_effect = parse_frame
        next(parser)
        parser.send(b'')
        with pytest.raises(WebSocketError) as ctx:
            parser.send(b'')

        assert ctx.value.code == CLOSE_PROTOCOL_ERROR


def test_continuation_with_close_bad_payload(out, parser):
    frames = [
        (0, MsgType.text, b'line1'),
        (0, MsgType.close, b'1'),
        (1, MsgType.continuation, b'line2')]

    def parse_frame(buf, cont=False):
        yield
        return frames.pop(0)

    with mock.patch('aiohttp._ws_impl.parse_frame') as m_parse_frame:
        m_parse_frame.side_effect = parse_frame
        next(parser)
        parser.send(b'')
        with pytest.raises(WebSocketError) as ctx:
            parser.send(b'')

        assert ctx.value.code, CLOSE_PROTOCOL_ERROR


def test_continuation_with_close_empty(out, parser):
    frames = [
        (0, MsgType.text, b'line1'),
        (0, MsgType.close, b''),
        (1, MsgType.continuation, b'line2'),
    ]

    def parse_frame(buf, cont=False):
        yield
        return frames.pop(0)

    with mock.patch('aiohttp._ws_impl.parse_frame') as m_parse_frame:
        m_parse_frame.side_effect = parse_frame
        next(parser)
        parser.send(b'')
        parser.send(b'')
        parser.send(b'')

    res = out._buffer[0]
    assert res, (Message(MsgType.close, 0, ''), 0)
    res = out._buffer[1]
    assert res == (Message(MsgType.text, 'line1line2', ''), 10)


websocket_mask_data = bytearray(
    b'some very long data for masking by websocket')
websocket_mask_mask = b'1234'
websocket_mask_masked = (b'B]^Q\x11DVFH\x12_[_U\x13PPFR\x14W]A\x14\\S@_X'
                         b'\\T\x14SK\x13CTP@[RYV@')


def test_websocket_mask_python():
    ret = _ws_impl._websocket_mask_python(websocket_mask_mask,
                                          websocket_mask_data)
    assert ret == websocket_mask_masked


@pytest.mark.skipif(not hasattr(_ws_impl, '_websocket_mask_cython'),
                    reason='Requires Cython')
def test_websocket_mask_cython():
    ret = _ws_impl._websocket_mask_cython(websocket_mask_mask,
                                          websocket_mask_data)
    assert ret == websocket_mask_masked


def test_websocket_mask_python_empty():
    ret = _ws_impl._websocket_mask_python(websocket_mask_mask,
                                          bytearray())
    assert ret == bytearray()


@pytest.mark.skipif(not hasattr(_ws_impl, '_websocket_mask_cython'),
                    reason='Requires Cython')
def test_websocket_mask_cython_empty():
    ret = _ws_impl._websocket_mask_cython(websocket_mask_mask,
                                          bytearray())
    assert ret == bytearray()
