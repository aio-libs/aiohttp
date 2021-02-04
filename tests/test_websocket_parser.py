# type: ignore
import pickle
import random
import struct
import zlib
from typing import Any
from unittest import mock

import pytest

import aiohttp
from aiohttp import http_websocket
from aiohttp.http import WebSocketError, WSCloseCode, WSMessage, WSMsgType
from aiohttp.http_websocket import (
    _WS_DEFLATE_TRAILING,
    PACK_CLOSE_CODE,
    PACK_LEN1,
    PACK_LEN2,
    PACK_LEN3,
    WebSocketReader,
    _websocket_mask,
)


def build_frame(
    message: Any,
    opcode: Any,
    use_mask: bool = False,
    noheader: bool = False,
    is_fin: bool = True,
    compress: bool = False,
):
    # Send a frame over the websocket with message as its payload.
    if compress:
        compressobj = zlib.compressobj(wbits=-9)
        message = compressobj.compress(message)
        message = message + compressobj.flush(zlib.Z_SYNC_FLUSH)
        if message.endswith(_WS_DEFLATE_TRAILING):
            message = message[:-4]
    msg_length = len(message)
    if use_mask:  # pragma: no cover
        mask_bit = 0x80
    else:
        mask_bit = 0

    if is_fin:
        header_first_byte = 0x80 | opcode
    else:
        header_first_byte = opcode

    if compress:
        header_first_byte |= 0x40

    if msg_length < 126:
        header = PACK_LEN1(header_first_byte, msg_length | mask_bit)
    elif msg_length < (1 << 16):  # pragma: no cover
        header = PACK_LEN2(header_first_byte, 126 | mask_bit, msg_length)
    else:
        header = PACK_LEN3(header_first_byte, 127 | mask_bit, msg_length)

    if use_mask:  # pragma: no cover
        mask = random.randrange(0, 0xFFFFFFFF)
        mask = mask.to_bytes(4, "big")
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


def build_close_frame(code: int = 1000, message: bytes = b"", noheader: bool = False):
    # Close the websocket, sending the specified code and message.
    if isinstance(message, str):  # pragma: no cover
        message = message.encode("utf-8")
    return build_frame(
        PACK_CLOSE_CODE(code) + message, opcode=WSMsgType.CLOSE, noheader=noheader
    )


@pytest.fixture()
def out(loop: Any):
    return aiohttp.DataQueue(loop)


@pytest.fixture()
def parser(out: Any):
    return WebSocketReader(out, 4 * 1024 * 1024)


def test_parse_frame(parser: Any) -> None:
    parser.parse_frame(struct.pack("!BB", 0b00000001, 0b00000001))
    res = parser.parse_frame(b"1")
    fin, opcode, payload, compress = res[0]

    assert (0, 1, b"1", False) == (fin, opcode, payload, not not compress)


def test_parse_frame_length0(parser: Any) -> None:
    fin, opcode, payload, compress = parser.parse_frame(
        struct.pack("!BB", 0b00000001, 0b00000000)
    )[0]

    assert (0, 1, b"", False) == (fin, opcode, payload, not not compress)


def test_parse_frame_length2(parser: Any) -> None:
    parser.parse_frame(struct.pack("!BB", 0b00000001, 126))
    parser.parse_frame(struct.pack("!H", 4))
    res = parser.parse_frame(b"1234")
    fin, opcode, payload, compress = res[0]

    assert (0, 1, b"1234", False) == (fin, opcode, payload, not not compress)


def test_parse_frame_length4(parser: Any) -> None:
    parser.parse_frame(struct.pack("!BB", 0b00000001, 127))
    parser.parse_frame(struct.pack("!Q", 4))
    fin, opcode, payload, compress = parser.parse_frame(b"1234")[0]

    assert (0, 1, b"1234", False) == (fin, opcode, payload, not not compress)


def test_parse_frame_mask(parser: Any) -> None:
    parser.parse_frame(struct.pack("!BB", 0b00000001, 0b10000001))
    parser.parse_frame(b"0001")
    fin, opcode, payload, compress = parser.parse_frame(b"1")[0]

    assert (0, 1, b"\x01", False) == (fin, opcode, payload, not not compress)


def test_parse_frame_header_reversed_bits(out: Any, parser: Any) -> None:
    with pytest.raises(WebSocketError):
        parser.parse_frame(struct.pack("!BB", 0b01100000, 0b00000000))
        raise out.exception()


def test_parse_frame_header_control_frame(out: Any, parser: Any) -> None:
    with pytest.raises(WebSocketError):
        parser.parse_frame(struct.pack("!BB", 0b00001000, 0b00000000))
        raise out.exception()


def _test_parse_frame_header_new_data_err(out, parser):
    with pytest.raises(WebSocketError):
        parser.parse_frame(struct.pack("!BB", 0b000000000, 0b00000000))
        raise out.exception()


def test_parse_frame_header_payload_size(out: Any, parser: Any) -> None:
    with pytest.raises(WebSocketError):
        parser.parse_frame(struct.pack("!BB", 0b10001000, 0b01111110))
        raise out.exception()


def test_ping_frame(out: Any, parser: Any) -> None:
    parser.parse_frame = mock.Mock()
    parser.parse_frame.return_value = [(1, WSMsgType.PING, b"data", False)]

    parser.feed_data(b"")
    res = out._buffer[0]
    assert res == ((WSMsgType.PING, b"data", ""), 4)


def test_pong_frame(out: Any, parser: Any) -> None:
    parser.parse_frame = mock.Mock()
    parser.parse_frame.return_value = [(1, WSMsgType.PONG, b"data", False)]

    parser.feed_data(b"")
    res = out._buffer[0]
    assert res == ((WSMsgType.PONG, b"data", ""), 4)


def test_close_frame(out: Any, parser: Any) -> None:
    parser.parse_frame = mock.Mock()
    parser.parse_frame.return_value = [(1, WSMsgType.CLOSE, b"", False)]

    parser.feed_data(b"")
    res = out._buffer[0]
    assert res == ((WSMsgType.CLOSE, 0, ""), 0)


def test_close_frame_info(out: Any, parser: Any) -> None:
    parser.parse_frame = mock.Mock()
    parser.parse_frame.return_value = [(1, WSMsgType.CLOSE, b"0112345", False)]

    parser.feed_data(b"")
    res = out._buffer[0]
    assert res == (WSMessage(WSMsgType.CLOSE, 12337, "12345"), 0)


def test_close_frame_invalid(out: Any, parser: Any) -> None:
    parser.parse_frame = mock.Mock()
    parser.parse_frame.return_value = [(1, WSMsgType.CLOSE, b"1", False)]
    parser.feed_data(b"")

    assert isinstance(out.exception(), WebSocketError)
    assert out.exception().code == WSCloseCode.PROTOCOL_ERROR


def test_close_frame_invalid_2(out: Any, parser: Any) -> None:
    data = build_close_frame(code=1)

    with pytest.raises(WebSocketError) as ctx:
        parser._feed_data(data)

    assert ctx.value.code == WSCloseCode.PROTOCOL_ERROR


def test_close_frame_unicode_err(parser: Any) -> None:
    data = build_close_frame(code=1000, message=b"\xf4\x90\x80\x80")

    with pytest.raises(WebSocketError) as ctx:
        parser._feed_data(data)

    assert ctx.value.code == WSCloseCode.INVALID_TEXT


def test_unknown_frame(out: Any, parser: Any) -> None:
    parser.parse_frame = mock.Mock()
    parser.parse_frame.return_value = [(1, WSMsgType.CONTINUATION, b"", False)]

    with pytest.raises(WebSocketError):
        parser.feed_data(b"")
        raise out.exception()


def test_simple_text(out: Any, parser: Any) -> None:
    data = build_frame(b"text", WSMsgType.TEXT)
    parser._feed_data(data)
    res = out._buffer[0]
    assert res == ((WSMsgType.TEXT, "text", ""), 4)


def test_simple_text_unicode_err(parser: Any) -> None:
    data = build_frame(b"\xf4\x90\x80\x80", WSMsgType.TEXT)

    with pytest.raises(WebSocketError) as ctx:
        parser._feed_data(data)

    assert ctx.value.code == WSCloseCode.INVALID_TEXT


def test_simple_binary(out: Any, parser: Any) -> None:
    parser.parse_frame = mock.Mock()
    parser.parse_frame.return_value = [(1, WSMsgType.BINARY, b"binary", False)]

    parser.feed_data(b"")
    res = out._buffer[0]
    assert res == ((WSMsgType.BINARY, b"binary", ""), 6)


def test_fragmentation_header(out: Any, parser: Any) -> None:
    data = build_frame(b"a", WSMsgType.TEXT)
    parser._feed_data(data[:1])
    parser._feed_data(data[1:])

    res = out._buffer[0]
    assert res == (WSMessage(WSMsgType.TEXT, "a", ""), 1)


def test_continuation(out: Any, parser: Any) -> None:
    data1 = build_frame(b"line1", WSMsgType.TEXT, is_fin=False)
    parser._feed_data(data1)

    data2 = build_frame(b"line2", WSMsgType.CONTINUATION)
    parser._feed_data(data2)

    res = out._buffer[0]
    assert res == (WSMessage(WSMsgType.TEXT, "line1line2", ""), 10)


def test_continuation_with_ping(out: Any, parser: Any) -> None:
    parser.parse_frame = mock.Mock()
    parser.parse_frame.return_value = [
        (0, WSMsgType.TEXT, b"line1", False),
        (0, WSMsgType.PING, b"", False),
        (1, WSMsgType.CONTINUATION, b"line2", False),
    ]

    data1 = build_frame(b"line1", WSMsgType.TEXT, is_fin=False)
    parser._feed_data(data1)

    data2 = build_frame(b"", WSMsgType.PING)
    parser._feed_data(data2)

    data3 = build_frame(b"line2", WSMsgType.CONTINUATION)
    parser._feed_data(data3)

    res = out._buffer[0]
    assert res == (WSMessage(WSMsgType.PING, b"", ""), 0)
    res = out._buffer[1]
    assert res == (WSMessage(WSMsgType.TEXT, "line1line2", ""), 10)


def test_continuation_err(out: Any, parser: Any) -> None:
    parser.parse_frame = mock.Mock()
    parser.parse_frame.return_value = [
        (0, WSMsgType.TEXT, b"line1", False),
        (1, WSMsgType.TEXT, b"line2", False),
    ]

    with pytest.raises(WebSocketError):
        parser._feed_data(b"")


def test_continuation_with_close(out: Any, parser: Any) -> None:
    parser.parse_frame = mock.Mock()
    parser.parse_frame.return_value = [
        (0, WSMsgType.TEXT, b"line1", False),
        (0, WSMsgType.CLOSE, build_close_frame(1002, b"test", noheader=True), False),
        (1, WSMsgType.CONTINUATION, b"line2", False),
    ]

    parser.feed_data(b"")
    res = out._buffer[0]
    assert res, (WSMessage(WSMsgType.CLOSE, 1002, "test"), 0)
    res = out._buffer[1]
    assert res == (WSMessage(WSMsgType.TEXT, "line1line2", ""), 10)


def test_continuation_with_close_unicode_err(out: Any, parser: Any) -> None:
    parser.parse_frame = mock.Mock()
    parser.parse_frame.return_value = [
        (0, WSMsgType.TEXT, b"line1", False),
        (
            0,
            WSMsgType.CLOSE,
            build_close_frame(1000, b"\xf4\x90\x80\x80", noheader=True),
            False,
        ),
        (1, WSMsgType.CONTINUATION, b"line2", False),
    ]

    with pytest.raises(WebSocketError) as ctx:
        parser._feed_data(b"")

    assert ctx.value.code == WSCloseCode.INVALID_TEXT


def test_continuation_with_close_bad_code(out: Any, parser: Any) -> None:
    parser.parse_frame = mock.Mock()
    parser.parse_frame.return_value = [
        (0, WSMsgType.TEXT, b"line1", False),
        (0, WSMsgType.CLOSE, build_close_frame(1, b"test", noheader=True), False),
        (1, WSMsgType.CONTINUATION, b"line2", False),
    ]

    with pytest.raises(WebSocketError) as ctx:
        parser._feed_data(b"")

    assert ctx.value.code == WSCloseCode.PROTOCOL_ERROR


def test_continuation_with_close_bad_payload(out: Any, parser: Any) -> None:
    parser.parse_frame = mock.Mock()
    parser.parse_frame.return_value = [
        (0, WSMsgType.TEXT, b"line1", False),
        (0, WSMsgType.CLOSE, b"1", False),
        (1, WSMsgType.CONTINUATION, b"line2", False),
    ]

    with pytest.raises(WebSocketError) as ctx:
        parser._feed_data(b"")

    assert ctx.value.code, WSCloseCode.PROTOCOL_ERROR


def test_continuation_with_close_empty(out: Any, parser: Any) -> None:
    parser.parse_frame = mock.Mock()
    parser.parse_frame.return_value = [
        (0, WSMsgType.TEXT, b"line1", False),
        (0, WSMsgType.CLOSE, b"", False),
        (1, WSMsgType.CONTINUATION, b"line2", False),
    ]

    parser.feed_data(b"")
    res = out._buffer[0]
    assert res, (WSMessage(WSMsgType.CLOSE, 0, ""), 0)
    res = out._buffer[1]
    assert res == (WSMessage(WSMsgType.TEXT, "line1line2", ""), 10)


websocket_mask_data: bytes = b"some very long data for masking by websocket"
websocket_mask_mask: bytes = b"1234"
websocket_mask_masked: bytes = (
    b"B]^Q\x11DVFH\x12_[_U\x13PPFR\x14W]A\x14\\S@_X" b"\\T\x14SK\x13CTP@[RYV@"
)


def test_websocket_mask_python() -> None:
    message = bytearray(websocket_mask_data)
    http_websocket._websocket_mask_python(websocket_mask_mask, message)
    assert message == websocket_mask_masked


@pytest.mark.skipif(
    not hasattr(http_websocket, "_websocket_mask_cython"), reason="Requires Cython"
)
def test_websocket_mask_cython() -> None:
    message = bytearray(websocket_mask_data)
    http_websocket._websocket_mask_cython(websocket_mask_mask, message)
    assert message == websocket_mask_masked


def test_websocket_mask_python_empty() -> None:
    message = bytearray()
    http_websocket._websocket_mask_python(websocket_mask_mask, message)
    assert message == bytearray()


@pytest.mark.skipif(
    not hasattr(http_websocket, "_websocket_mask_cython"), reason="Requires Cython"
)
def test_websocket_mask_cython_empty() -> None:
    message = bytearray()
    http_websocket._websocket_mask_cython(websocket_mask_mask, message)
    assert message == bytearray()


def test_parse_compress_frame_single(parser: Any) -> None:
    parser.parse_frame(struct.pack("!BB", 0b11000001, 0b00000001))
    res = parser.parse_frame(b"1")
    fin, opcode, payload, compress = res[0]

    assert (1, 1, b"1", True) == (fin, opcode, payload, not not compress)


def test_parse_compress_frame_multi(parser: Any) -> None:
    parser.parse_frame(struct.pack("!BB", 0b01000001, 126))
    parser.parse_frame(struct.pack("!H", 4))
    res = parser.parse_frame(b"1234")
    fin, opcode, payload, compress = res[0]
    assert (0, 1, b"1234", True) == (fin, opcode, payload, not not compress)

    parser.parse_frame(struct.pack("!BB", 0b10000001, 126))
    parser.parse_frame(struct.pack("!H", 4))
    res = parser.parse_frame(b"1234")
    fin, opcode, payload, compress = res[0]
    assert (1, 1, b"1234", True) == (fin, opcode, payload, not not compress)

    parser.parse_frame(struct.pack("!BB", 0b10000001, 126))
    parser.parse_frame(struct.pack("!H", 4))
    res = parser.parse_frame(b"1234")
    fin, opcode, payload, compress = res[0]
    assert (1, 1, b"1234", False) == (fin, opcode, payload, not not compress)


def test_parse_compress_error_frame(parser: Any) -> None:
    parser.parse_frame(struct.pack("!BB", 0b01000001, 0b00000001))
    parser.parse_frame(b"1")

    with pytest.raises(WebSocketError) as ctx:
        parser.parse_frame(struct.pack("!BB", 0b11000001, 0b00000001))
        parser.parse_frame(b"1")

    assert ctx.value.code == WSCloseCode.PROTOCOL_ERROR


def test_parse_no_compress_frame_single() -> None:
    parser_no_compress = WebSocketReader(out, 0, compress=False)
    with pytest.raises(WebSocketError) as ctx:
        parser_no_compress.parse_frame(struct.pack("!BB", 0b11000001, 0b00000001))
        parser_no_compress.parse_frame(b"1")

    assert ctx.value.code == WSCloseCode.PROTOCOL_ERROR


def test_msg_too_large(out: Any) -> None:
    parser = WebSocketReader(out, 256, compress=False)
    data = build_frame(b"text" * 256, WSMsgType.TEXT)
    with pytest.raises(WebSocketError) as ctx:
        parser._feed_data(data)
    assert ctx.value.code == WSCloseCode.MESSAGE_TOO_BIG


def test_msg_too_large_not_fin(out: Any) -> None:
    parser = WebSocketReader(out, 256, compress=False)
    data = build_frame(b"text" * 256, WSMsgType.TEXT, is_fin=False)
    with pytest.raises(WebSocketError) as ctx:
        parser._feed_data(data)
    assert ctx.value.code == WSCloseCode.MESSAGE_TOO_BIG


def test_compressed_msg_too_large(out: Any) -> None:
    parser = WebSocketReader(out, 256, compress=True)
    data = build_frame(b"aaa" * 256, WSMsgType.TEXT, compress=True)
    with pytest.raises(WebSocketError) as ctx:
        parser._feed_data(data)
    assert ctx.value.code == WSCloseCode.MESSAGE_TOO_BIG


class TestWebSocketError:
    def test_ctor(self) -> None:
        err = WebSocketError(WSCloseCode.PROTOCOL_ERROR, "Something invalid")
        assert err.code == WSCloseCode.PROTOCOL_ERROR
        assert str(err) == "Something invalid"

    def test_pickle(self) -> None:
        err = WebSocketError(WSCloseCode.PROTOCOL_ERROR, "Something invalid")
        err.foo = "bar"
        for proto in range(pickle.HIGHEST_PROTOCOL + 1):
            pickled = pickle.dumps(err, proto)
            err2 = pickle.loads(pickled)
            assert err2.code == WSCloseCode.PROTOCOL_ERROR
            assert str(err2) == "Something invalid"
            assert err2.foo == "bar"
