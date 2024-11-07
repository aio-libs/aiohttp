import asyncio
import pickle
import random
import struct
import zlib
from typing import Union
from unittest import mock

import pytest

import aiohttp
from aiohttp._websocket import helpers as _websocket_helpers
from aiohttp._websocket.helpers import (
    PACK_CLOSE_CODE,
    PACK_LEN1,
    PACK_LEN2,
    PACK_LEN3,
    websocket_mask,
)
from aiohttp._websocket.models import WS_DEFLATE_TRAILING
from aiohttp.base_protocol import BaseProtocol
from aiohttp.http import WebSocketError, WSCloseCode, WSMessage, WSMsgType
from aiohttp.http_websocket import (
    WebSocketReader,
    WSMessageBinary,
    WSMessageClose,
    WSMessagePing,
    WSMessagePong,
    WSMessageText,
)


class PatchableWebSocketReader(WebSocketReader):
    """WebSocketReader subclass that allows for patching parse_frame."""


def build_frame(
    message: bytes,
    opcode: int,
    use_mask: bool = False,
    noheader: bool = False,
    is_fin: bool = True,
    compress: bool = False,
) -> bytes:
    # Send a frame over the websocket with message as its payload.
    if compress:
        compressobj = zlib.compressobj(wbits=-9)
        message = compressobj.compress(message)
        message = message + compressobj.flush(zlib.Z_SYNC_FLUSH)
        if message.endswith(WS_DEFLATE_TRAILING):
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
        maski = random.randrange(0, 0xFFFFFFFF)
        mask = maski.to_bytes(4, "big")
        message = bytearray(message)
        websocket_mask(mask, message)
        if noheader:
            return message
        else:
            return header + mask + message
    else:
        if noheader:
            return message
        else:
            return header + message


def build_close_frame(
    code: int = 1000, message: bytes = b"", noheader: bool = False
) -> bytes:
    # Close the websocket, sending the specified code and message.
    return build_frame(
        PACK_CLOSE_CODE(code) + message, opcode=WSMsgType.CLOSE, noheader=noheader
    )


@pytest.fixture()
def protocol(loop: asyncio.AbstractEventLoop) -> BaseProtocol:
    transport = mock.Mock(spec_set=asyncio.Transport)
    protocol = BaseProtocol(loop)
    protocol.connection_made(transport)
    return protocol


@pytest.fixture()
def out(
    loop: asyncio.AbstractEventLoop, protocol: BaseProtocol
) -> aiohttp.DataQueue[WSMessage]:
    return aiohttp.FlowControlDataQueue(protocol, 2**16, loop=loop)


@pytest.fixture()
def out_low_limit(
    loop: asyncio.AbstractEventLoop, protocol: BaseProtocol
) -> aiohttp.DataQueue[WSMessage]:
    return aiohttp.FlowControlDataQueue(protocol, 16, loop=loop)


@pytest.fixture()
def parser_low_limit(
    out_low_limit: aiohttp.DataQueue[WSMessage],
) -> PatchableWebSocketReader:
    return PatchableWebSocketReader(out_low_limit, 4 * 1024 * 1024)


@pytest.fixture()
def parser(out: aiohttp.DataQueue[WSMessage]) -> PatchableWebSocketReader:
    return PatchableWebSocketReader(out, 4 * 1024 * 1024)


def test_feed_data_remembers_exception(parser: WebSocketReader) -> None:
    """Verify that feed_data remembers an exception was already raised internally."""
    error, data = parser.feed_data(struct.pack("!BB", 0b01100000, 0b00000000))
    assert error is True
    assert data == b""

    error, data = parser.feed_data(b"")
    assert error is True
    assert data == b""


def test_parse_frame(parser: WebSocketReader) -> None:
    parser.parse_frame(struct.pack("!BB", 0b00000001, 0b00000001))
    res = parser.parse_frame(b"1")
    fin, opcode, payload, compress = res[0]

    assert (0, 1, b"1", False) == (fin, opcode, payload, not not compress)


def test_parse_frame_length0(parser: WebSocketReader) -> None:
    fin, opcode, payload, compress = parser.parse_frame(
        struct.pack("!BB", 0b00000001, 0b00000000)
    )[0]

    assert (0, 1, b"", False) == (fin, opcode, payload, not not compress)


def test_parse_frame_length2(parser: WebSocketReader) -> None:
    parser.parse_frame(struct.pack("!BB", 0b00000001, 126))
    parser.parse_frame(struct.pack("!H", 4))
    res = parser.parse_frame(b"1234")
    fin, opcode, payload, compress = res[0]

    assert (0, 1, b"1234", False) == (fin, opcode, payload, not not compress)


def test_parse_frame_length2_multi_byte(parser: WebSocketReader) -> None:
    """Ensure a multi-byte length is parsed correctly."""
    expected_payload = b"1" * 32768
    parser.parse_frame(struct.pack("!BB", 0b00000001, 126))
    parser.parse_frame(struct.pack("!H", 32768))
    res = parser.parse_frame(b"1" * 32768)
    fin, opcode, payload, compress = res[0]

    assert (0, 1, expected_payload, False) == (fin, opcode, payload, not not compress)


def test_parse_frame_length2_multi_byte_multi_packet(parser: WebSocketReader) -> None:
    """Ensure a multi-byte length with multiple packets is parsed correctly."""
    expected_payload = b"1" * 32768
    assert parser.parse_frame(struct.pack("!BB", 0b00000001, 126)) == []
    assert parser.parse_frame(struct.pack("!H", 32768)) == []
    assert parser.parse_frame(b"1" * 8192) == []
    assert parser.parse_frame(b"1" * 8192) == []
    assert parser.parse_frame(b"1" * 8192) == []
    res = parser.parse_frame(b"1" * 8192)
    fin, opcode, payload, compress = res[0]
    assert len(payload) == 32768
    assert (0, 1, expected_payload, False) == (fin, opcode, payload, not not compress)


def test_parse_frame_length4(parser: WebSocketReader) -> None:
    parser.parse_frame(struct.pack("!BB", 0b00000001, 127))
    parser.parse_frame(struct.pack("!Q", 4))
    fin, opcode, payload, compress = parser.parse_frame(b"1234")[0]

    assert (0, 1, b"1234", False) == (fin, opcode, payload, not not compress)


def test_parse_frame_mask(parser: WebSocketReader) -> None:
    parser.parse_frame(struct.pack("!BB", 0b00000001, 0b10000001))
    parser.parse_frame(b"0001")
    fin, opcode, payload, compress = parser.parse_frame(b"1")[0]

    assert (0, 1, b"\x01", False) == (fin, opcode, payload, not not compress)


def test_parse_frame_header_reversed_bits(
    out: aiohttp.DataQueue[WSMessage], parser: WebSocketReader
) -> None:
    with pytest.raises(WebSocketError):
        parser.parse_frame(struct.pack("!BB", 0b01100000, 0b00000000))


def test_parse_frame_header_control_frame(
    out: aiohttp.DataQueue[WSMessage], parser: WebSocketReader
) -> None:
    with pytest.raises(WebSocketError):
        parser.parse_frame(struct.pack("!BB", 0b00001000, 0b00000000))


@pytest.mark.xfail()
def test_parse_frame_header_new_data_err(
    out: aiohttp.DataQueue[WSMessage], parser: WebSocketReader
) -> None:
    with pytest.raises(WebSocketError):
        parser.parse_frame(struct.pack("!BB", 0b000000000, 0b00000000))


def test_parse_frame_header_payload_size(
    out: aiohttp.DataQueue[WSMessage], parser: WebSocketReader
) -> None:
    with pytest.raises(WebSocketError):
        parser.parse_frame(struct.pack("!BB", 0b10001000, 0b01111110))


# Protractor event loop will call feed_data with bytearray. Since
# asyncio technically supports memoryview as well, we should test that.
@pytest.mark.parametrize(
    argnames="data",
    argvalues=[b"", bytearray(b""), memoryview(b"")],
    ids=["bytes", "bytearray", "memoryview"],
)
def test_ping_frame(
    out: aiohttp.DataQueue[WSMessage],
    parser: WebSocketReader,
    data: Union[bytes, bytearray, memoryview],
) -> None:
    with mock.patch.object(parser, "parse_frame", autospec=True) as m:
        m.return_value = [(1, WSMsgType.PING, b"data", False)]

        parser.feed_data(data)
        res = out._buffer[0]
        assert res == WSMessagePing(data=b"data", extra="")


def test_pong_frame(out: aiohttp.DataQueue[WSMessage], parser: WebSocketReader) -> None:
    with mock.patch.object(parser, "parse_frame", autospec=True) as m:
        m.return_value = [(1, WSMsgType.PONG, b"data", False)]

        parser.feed_data(b"")
        res = out._buffer[0]
        assert res == WSMessagePong(data=b"data", extra="")


def test_close_frame(
    out: aiohttp.DataQueue[WSMessage], parser: WebSocketReader
) -> None:
    with mock.patch.object(parser, "parse_frame", autospec=True) as m:
        m.return_value = [(1, WSMsgType.CLOSE, b"", False)]

        parser.feed_data(b"")
        res = out._buffer[0]
        assert res == WSMessageClose(data=0, extra="")


def test_close_frame_info(
    out: aiohttp.DataQueue[WSMessage], parser: WebSocketReader
) -> None:
    with mock.patch.object(parser, "parse_frame", autospec=True) as m:
        m.return_value = [(1, WSMsgType.CLOSE, b"0112345", False)]

        parser.feed_data(b"")
        res = out._buffer[0]
        assert res == WSMessageClose(data=12337, extra="12345")


def test_close_frame_invalid(
    out: aiohttp.DataQueue[WSMessage], parser: WebSocketReader
) -> None:
    with mock.patch.object(parser, "parse_frame", autospec=True) as m:
        m.return_value = [(1, WSMsgType.CLOSE, b"1", False)]
        parser.feed_data(b"")

        exc = out.exception()
        assert isinstance(exc, WebSocketError)
        assert exc.code == WSCloseCode.PROTOCOL_ERROR


def test_close_frame_invalid_2(
    out: aiohttp.DataQueue[WSMessage], parser: WebSocketReader
) -> None:
    data = build_close_frame(code=1)

    with pytest.raises(WebSocketError) as ctx:
        parser._feed_data(data)

    assert ctx.value.code == WSCloseCode.PROTOCOL_ERROR


def test_close_frame_unicode_err(parser: WebSocketReader) -> None:
    data = build_close_frame(code=1000, message=b"\xf4\x90\x80\x80")

    with pytest.raises(WebSocketError) as ctx:
        parser._feed_data(data)

    assert ctx.value.code == WSCloseCode.INVALID_TEXT


def test_unknown_frame(
    out: aiohttp.DataQueue[WSMessage], parser: WebSocketReader
) -> None:
    with mock.patch.object(parser, "parse_frame", autospec=True) as m:
        m.return_value = [(1, WSMsgType.CONTINUATION, b"", False)]

        parser.feed_data(b"")
        assert isinstance(out.exception(), WebSocketError)


def test_simple_text(
    out: aiohttp.DataQueue[WSMessage], parser: WebSocketReader
) -> None:
    data = build_frame(b"text", WSMsgType.TEXT)
    parser._feed_data(data)
    res = out._buffer[0]
    assert res == WSMessageText(data="text", extra="")


def test_simple_text_unicode_err(parser: WebSocketReader) -> None:
    data = build_frame(b"\xf4\x90\x80\x80", WSMsgType.TEXT)

    with pytest.raises(WebSocketError) as ctx:
        parser._feed_data(data)

    assert ctx.value.code == WSCloseCode.INVALID_TEXT


def test_simple_binary(
    out: aiohttp.DataQueue[WSMessage], parser: WebSocketReader
) -> None:
    with mock.patch.object(parser, "parse_frame", autospec=True) as m:
        m.return_value = [(1, WSMsgType.BINARY, b"binary", False)]

        parser.feed_data(b"")
        res = out._buffer[0]
        assert res == WSMessageBinary(data=b"binary", extra="")


def test_fragmentation_header(
    out: aiohttp.DataQueue[WSMessage], parser: WebSocketReader
) -> None:
    data = build_frame(b"a", WSMsgType.TEXT)
    parser._feed_data(data[:1])
    parser._feed_data(data[1:])

    res = out._buffer[0]
    assert res == WSMessageText(data="a", extra="")


def test_continuation(
    out: aiohttp.DataQueue[WSMessage], parser: WebSocketReader
) -> None:
    data1 = build_frame(b"line1", WSMsgType.TEXT, is_fin=False)
    parser._feed_data(data1)

    data2 = build_frame(b"line2", WSMsgType.CONTINUATION)
    parser._feed_data(data2)

    res = out._buffer[0]
    assert res == WSMessageText(data="line1line2", extra="")


def test_continuation_with_ping(
    out: aiohttp.DataQueue[WSMessage], parser: WebSocketReader
) -> None:
    with mock.patch.object(parser, "parse_frame", autospec=True) as m:
        m.return_value = [
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
        assert res == WSMessagePing(data=b"", extra="")
        res = out._buffer[1]
        assert res == WSMessageText(data="line1line2", extra="")


def test_continuation_err(
    out: aiohttp.DataQueue[WSMessage], parser: WebSocketReader
) -> None:
    with mock.patch.object(parser, "parse_frame", autospec=True) as m:
        m.return_value = [
            (0, WSMsgType.TEXT, b"line1", False),
            (1, WSMsgType.TEXT, b"line2", False),
        ]

        with pytest.raises(WebSocketError):
            parser._feed_data(b"")


def test_continuation_with_close(
    out: aiohttp.DataQueue[WSMessage], parser: WebSocketReader
) -> None:
    with mock.patch.object(parser, "parse_frame", autospec=True) as m:
        m.return_value = [
            (0, WSMsgType.TEXT, b"line1", False),
            (
                0,
                WSMsgType.CLOSE,
                build_close_frame(1002, b"test", noheader=True),
                False,
            ),
            (1, WSMsgType.CONTINUATION, b"line2", False),
        ]

        parser.feed_data(b"")
        res = out._buffer[0]
        assert res == WSMessageClose(data=1002, extra="test")
        res = out._buffer[1]
        assert res == WSMessageText(data="line1line2", extra="")


def test_continuation_with_close_unicode_err(
    out: aiohttp.DataQueue[WSMessage], parser: WebSocketReader
) -> None:
    with mock.patch.object(parser, "parse_frame", autospec=True) as m:
        m.return_value = [
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


def test_continuation_with_close_bad_code(
    out: aiohttp.DataQueue[WSMessage], parser: WebSocketReader
) -> None:
    with mock.patch.object(parser, "parse_frame", autospec=True) as m:
        m.return_value = [
            (0, WSMsgType.TEXT, b"line1", False),
            (0, WSMsgType.CLOSE, build_close_frame(1, b"test", noheader=True), False),
            (1, WSMsgType.CONTINUATION, b"line2", False),
        ]

        with pytest.raises(WebSocketError) as ctx:
            parser._feed_data(b"")

        assert ctx.value.code == WSCloseCode.PROTOCOL_ERROR


def test_continuation_with_close_bad_payload(
    out: aiohttp.DataQueue[WSMessage], parser: WebSocketReader
) -> None:
    with mock.patch.object(parser, "parse_frame", autospec=True) as m:
        m.return_value = [
            (0, WSMsgType.TEXT, b"line1", False),
            (0, WSMsgType.CLOSE, b"1", False),
            (1, WSMsgType.CONTINUATION, b"line2", False),
        ]

        with pytest.raises(WebSocketError) as ctx:
            parser._feed_data(b"")

        assert ctx.value.code, WSCloseCode.PROTOCOL_ERROR


def test_continuation_with_close_empty(
    out: aiohttp.DataQueue[WSMessage], parser: WebSocketReader
) -> None:
    with mock.patch.object(parser, "parse_frame", autospec=True) as m:
        m.return_value = [
            (0, WSMsgType.TEXT, b"line1", False),
            (0, WSMsgType.CLOSE, b"", False),
            (1, WSMsgType.CONTINUATION, b"line2", False),
        ]

        parser.feed_data(b"")
        res = out._buffer[0]
        assert res == WSMessageClose(data=0, extra="")
        res = out._buffer[1]
        assert res == WSMessageText(data="line1line2", extra="")


websocket_mask_data: bytes = b"some very long data for masking by websocket"
websocket_mask_mask: bytes = b"1234"
websocket_mask_masked: bytes = (
    b"B]^Q\x11DVFH\x12_[_U\x13PPFR\x14W]A\x14\\S@_X\\T\x14SK\x13CTP@[RYV@"
)


def test_websocket_mask_python() -> None:
    message = bytearray(websocket_mask_data)
    _websocket_helpers._websocket_mask_python(websocket_mask_mask, message)
    assert message == websocket_mask_masked


@pytest.mark.skipif(
    not hasattr(_websocket_helpers, "_websocket_mask_cython"), reason="Requires Cython"
)
def test_websocket_mask_cython() -> None:
    message = bytearray(websocket_mask_data)
    _websocket_helpers._websocket_mask_cython(websocket_mask_mask, message)  # type: ignore[attr-defined]
    assert message == websocket_mask_masked
    assert (
        _websocket_helpers.websocket_mask is _websocket_helpers._websocket_mask_cython  # type: ignore[attr-defined]
    )


def test_websocket_mask_python_empty() -> None:
    message = bytearray()
    _websocket_helpers._websocket_mask_python(websocket_mask_mask, message)
    assert message == bytearray()


@pytest.mark.skipif(
    not hasattr(_websocket_helpers, "_websocket_mask_cython"), reason="Requires Cython"
)
def test_websocket_mask_cython_empty() -> None:
    message = bytearray()
    _websocket_helpers._websocket_mask_cython(websocket_mask_mask, message)  # type: ignore[attr-defined]
    assert message == bytearray()


def test_parse_compress_frame_single(parser: WebSocketReader) -> None:
    parser.parse_frame(struct.pack("!BB", 0b11000001, 0b00000001))
    res = parser.parse_frame(b"1")
    fin, opcode, payload, compress = res[0]

    assert (1, 1, b"1", True) == (fin, opcode, payload, not not compress)


def test_parse_compress_frame_multi(parser: WebSocketReader) -> None:
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


def test_parse_compress_error_frame(parser: WebSocketReader) -> None:
    parser.parse_frame(struct.pack("!BB", 0b01000001, 0b00000001))
    parser.parse_frame(b"1")

    with pytest.raises(WebSocketError) as ctx:
        parser.parse_frame(struct.pack("!BB", 0b11000001, 0b00000001))
        parser.parse_frame(b"1")

    assert ctx.value.code == WSCloseCode.PROTOCOL_ERROR


def test_parse_no_compress_frame_single(out: aiohttp.DataQueue[WSMessage]) -> None:
    parser_no_compress = WebSocketReader(out, 0, compress=False)
    with pytest.raises(WebSocketError) as ctx:
        parser_no_compress.parse_frame(struct.pack("!BB", 0b11000001, 0b00000001))
        parser_no_compress.parse_frame(b"1")

    assert ctx.value.code == WSCloseCode.PROTOCOL_ERROR


def test_msg_too_large(out: aiohttp.DataQueue[WSMessage]) -> None:
    parser = WebSocketReader(out, 256, compress=False)
    data = build_frame(b"text" * 256, WSMsgType.TEXT)
    with pytest.raises(WebSocketError) as ctx:
        parser._feed_data(data)
    assert ctx.value.code == WSCloseCode.MESSAGE_TOO_BIG


def test_msg_too_large_not_fin(out: aiohttp.DataQueue[WSMessage]) -> None:
    parser = WebSocketReader(out, 256, compress=False)
    data = build_frame(b"text" * 256, WSMsgType.TEXT, is_fin=False)
    with pytest.raises(WebSocketError) as ctx:
        parser._feed_data(data)
    assert ctx.value.code == WSCloseCode.MESSAGE_TOO_BIG


def test_compressed_msg_too_large(out: aiohttp.DataQueue[WSMessage]) -> None:
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
        err.foo = "bar"  # type: ignore[attr-defined]
        for proto in range(pickle.HIGHEST_PROTOCOL + 1):
            pickled = pickle.dumps(err, proto)
            err2 = pickle.loads(pickled)
            assert err2.code == WSCloseCode.PROTOCOL_ERROR
            assert str(err2) == "Something invalid"
            assert err2.foo == "bar"


@pytest.mark.xfail(
    reason="Flow control is currently broken on master branch; see #9685"
)
def test_flow_control_binary(
    protocol: BaseProtocol,
    out_low_limit: aiohttp.FlowControlDataQueue[WSMessage],
    parser_low_limit: WebSocketReader,
) -> None:
    large_payload = b"b" * (1 + 16 * 2)
    with mock.patch.object(parser_low_limit, "parse_frame", autospec=True) as m:
        m.return_value = [(1, WSMsgType.BINARY, large_payload, False)]

        parser_low_limit.feed_data(b"")

    res = out_low_limit._buffer[0]
    assert res == WSMessageBinary(data=large_payload, extra="")
    assert protocol._reading_paused is True


@pytest.mark.xfail(
    reason="Flow control is currently broken on master branch; see #9685"
)
def test_flow_control_multi_byte_text(
    protocol: BaseProtocol,
    out_low_limit: aiohttp.FlowControlDataQueue[WSMessage],
    parser_low_limit: WebSocketReader,
) -> None:
    large_payload_text = "𒀁" * (1 + 16 * 2)
    large_payload = large_payload_text.encode("utf-8")

    with mock.patch.object(parser_low_limit, "parse_frame", autospec=True) as m:
        m.return_value = [(1, WSMsgType.TEXT, large_payload, False)]

        parser_low_limit.feed_data(b"")

    res = out_low_limit._buffer[0]
    assert res == WSMessageText(data=large_payload_text, extra="")
    assert protocol._reading_paused is True
