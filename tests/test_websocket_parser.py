import asyncio
import pickle
import random
import struct
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
from aiohttp._websocket.reader import WebSocketDataQueue
from aiohttp.base_protocol import BaseProtocol
from aiohttp.compression_utils import ZLibBackend
from aiohttp.http import WebSocketError, WSCloseCode, WSMessage, WSMsgType
from aiohttp.http_websocket import WebSocketReader


class PatchableWebSocketReader(WebSocketReader):
    """WebSocketReader subclass that allows for patching parse_frame."""

    def parse_frame(
        self, data: bytes
    ) -> list[tuple[bool, int, Union[bytes, bytearray], int]]:
        # This method is overridden to allow for patching in tests.
        frames: list[tuple[bool, int, Union[bytes, bytearray], int]] = []

        def _handle_frame(
            fin: bool,
            opcode: int,
            payload: Union[bytes, bytearray],
            compressed: int,
        ) -> None:
            # This method is overridden to allow for patching in tests.
            frames.append((fin, opcode, payload, compressed))

        with mock.patch.object(self, "_handle_frame", _handle_frame):
            self._feed_data(data)
        return frames


def build_frame(
    message, opcode, use_mask=False, noheader=False, is_fin=True, ZLibBackend=None
):
    # Send a frame over the websocket with message as its payload.
    compress = False
    if ZLibBackend:
        compress = True
        compressobj = ZLibBackend.compressobj(wbits=-9)
        message = compressobj.compress(message)
        message = message + compressobj.flush(ZLibBackend.Z_SYNC_FLUSH)
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
        mask = random.randrange(0, 0xFFFFFFFF)
        mask = mask.to_bytes(4, "big")
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


def build_close_frame(code=1000, message=b"", noheader=False):
    # Close the websocket, sending the specified code and message.
    if isinstance(message, str):  # pragma: no cover
        message = message.encode("utf-8")
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
def out(loop: asyncio.AbstractEventLoop) -> WebSocketDataQueue:
    return WebSocketDataQueue(mock.Mock(_reading_paused=False), 2**16, loop=loop)


@pytest.fixture()
def out_low_limit(
    loop: asyncio.AbstractEventLoop, protocol: BaseProtocol
) -> WebSocketDataQueue:
    return WebSocketDataQueue(protocol, 16, loop=loop)


@pytest.fixture()
def parser_low_limit(
    out_low_limit: WebSocketDataQueue,
) -> PatchableWebSocketReader:
    return PatchableWebSocketReader(out_low_limit, 4 * 1024 * 1024)


@pytest.fixture()
def parser(out: WebSocketDataQueue) -> PatchableWebSocketReader:
    return PatchableWebSocketReader(out, 4 * 1024 * 1024)


def test_feed_data_remembers_exception(parser: WebSocketReader) -> None:
    """Verify that feed_data remembers an exception was already raised internally."""
    error, data = parser.feed_data(struct.pack("!BB", 0b01100000, 0b00000000))
    assert error is True
    assert data == b""

    error, data = parser.feed_data(b"")
    assert error is True
    assert data == b""


def test_parse_frame(parser: PatchableWebSocketReader) -> None:
    parser.parse_frame(struct.pack("!BB", 0b00000001, 0b00000001))
    res = parser.parse_frame(b"1")
    fin, opcode, payload, compress = res[0]

    assert (0, 1, b"1", 0) == (fin, opcode, payload, not not compress)


def test_parse_frame_length0(parser: PatchableWebSocketReader) -> None:
    fin, opcode, payload, compress = parser.parse_frame(
        struct.pack("!BB", 0b00000001, 0b00000000)
    )[0]

    assert (0, 1, b"", 0) == (fin, opcode, payload, not not compress)


def test_parse_frame_length2(parser: PatchableWebSocketReader) -> None:
    parser.parse_frame(struct.pack("!BB", 0b00000001, 126))
    parser.parse_frame(struct.pack("!H", 4))
    res = parser.parse_frame(b"1234")
    fin, opcode, payload, compress = res[0]

    assert (0, 1, b"1234", 0) == (fin, opcode, payload, not not compress)


def test_parse_frame_length2_multi_byte(parser: PatchableWebSocketReader) -> None:
    """Ensure a multi-byte length is parsed correctly."""
    expected_payload = b"1" * 32768
    parser.parse_frame(struct.pack("!BB", 0b00000001, 126))
    parser.parse_frame(struct.pack("!H", 32768))
    res = parser.parse_frame(b"1" * 32768)
    fin, opcode, payload, compress = res[0]

    assert (0, 1, expected_payload, 0) == (fin, opcode, payload, not not compress)


def test_parse_frame_length2_multi_byte_multi_packet(
    parser: PatchableWebSocketReader,
) -> None:
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
    assert (0, 1, expected_payload, 0) == (fin, opcode, payload, not not compress)


def test_parse_frame_length4(parser: PatchableWebSocketReader) -> None:
    parser.parse_frame(struct.pack("!BB", 0b00000001, 127))
    parser.parse_frame(struct.pack("!Q", 4))
    fin, opcode, payload, compress = parser.parse_frame(b"1234")[0]

    assert (0, 1, b"1234", 0) == (fin, opcode, payload, compress)


def test_parse_frame_mask(parser: PatchableWebSocketReader) -> None:
    parser.parse_frame(struct.pack("!BB", 0b00000001, 0b10000001))
    parser.parse_frame(b"0001")
    fin, opcode, payload, compress = parser.parse_frame(b"1")[0]

    assert (0, 1, b"\x01", 0) == (fin, opcode, payload, compress)


def test_parse_frame_header_reversed_bits(
    out: WebSocketDataQueue, parser: PatchableWebSocketReader
) -> None:
    with pytest.raises(WebSocketError):
        parser.parse_frame(struct.pack("!BB", 0b01100000, 0b00000000))
        raise out.exception()


def test_parse_frame_header_control_frame(
    out: WebSocketDataQueue, parser: PatchableWebSocketReader
) -> None:
    with pytest.raises(WebSocketError):
        parser.parse_frame(struct.pack("!BB", 0b00001000, 0b00000000))
        raise out.exception()


@pytest.mark.xfail()
def test_parse_frame_header_new_data_err(
    out: WebSocketDataQueue, parser: PatchableWebSocketReader
) -> None:
    with pytest.raises(WebSocketError):
        parser.parse_frame(struct.pack("!BB", 0b000000000, 0b00000000))
        raise out.exception()


def test_parse_frame_header_payload_size(
    out: WebSocketDataQueue, parser: PatchableWebSocketReader
) -> None:
    with pytest.raises(WebSocketError):
        parser.parse_frame(struct.pack("!BB", 0b10001000, 0b01111110))
        raise out.exception()


# Protractor event loop will call feed_data with bytearray. Since
# asyncio technically supports memoryview as well, we should test that.
@pytest.mark.parametrize(
    argnames="data",
    argvalues=[b"", bytearray(b""), memoryview(b"")],
    ids=["bytes", "bytearray", "memoryview"],
)
def test_ping_frame(
    out: WebSocketDataQueue,
    parser: PatchableWebSocketReader,
    data: Union[bytes, bytearray, memoryview],
) -> None:
    parser._handle_frame(True, WSMsgType.PING, b"data", 0)
    res = out._buffer[0]
    assert res == ((WSMsgType.PING, b"data", ""), 4)


def test_pong_frame(out: WebSocketDataQueue, parser: PatchableWebSocketReader) -> None:
    parser._handle_frame(True, WSMsgType.PONG, b"data", 0)
    res = out._buffer[0]
    assert res == ((WSMsgType.PONG, b"data", ""), 4)


def test_close_frame(out: WebSocketDataQueue, parser: PatchableWebSocketReader) -> None:
    parser._handle_frame(True, WSMsgType.CLOSE, b"", 0)
    res = out._buffer[0]
    assert res == ((WSMsgType.CLOSE, 0, ""), 0)


def test_close_frame_info(
    out: WebSocketDataQueue, parser: PatchableWebSocketReader
) -> None:
    parser._handle_frame(True, WSMsgType.CLOSE, b"0112345", 0)
    res = out._buffer[0]
    assert res == (WSMessage(WSMsgType.CLOSE, 12337, "12345"), 0)


def test_close_frame_invalid(
    out: WebSocketDataQueue, parser: PatchableWebSocketReader
) -> None:
    with pytest.raises(WebSocketError) as ctx:
        parser._handle_frame(True, WSMsgType.CLOSE, b"1", 0)
    assert ctx.value.code == WSCloseCode.PROTOCOL_ERROR


def test_close_frame_invalid_2(
    out: WebSocketDataQueue, parser: PatchableWebSocketReader
) -> None:
    data = build_close_frame(code=1)

    with pytest.raises(WebSocketError) as ctx:
        parser._feed_data(data)

    assert ctx.value.code == WSCloseCode.PROTOCOL_ERROR


def test_close_frame_unicode_err(parser: PatchableWebSocketReader) -> None:
    data = build_close_frame(code=1000, message=b"\xf4\x90\x80\x80")

    with pytest.raises(WebSocketError) as ctx:
        parser._feed_data(data)

    assert ctx.value.code == WSCloseCode.INVALID_TEXT


def test_unknown_frame(
    out: WebSocketDataQueue, parser: PatchableWebSocketReader
) -> None:
    with pytest.raises(WebSocketError):
        parser._handle_frame(True, WSMsgType.CONTINUATION, b"", 0)


def test_simple_text(out: WebSocketDataQueue, parser: PatchableWebSocketReader) -> None:
    data = build_frame(b"text", WSMsgType.TEXT)
    parser._feed_data(data)
    res = out._buffer[0]
    assert res == ((WSMsgType.TEXT, "text", ""), 4)


def test_simple_text_unicode_err(parser: PatchableWebSocketReader) -> None:
    data = build_frame(b"\xf4\x90\x80\x80", WSMsgType.TEXT)

    with pytest.raises(WebSocketError) as ctx:
        parser._feed_data(data)

    assert ctx.value.code == WSCloseCode.INVALID_TEXT


def test_simple_binary(
    out: WebSocketDataQueue, parser: PatchableWebSocketReader
) -> None:
    data = build_frame(b"binary", WSMsgType.BINARY)
    parser._feed_data(data)
    res = out._buffer[0]
    assert res == ((WSMsgType.BINARY, b"binary", ""), 6)


def test_fragmentation_header(
    out: WebSocketDataQueue, parser: PatchableWebSocketReader
) -> None:
    data = build_frame(b"a", WSMsgType.TEXT)
    parser._feed_data(data[:1])
    parser._feed_data(data[1:])

    res = out._buffer[0]
    assert res == (WSMessage(WSMsgType.TEXT, "a", ""), 1)


def test_continuation(
    out: WebSocketDataQueue, parser: PatchableWebSocketReader
) -> None:
    data1 = build_frame(b"line1", WSMsgType.TEXT, is_fin=False)
    parser._feed_data(data1)

    data2 = build_frame(b"line2", WSMsgType.CONTINUATION)
    parser._feed_data(data2)

    res = out._buffer[0]
    assert res == (WSMessage(WSMsgType.TEXT, "line1line2", ""), 10)


def test_continuation_with_ping(
    out: WebSocketDataQueue, parser: PatchableWebSocketReader
) -> None:
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


def test_continuation_err(
    out: WebSocketDataQueue, parser: PatchableWebSocketReader
) -> None:
    parser._handle_frame(False, WSMsgType.TEXT, b"line1", 0)
    with pytest.raises(WebSocketError):
        parser._handle_frame(True, WSMsgType.TEXT, b"line2", 0)


def test_continuation_with_close(
    out: WebSocketDataQueue, parser: WebSocketReader
) -> None:
    parser._handle_frame(False, WSMsgType.TEXT, b"line1", 0)
    parser._handle_frame(
        False,
        WSMsgType.CLOSE,
        build_close_frame(1002, b"test", noheader=True),
        False,
    )
    parser._handle_frame(True, WSMsgType.CONTINUATION, b"line2", 0)
    res = out._buffer[0]
    assert res == (WSMessage(WSMsgType.CLOSE, 1002, "test"), 0)
    res = out._buffer[1]
    assert res == (WSMessage(WSMsgType.TEXT, "line1line2", ""), 10)


def test_continuation_with_close_unicode_err(
    out: WebSocketDataQueue, parser: PatchableWebSocketReader
) -> None:
    parser._handle_frame(False, WSMsgType.TEXT, b"line1", 0)
    with pytest.raises(WebSocketError) as ctx:
        parser._handle_frame(
            False,
            WSMsgType.CLOSE,
            build_close_frame(1000, b"\xf4\x90\x80\x80", noheader=True),
            0,
        )
    parser._handle_frame(True, WSMsgType.CONTINUATION, b"line2", 0)
    assert ctx.value.code == WSCloseCode.INVALID_TEXT


def test_continuation_with_close_bad_code(
    out: WebSocketDataQueue, parser: PatchableWebSocketReader
) -> None:
    parser._handle_frame(False, WSMsgType.TEXT, b"line1", 0)
    with pytest.raises(WebSocketError) as ctx:

        parser._handle_frame(
            False, WSMsgType.CLOSE, build_close_frame(1, b"test", noheader=True), 0
        )
    assert ctx.value.code == WSCloseCode.PROTOCOL_ERROR
    parser._handle_frame(True, WSMsgType.CONTINUATION, b"line2", 0)


def test_continuation_with_close_bad_payload(
    out: WebSocketDataQueue, parser: PatchableWebSocketReader
) -> None:
    parser._handle_frame(False, WSMsgType.TEXT, b"line1", 0)
    with pytest.raises(WebSocketError) as ctx:
        parser._handle_frame(False, WSMsgType.CLOSE, b"1", 0)
    assert ctx.value.code == WSCloseCode.PROTOCOL_ERROR
    parser._handle_frame(True, WSMsgType.CONTINUATION, b"line2", 0)


def test_continuation_with_close_empty(
    out: WebSocketDataQueue, parser: PatchableWebSocketReader
) -> None:
    parser._handle_frame(False, WSMsgType.TEXT, b"line1", 0)
    parser._handle_frame(False, WSMsgType.CLOSE, b"", 0)
    parser._handle_frame(True, WSMsgType.CONTINUATION, b"line2", 0)

    res = out._buffer[0]
    assert res == (WSMessage(WSMsgType.CLOSE, 0, ""), 0)
    res = out._buffer[1]
    assert res == (WSMessage(WSMsgType.TEXT, "line1line2", ""), 10)


websocket_mask_data = b"some very long data for masking by websocket"
websocket_mask_mask = b"1234"
websocket_mask_masked = (
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


def test_msgtype_aliases() -> None:
    assert aiohttp.WSMsgType.TEXT == aiohttp.WSMsgType.text
    assert aiohttp.WSMsgType.BINARY == aiohttp.WSMsgType.binary
    assert aiohttp.WSMsgType.PING == aiohttp.WSMsgType.ping
    assert aiohttp.WSMsgType.PONG == aiohttp.WSMsgType.pong
    assert aiohttp.WSMsgType.CLOSE == aiohttp.WSMsgType.close
    assert aiohttp.WSMsgType.CLOSED == aiohttp.WSMsgType.closed
    assert aiohttp.WSMsgType.ERROR == aiohttp.WSMsgType.error


def test_parse_compress_frame_single(parser: PatchableWebSocketReader) -> None:
    parser.parse_frame(struct.pack("!BB", 0b11000001, 0b00000001))
    res = parser.parse_frame(b"1")
    fin, opcode, payload, compress = res[0]

    assert (1, 1, b"1", True) == (fin, opcode, payload, not not compress)


def test_parse_compress_frame_multi(parser: PatchableWebSocketReader) -> None:
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


def test_parse_compress_error_frame(parser: PatchableWebSocketReader) -> None:
    parser.parse_frame(struct.pack("!BB", 0b01000001, 0b00000001))
    parser.parse_frame(b"1")

    with pytest.raises(WebSocketError) as ctx:
        parser.parse_frame(struct.pack("!BB", 0b11000001, 0b00000001))
        parser.parse_frame(b"1")

    assert ctx.value.code == WSCloseCode.PROTOCOL_ERROR


@pytest.mark.usefixtures("parametrize_zlib_backend")
async def test_parse_no_compress_frame_single(
    loop: asyncio.AbstractEventLoop, out: WebSocketDataQueue
) -> None:
    parser_no_compress = PatchableWebSocketReader(out, 0, compress=False)
    with pytest.raises(WebSocketError) as ctx:
        parser_no_compress.parse_frame(struct.pack("!BB", 0b11000001, 0b00000001))
        parser_no_compress.parse_frame(b"1")

    assert ctx.value.code == WSCloseCode.PROTOCOL_ERROR


def test_msg_too_large(out) -> None:
    parser = WebSocketReader(out, 256, compress=False)
    data = build_frame(b"text" * 256, WSMsgType.TEXT)
    with pytest.raises(WebSocketError) as ctx:
        parser._feed_data(data)
    assert ctx.value.code == WSCloseCode.MESSAGE_TOO_BIG


def test_msg_too_large_not_fin(out) -> None:
    parser = WebSocketReader(out, 256, compress=False)
    data = build_frame(b"text" * 256, WSMsgType.TEXT, is_fin=False)
    with pytest.raises(WebSocketError) as ctx:
        parser._feed_data(data)
    assert ctx.value.code == WSCloseCode.MESSAGE_TOO_BIG


def test_compressed_msg_too_large(out) -> None:
    parser = WebSocketReader(out, 256, compress=True)
    data = build_frame(b"aaa" * 256, WSMsgType.TEXT, ZLibBackend=ZLibBackend)
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


def test_flow_control_binary(
    protocol: BaseProtocol,
    out_low_limit: WebSocketDataQueue,
    parser_low_limit: PatchableWebSocketReader,
) -> None:
    large_payload = b"b" * (1 + 16 * 2)
    large_payload_size = len(large_payload)
    parser_low_limit._handle_frame(True, WSMsgType.BINARY, large_payload, 0)
    res = out_low_limit._buffer[0]
    assert res == (WSMessage(WSMsgType.BINARY, large_payload, ""), large_payload_size)
    assert protocol._reading_paused is True


def test_flow_control_multi_byte_text(
    protocol: BaseProtocol,
    out_low_limit: WebSocketDataQueue,
    parser_low_limit: PatchableWebSocketReader,
) -> None:
    large_payload_text = "𒀁" * (1 + 16 * 2)
    large_payload = large_payload_text.encode("utf-8")
    large_payload_size = len(large_payload)
    parser_low_limit._handle_frame(True, WSMsgType.TEXT, large_payload, 0)
    res = out_low_limit._buffer[0]
    assert res == (
        WSMessage(WSMsgType.TEXT, large_payload_text, ""),
        large_payload_size,
    )
    assert protocol._reading_paused is True
