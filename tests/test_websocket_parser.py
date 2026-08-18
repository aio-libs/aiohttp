import asyncio
import gc
import pickle
import random
import struct
import weakref
import zlib
from unittest import mock

import pytest

from aiohttp._websocket import helpers as _websocket_helpers
from aiohttp._websocket.helpers import (
    PACK_CLOSE_CODE,
    PACK_LEN1,
    PACK_LEN2,
    PACK_LEN3,
    PACK_RANDBITS,
    websocket_mask,
)
from aiohttp._websocket.models import WS_DEFLATE_TRAILING
from aiohttp._websocket.reader import WebSocketDataQueue
from aiohttp._websocket.reader_py import MSG_SIZE_OVERHEAD
from aiohttp.base_protocol import BaseProtocol
from aiohttp.compression_utils import ZLibBackend, ZLibBackendWrapper
from aiohttp.helpers import DEFAULT_CHUNK_SIZE
from aiohttp.http import HttpParser, WebSocketError, WSCloseCode, WSMsgType
from aiohttp.http_websocket import (
    WebSocketReader,
    WSMessageBinary,
    WSMessageClose,
    WSMessagePing,
    WSMessagePong,
    WSMessageText,
)
from aiohttp.streams import EofStream


class PatchableWebSocketReader(WebSocketReader):
    """WebSocketReader subclass that allows for patching parse_frame."""

    def parse_frame(
        self, data: bytes
    ) -> list[tuple[bool, int, bytes | bytearray, int]]:
        # This method is overridden to allow for patching in tests.
        frames: list[tuple[bool, int, bytes | bytearray, int]] = []

        def _handle_frame(
            fin: bool,
            opcode: int,
            payload: bytes | bytearray,
            compressed: int,
        ) -> None:
            # This method is overridden to allow for patching in tests.
            frames.append((fin, opcode, payload, compressed))

        with mock.patch.object(self, "_handle_frame", _handle_frame):
            self._feed_data(data)
        return frames


def build_frame(
    message: bytes,
    opcode: int,
    noheader: bool = False,
    is_fin: bool = True,
    ZLibBackend: ZLibBackendWrapper | None = None,
    mask: bool = False,
) -> bytes:
    # Send a frame over the websocket with message as its payload.
    compress = False
    if ZLibBackend:
        compress = True
        compressobj = ZLibBackend.compressobj(wbits=-9)
        message = compressobj.compress(message)
        message = message + compressobj.flush(ZLibBackend.Z_SYNC_FLUSH)
        assert message.endswith(WS_DEFLATE_TRAILING)
        message = message[:-4]
    msg_length = len(message)

    if is_fin:
        header_first_byte = 0x80 | opcode
    else:
        header_first_byte = opcode

    if compress:
        header_first_byte |= 0x40

    mask_bit = 0x80 if mask else 0

    if msg_length < 126:
        header = PACK_LEN1(header_first_byte, msg_length | mask_bit)
    elif msg_length < 65536:
        header = PACK_LEN2(header_first_byte, 126 | mask_bit, msg_length)
    else:
        header = PACK_LEN3(header_first_byte, 127 | mask_bit, msg_length)

    if mask:
        assert not noheader
        mask_bytes = PACK_RANDBITS(random.getrandbits(32))
        message_arr = bytearray(message)
        websocket_mask(mask_bytes, message_arr)
        return header + mask_bytes + message_arr

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
def protocol(event_loop: asyncio.AbstractEventLoop) -> BaseProtocol:
    parser = mock.create_autospec(HttpParser, spec_set=True, instance=True)
    transport = mock.Mock(spec_set=asyncio.Transport)
    protocol = BaseProtocol(event_loop, parser=parser)
    protocol.connection_made(transport)
    return protocol


@pytest.fixture()
def out(event_loop: asyncio.AbstractEventLoop) -> WebSocketDataQueue:
    return WebSocketDataQueue(mock.Mock(_reading_paused=False), 2**16, loop=event_loop)


@pytest.fixture()
def out_low_limit(
    event_loop: asyncio.AbstractEventLoop, protocol: BaseProtocol
) -> WebSocketDataQueue:
    return WebSocketDataQueue(protocol, 16, loop=event_loop)


@pytest.fixture()
def parser_low_limit(
    out_low_limit: WebSocketDataQueue,
) -> PatchableWebSocketReader:
    return PatchableWebSocketReader(
        out_low_limit, 4 * 1024 * 1024, compress=True, decode_text=True
    )


@pytest.fixture()
def parser(out: WebSocketDataQueue) -> PatchableWebSocketReader:
    return PatchableWebSocketReader(
        out, 4 * 1024 * 1024, compress=True, decode_text=True
    )


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


def test_parse_frame_header_control_frame(
    out: WebSocketDataQueue, parser: PatchableWebSocketReader
) -> None:
    with pytest.raises(WebSocketError):
        parser.parse_frame(struct.pack("!BB", 0b00001000, 0b00000000))


def test_parse_frame_header_new_data_err(parser: PatchableWebSocketReader) -> None:
    with pytest.raises(WebSocketError) as msg:
        parser._feed_data(struct.pack("!BB", 0b00000000, 0b00000000))
    assert msg.value.code == WSCloseCode.PROTOCOL_ERROR
    assert str(msg.value) == "Continuation frame for non started message"


def test_parse_frame_header_payload_size(
    out: WebSocketDataQueue, parser: PatchableWebSocketReader
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
    out: WebSocketDataQueue,
    parser: PatchableWebSocketReader,
    data: bytes | bytearray | memoryview,
) -> None:
    parser._handle_frame(True, WSMsgType.PING, b"data", 0)
    res = out._buffer[0]
    assert res == WSMessagePing(data=b"data", size=4, extra="")


def test_pong_frame(out: WebSocketDataQueue, parser: PatchableWebSocketReader) -> None:
    parser._handle_frame(True, WSMsgType.PONG, b"data", 0)
    res = out._buffer[0]
    assert res == WSMessagePong(data=b"data", size=4, extra="")


def test_close_frame(out: WebSocketDataQueue, parser: PatchableWebSocketReader) -> None:
    parser._handle_frame(True, WSMsgType.CLOSE, b"", 0)
    res = out._buffer[0]
    assert res == WSMessageClose(data=0, size=0, extra="")


def test_close_frame_info(
    out: WebSocketDataQueue, parser: PatchableWebSocketReader
) -> None:
    parser._handle_frame(True, WSMsgType.CLOSE, b"\x03\xe912345", 0)
    res = out._buffer[0]
    assert res == WSMessageClose(data=1001, size=7, extra="12345")


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


@pytest.mark.parametrize("code", (5000, 9999, 65535))
def test_close_frame_invalid_code_above_range(
    parser: PatchableWebSocketReader, code: int
) -> None:
    data = build_close_frame(code=code)

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
    assert res == WSMessageText(data="text", size=4, extra="")


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
    assert res == WSMessageBinary(data=b"binary", size=6, extra="")


def test_one_byte_at_a_time(
    out: WebSocketDataQueue, parser: PatchableWebSocketReader
) -> None:
    """Send one byte at a time to the parser."""
    data = build_frame(b"binary", WSMsgType.BINARY)
    for i in range(len(data)):
        parser._feed_data(data[i : i + 1])
    res = out._buffer[0]
    assert res == WSMessageBinary(data=b"binary", size=6, extra="")


def test_fragmentation_header(
    out: WebSocketDataQueue, parser: PatchableWebSocketReader
) -> None:
    data = build_frame(b"a", WSMsgType.TEXT)
    parser._feed_data(data[:1])
    parser._feed_data(data[1:])

    res = out._buffer[0]
    assert res == WSMessageText(data="a", size=1, extra="")


def test_large_message(
    out: WebSocketDataQueue, parser: PatchableWebSocketReader
) -> None:
    large_payload = b"b" * 131072
    data = build_frame(large_payload, WSMsgType.BINARY)
    parser._feed_data(data)

    res = out._buffer[0]
    assert res == WSMessageBinary(data=large_payload, size=131072, extra="")


def test_large_masked_message(
    out: WebSocketDataQueue, parser: PatchableWebSocketReader
) -> None:
    large_payload = b"b" * 131072
    data = build_frame(large_payload, WSMsgType.BINARY, mask=True)
    parser._feed_data(data)

    res = out._buffer[0]
    assert res == WSMessageBinary(data=large_payload, size=131072, extra="")


def test_fragmented_masked_message(
    out: WebSocketDataQueue, parser: PatchableWebSocketReader
) -> None:
    large_payload = b"b" * 100
    data = build_frame(large_payload, WSMsgType.BINARY, mask=True)
    for i in range(len(data)):
        parser._feed_data(data[i : i + 1])

    res = out._buffer[0]
    assert res == WSMessageBinary(data=large_payload, size=100, extra="")


def test_large_fragmented_masked_message(
    out: WebSocketDataQueue, parser: PatchableWebSocketReader
) -> None:
    large_payload = b"b" * 131072
    data = build_frame(large_payload, WSMsgType.BINARY, mask=True)
    for i in range(0, len(data), 16384):
        parser._feed_data(data[i : i + 16384])
    res = out._buffer[0]
    assert res == WSMessageBinary(data=large_payload, size=131072, extra="")


def test_continuation(
    out: WebSocketDataQueue, parser: PatchableWebSocketReader
) -> None:
    data1 = build_frame(b"line1", WSMsgType.TEXT, is_fin=False)
    parser._feed_data(data1)

    data2 = build_frame(b"line2", WSMsgType.CONTINUATION)
    parser._feed_data(data2)

    res = out._buffer[0]
    assert res == WSMessageText(data="line1line2", size=10, extra="")


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
    assert res == WSMessagePing(data=b"", size=0, extra="")
    res = out._buffer[1]
    assert res == WSMessageText(data="line1line2", size=10, extra="")


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
    assert res == WSMessageClose(data=1002, size=6, extra="test")
    res = out._buffer[1]
    assert res == WSMessageText(data="line1line2", size=10, extra="")


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
    assert res == WSMessageClose(data=0, size=0, extra="")
    res = out._buffer[1]
    assert res == WSMessageText(data="line1line2", size=10, extra="")


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


def test_compressed_continuation_with_ping(
    out: WebSocketDataQueue, parser: PatchableWebSocketReader
) -> None:
    # A control frame may be interleaved between the fragments of a data
    # message. The continuation must still be decompressed.
    # https://datatracker.ietf.org/doc/html/rfc6455#section-5.4
    message = b"hello compressed world " * 4
    compressobj = ZLibBackend.compressobj(wbits=-9)
    compressed = compressobj.compress(message)
    compressed += compressobj.flush(ZLibBackend.Z_SYNC_FLUSH)
    assert compressed.endswith(WS_DEFLATE_TRAILING)
    compressed = compressed[:-4]
    half = len(compressed) // 2

    # first fragment: compressed binary, RSV1 set, not final
    parser.feed_data(PACK_LEN1(0x40 | WSMsgType.BINARY, half) + compressed[:half])
    # interleaved ping
    parser.feed_data(PACK_LEN1(0x80 | WSMsgType.PING, 0))
    # final continuation fragment
    parser.feed_data(
        PACK_LEN1(0x80 | WSMsgType.CONTINUATION, len(compressed) - half)
        + compressed[half:]
    )

    assert out._buffer[0] == WSMessagePing(data=b"", size=0, extra="")
    assert out._buffer[1] == WSMessageBinary(data=message, size=len(message), extra="")


def test_compressed_frame_after_control_frame(
    out: WebSocketDataQueue, parser: PatchableWebSocketReader
) -> None:
    # A control frame arriving before the first data frame must not
    # latch the per-message compression state.
    # https://github.com/aio-libs/aiohttp/issues/13274
    parser.feed_data(PACK_LEN1(0x80 | WSMsgType.PONG, 0))
    parser.feed_data(build_frame(b"hello", WSMsgType.TEXT, ZLibBackend=ZLibBackend))

    assert out._buffer[0] == WSMessagePong(data=b"", size=0, extra="")
    assert out._buffer[1] == WSMessageText(data="hello", size=5, extra="")


# A complete raw-deflate member: BFINAL set, empty fixed-Huffman block,
# decoding to nothing.
EMPTY_DEFLATE_MEMBER = b"\x03\x00"


@pytest.mark.usefixtures("parametrize_zlib_backend")
def test_compressed_multi_block_message(out: WebSocketDataQueue) -> None:
    """Blocks that leave BFINAL unset stay a single member."""
    reader = WebSocketReader(out, 4 * 1024 * 1024, compress=True, decode_text=True)
    compressobj = zlib.compressobj(wbits=-15)
    payload = b"".join(
        compressobj.compress(b"block %d " % i)
        + compressobj.flush(ZLibBackend.Z_SYNC_FLUSH)
        for i in range(50)
    ).removesuffix(WS_DEFLATE_TRAILING)
    expected = b"".join(b"block %d " % i for i in range(50))

    # FIN | RSV1 (compressed) | BINARY
    error, _ = reader.feed_data(
        PACK_LEN2(0x80 | 0x40 | WSMsgType.BINARY, 126, len(payload)) + payload
    )

    assert error is False
    assert out._buffer[0] == WSMessageBinary(
        data=expected, size=len(expected), extra=""
    )


@pytest.mark.usefixtures("parametrize_zlib_backend")
def test_compressed_multi_member_message(out: WebSocketDataQueue) -> None:
    """Concatenated BFINAL members decode.

    A block following a BFINAL one starts a fresh deflate member, so this must
    keep working well below the member limit.
    """
    reader = WebSocketReader(out, 4 * 1024 * 1024, compress=True, decode_text=True)
    payload = b""
    for i in range(50):
        compressobj = zlib.compressobj(wbits=-15)
        payload += compressobj.compress(b"part %d " % i) + compressobj.flush()
    expected = b"".join(b"part %d " % i for i in range(50))

    error, _ = reader.feed_data(
        PACK_LEN2(0x80 | 0x40 | WSMsgType.BINARY, 126, len(payload)) + payload
    )

    assert error is False
    assert out._buffer[0] == WSMessageBinary(
        data=expected, size=len(expected), extra=""
    )


@pytest.mark.usefixtures("parametrize_zlib_backend")
def test_compressed_member_flood_rejected(out: WebSocketDataQueue) -> None:
    """Past the member limit the message is rejected, not decoded.

    The reader hands the whole assembled message to one synchronous
    decompress_sync() call. Empty members produce no output for max_msg_size
    to bound, so must be limited by member count.
    """
    max_msg_size = 262144
    reader = WebSocketReader(out, max_msg_size, compress=True, decode_text=True)
    payload = EMPTY_DEFLATE_MEMBER * (2 * max_msg_size // 256)

    with pytest.raises(WebSocketError) as ctx:
        reader._feed_data(
            PACK_LEN2(0x80 | 0x40 | WSMsgType.BINARY, 126, len(payload)) + payload
        )

    assert ctx.value.code == WSCloseCode.MESSAGE_TOO_BIG


@pytest.mark.parametrize("opcode", (WSMsgType.PING, WSMsgType.PONG, WSMsgType.CLOSE))
def test_control_frame_with_rsv1(
    parser: PatchableWebSocketReader, opcode: WSMsgType
) -> None:
    # Control frames never carry the per-message compressed bit.
    # https://datatracker.ietf.org/doc/html/rfc7692#section-6.1
    with pytest.raises(WebSocketError) as ctx:
        parser._feed_data(PACK_LEN1(0xC0 | opcode, 0))

    assert ctx.value.code == WSCloseCode.PROTOCOL_ERROR


def test_parse_compress_error_frame(parser: PatchableWebSocketReader) -> None:
    parser.parse_frame(struct.pack("!BB", 0b01000001, 0b00000001))
    parser.parse_frame(b"1")

    with pytest.raises(WebSocketError) as ctx:
        parser.parse_frame(struct.pack("!BB", 0b11000001, 0b00000001))

    assert ctx.value.code == WSCloseCode.PROTOCOL_ERROR


def test_parse_no_compress_frame_single(out: WebSocketDataQueue) -> None:
    parser_no_compress = PatchableWebSocketReader(
        out, 0, compress=False, decode_text=True
    )
    with pytest.raises(WebSocketError) as ctx:
        parser_no_compress.parse_frame(struct.pack("!BB", 0b11000001, 0b00000001))

    assert ctx.value.code == WSCloseCode.PROTOCOL_ERROR


def test_msg_too_large(out: WebSocketDataQueue) -> None:
    parser = WebSocketReader(out, 256, compress=False, decode_text=True)
    data = build_frame(b"text" * 256, WSMsgType.TEXT)
    with pytest.raises(WebSocketError) as ctx:
        parser._feed_data(data)
    assert ctx.value.code == WSCloseCode.MESSAGE_TOO_BIG


def test_msg_too_large_not_fin(out: WebSocketDataQueue) -> None:
    parser = WebSocketReader(out, 256, compress=False, decode_text=True)
    data = build_frame(b"text" * 256, WSMsgType.TEXT, is_fin=False)
    with pytest.raises(WebSocketError) as ctx:
        parser._feed_data(data)
    assert ctx.value.code == WSCloseCode.MESSAGE_TOO_BIG


@pytest.mark.usefixtures("parametrize_zlib_backend")
def test_compressed_msg_too_large(out: WebSocketDataQueue) -> None:
    parser = WebSocketReader(out, 256, compress=True, decode_text=True)
    data = build_frame(b"aaa" * 256, WSMsgType.TEXT, ZLibBackend=ZLibBackend)
    with pytest.raises(WebSocketError) as ctx:
        parser._feed_data(data)
    assert ctx.value.code == WSCloseCode.MESSAGE_TOO_BIG


@pytest.mark.parametrize("fin", (0x80, 0x00), ids=("fin", "non-fin"))
def test_msg_too_large_at_header(out: WebSocketDataQueue, fin: int) -> None:
    max_msg_size = 256
    parser = WebSocketReader(out, max_msg_size, compress=False, decode_text=True)

    # Header alone: TEXT, 64-bit length, declares 1 MiB of payload.
    header = PACK_LEN3(fin | WSMsgType.TEXT, 127, 1024 * 1024)
    with pytest.raises(
        WebSocketError, match=r"^Message size 1048576 exceeds limit 256$"
    ) as ctx:
        parser._feed_data(header)
    assert ctx.value.code == WSCloseCode.MESSAGE_TOO_BIG


def test_msg_too_large_across_fragments(out: WebSocketDataQueue) -> None:
    # Individual fragments fit under max_msg_size but accumulate past it.
    max_msg_size = 256
    parser = WebSocketReader(out, max_msg_size, compress=False, decode_text=True)

    first = build_frame(b"a" * 100, WSMsgType.TEXT, is_fin=False)
    parser._feed_data(first)
    middle = build_frame(b"b" * 100, WSMsgType.CONTINUATION, is_fin=False)
    parser._feed_data(middle)

    # Third 100-byte fragment would push the accumulated total to 300.
    last = build_frame(b"c" * 100, WSMsgType.CONTINUATION, is_fin=False)
    with pytest.raises(
        WebSocketError, match=r"^Message size 300 exceeds limit 256$"
    ) as ctx:
        parser._feed_data(last)
    assert ctx.value.code == WSCloseCode.MESSAGE_TOO_BIG


def test_msg_too_large_text_after_non_fin_text(out: WebSocketDataQueue) -> None:
    # Protocol-violating sequence: a fresh TEXT arrives while a fragmented
    # message is still open.
    max_msg_size = 256
    parser = WebSocketReader(out, max_msg_size, compress=False, decode_text=True)

    first = build_frame(b"a" * 200, WSMsgType.TEXT, is_fin=False)
    parser._feed_data(first)

    # Second TEXT header alone announces 100 bytes; 100 + 200 partial = 300.
    second_header = PACK_LEN1(WSMsgType.TEXT, 100)
    with pytest.raises(
        WebSocketError, match=r"^Message size 300 exceeds limit 256$"
    ) as ctx:
        parser._feed_data(second_header)
    assert ctx.value.code == WSCloseCode.MESSAGE_TOO_BIG


@pytest.mark.parametrize(
    "opcode",
    (0x3, 0x4, 0x5, 0x6, 0x7, 0xB, 0xC, 0xD, 0xE, 0xF),
    ids=lambda v: f"0x{v:x}",
)
def test_reserved_opcode_rejected_at_header(
    out: WebSocketDataQueue, opcode: int
) -> None:
    # RFC 6455 reserves opcodes 0x3-0x7 (non-control) and 0xB-0xF (control).
    parser = WebSocketReader(out, max_msg_size=256, compress=False, decode_text=True)

    header = PACK_LEN3(0x80 | opcode, 127, 1024 * 1024)
    with pytest.raises(WebSocketError, match=rf"^Unexpected opcode={opcode}$") as ctx:
        parser._feed_data(header)
    assert ctx.value.code == WSCloseCode.PROTOCOL_ERROR


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


def test_flow_control_binary(
    protocol: BaseProtocol,
    out_low_limit: WebSocketDataQueue,
    parser_low_limit: PatchableWebSocketReader,
) -> None:
    large_payload = b"b" * (1 + 16 * 2)
    large_payload_size = len(large_payload)
    parser_low_limit._handle_frame(True, WSMsgType.BINARY, large_payload, 0)
    res = out_low_limit._buffer[0]
    assert res == WSMessageBinary(data=large_payload, size=large_payload_size, extra="")
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
    assert res == WSMessageText(
        data=large_payload_text, size=large_payload_size, extra=""
    )
    assert protocol._reading_paused is True


async def test_incomplete_frame_pauses_when_fragment_limit_exceeded(
    protocol: BaseProtocol,
) -> None:
    max_msg_size = 64 * 1024
    loop = asyncio.get_running_loop()
    out = WebSocketDataQueue(protocol, 2**16, loop=loop)
    parser = WebSocketReader(out, max_msg_size, compress=False, decode_text=False)

    payload_len = 32 * 1024
    parser.feed_data(PACK_LEN2(0x80 | WSMsgType.BINARY, 126, payload_len))
    assert protocol._reading_paused is False

    # Feed the payload two bytes per read so the pause is
    # driven purely by the fragment count, not the total byte count.
    paused_after = None
    for i in range(payload_len // 2 - 1):  # pragma: no branch
        parser.feed_data(b"xx")
        if protocol._reading_paused:
            paused_after = i + 1  # type: ignore[unreachable]
            break

    assert paused_after is not None
    # Paused long before the frame could complete (16384 two-byte reads).
    assert paused_after < payload_len // 2  # type: ignore[unreachable]


async def test_incomplete_frame_not_paused_for_normal_reads(
    protocol: BaseProtocol,
) -> None:
    max_msg_size = 64 * 1024
    loop = asyncio.get_running_loop()
    out = WebSocketDataQueue(protocol, 2**16, loop=loop)
    parser = WebSocketReader(out, max_msg_size, compress=False, decode_text=False)

    # Normal traffic (a frame delivered in a handful of reasonably sized reads)
    # must never trip the fragment-limit backpressure.
    payload_len = 32 * 1024
    parser.feed_data(PACK_LEN2(0x80 | WSMsgType.BINARY, 126, payload_len))
    # 32 KiB in 4 KiB reads -> 8 fragments, far below the cap.
    for _ in range(payload_len // 4096):
        parser.feed_data(b"x" * 4096)
    assert protocol._reading_paused is False


def _compressed_burst(payload: bytes, count: int) -> bytes:
    """`count` complete, independently deflated BINARY messages in one read."""
    return build_frame(
        payload, WSMsgType.BINARY, ZLibBackend=ZLibBackend, mask=True
    ) * (count)


async def test_empty_messages_apply_backpressure(protocol: BaseProtocol) -> None:
    # Zero-length messages are not free: each one is a queued object. They used
    # to add nothing to the queue's byte counter, so a peer could stream empty
    # frames forever without the transport ever being paused.
    high_water = 2 * 2**16
    loop = asyncio.get_running_loop()
    out = WebSocketDataQueue(protocol, 2**16, loop=loop)
    parser = WebSocketReader(out, 4 * 1024 * 1024, compress=False, decode_text=True)

    sent = 10000
    parser.feed_data(build_frame(b"", WSMsgType.TEXT, mask=True) * sent)

    assert protocol._reading_paused is True
    assert len(out._buffer) < sent
    assert len(out._buffer) * MSG_SIZE_OVERHEAD <= high_water + MSG_SIZE_OVERHEAD


async def test_compressed_burst_stops_at_high_water(protocol: BaseProtocol) -> None:
    # permessage-deflate reaches ~1000:1, so a single read can carry dozens of
    # complete frames that each inflate to max_msg_size. pause_reading() only
    # stops the transport from delivering more data; the parser has to stop
    # too, or the whole read is inflated into the queue in one go.
    loop = asyncio.get_running_loop()
    out = WebSocketDataQueue(protocol, 2**16, loop=loop)
    parser = WebSocketReader(out, 1024 * 1024, compress=True, decode_text=False)

    payload = b"\0" * (512 * 1024)
    burst = _compressed_burst(payload, 32)
    assert len(burst) < 2**16  # the whole burst is one plausible socket read

    parser.feed_data(burst)

    assert protocol._reading_paused is True
    # Overshoot is capped at the one message that crossed the mark, not the
    # 16 MiB the peer asked us to inflate.
    assert len(out._buffer) == 1
    assert sum(msg.size for msg in out._buffer) == len(payload)


async def test_read_arriving_over_high_water_inflates_nothing(
    protocol: BaseProtocol,
) -> None:
    # pause_reading() does not retract a read already in flight (the proactor
    # transport completes its outstanding overlapped read, and a transport
    # without flow control ignores the pause entirely). Such a read must not
    # buy the peer one more inflated message before the parser stops again.
    loop = asyncio.get_running_loop()
    out = WebSocketDataQueue(protocol, 2**16, loop=loop)
    parser = WebSocketReader(out, 1024 * 1024, compress=True, decode_text=False)

    payload = b"\0" * (512 * 1024)
    parser.feed_data(_compressed_burst(payload, 2))
    assert len(out._buffer) == 1

    # Lands while the queue is still over the mark and nothing has drained.
    parser.feed_data(_compressed_burst(payload, 2))
    assert len(out._buffer) == 1

    # All four are still delivered once the application catches up.
    for _ in range(4):
        msg = await asyncio.wait_for(out.read(), 5)
        assert msg.data == payload


async def test_backpressure_does_not_drop_stashed_frames(
    protocol: BaseProtocol,
) -> None:
    # The frames the parser stopped short of must still be delivered as the
    # application drains the queue, with no further socket data to drive it.
    loop = asyncio.get_running_loop()
    out = WebSocketDataQueue(protocol, 2**16, loop=loop)
    parser = WebSocketReader(out, 1024 * 1024, compress=True, decode_text=False)

    payload = b"\0" * (512 * 1024)
    parser.feed_data(_compressed_burst(payload, 32))

    for _ in range(32):
        msg = await asyncio.wait_for(out.read(), 5)
        assert msg.data == payload

    assert not out._buffer
    # feed_data() adds MSG_SIZE_OVERHEAD and _read_from_buffer() subtracts it;
    # _size is an unsigned int under Cython, so if those ever drift the
    # subtraction wraps to ~4G rather than going negative. _size < _limit is
    # then permanently false and the connection wedges silently: the transport
    # is never resumed and the stalled parser is never driven again.
    assert out._size == 0
    assert protocol._reading_paused is False


async def test_backpressure_stash_survives_eof(protocol: BaseProtocol) -> None:
    # A peer that bursts and then disconnects must not lose the tail: at EOF
    # there is no resume to ride on, so draining has to keep driving the parser.
    loop = asyncio.get_running_loop()
    out = WebSocketDataQueue(protocol, 2**16, loop=loop)
    parser = WebSocketReader(out, 1024 * 1024, compress=True, decode_text=False)

    payload = b"\0" * (512 * 1024)
    parser.feed_data(_compressed_burst(payload, 8))
    parser.feed_eof()

    for _ in range(8):
        msg = await asyncio.wait_for(out.read(), 5)
        assert msg.data == payload

    with pytest.raises(EofStream):
        await asyncio.wait_for(out.read(), 5)


async def test_stalled_reader_reference_released_after_drain(
    protocol: BaseProtocol,
) -> None:
    # The queue holds the reader back only while parsing is stalled. Keeping it
    # any longer would leave reader <-> queue as a cycle outliving the
    # connection, reclaimable only by the collector rather than by refcounting.
    loop = asyncio.get_running_loop()
    out = WebSocketDataQueue(protocol, 2**16, loop=loop)
    parser = WebSocketReader(out, 1024 * 1024, compress=True, decode_text=False)

    payload = b"\0" * (512 * 1024)
    parser.feed_data(_compressed_burst(payload, 4))
    stalled = out._stalled_reader
    assert stalled is not None and stalled() is parser

    for _ in range(4):
        await asyncio.wait_for(out.read(), 5)

    assert out._stalled_reader is None


async def test_set_exception_still_delivers_stashed_frames(
    protocol: BaseProtocol,
) -> None:
    # set_exception() is also the transport-died hook (WebSocketResponse._cancel).
    # _read_from_buffer() only raises once the buffer is empty, so complete
    # frames the parser stopped short of must still be delivered first, exactly
    # as they were before the parser learned to stall.
    loop = asyncio.get_running_loop()
    out = WebSocketDataQueue(protocol, DEFAULT_CHUNK_SIZE, loop=loop)
    parser = WebSocketReader(out, 1024 * 1024, compress=False, decode_text=True)

    sent = 8000
    parser.feed_data(build_frame(b"", WSMsgType.TEXT, mask=True) * sent)
    stalled = len(out._buffer)
    assert stalled < sent

    out.set_exception(ConnectionResetError())

    received = 0
    with pytest.raises(ConnectionResetError):
        for _ in range(sent + 1):
            await asyncio.wait_for(out.read(), 5)
            received += 1
    assert received == sent


async def test_parse_error_abandons_the_stash(protocol: BaseProtocol) -> None:
    # A parse error poisons the reader, so re-driving it from a drain is a
    # no-op and the error surfaces once the buffer is empty.
    loop = asyncio.get_running_loop()
    out = WebSocketDataQueue(protocol, 2**16, loop=loop)
    parser = WebSocketReader(out, 1024 * 1024, compress=True, decode_text=False)

    payload = b"\0" * (512 * 1024)
    # The reserved opcode sits behind the stash, so it is only reached on a
    # drain-driven resume.
    parser.feed_data(_compressed_burst(payload, 3) + build_frame(b"", 0x3, mask=True))
    stalled = out._stalled_reader
    assert stalled is not None and stalled() is parser

    for _ in range(3):
        await asyncio.wait_for(out.read(), 5)
    with pytest.raises(WebSocketError):
        await asyncio.wait_for(out.read(), 5)


async def test_queue_does_not_keep_stalled_reader_alive(
    protocol: BaseProtocol,
) -> None:
    # The one case feed_eof() cannot clean up: the connection dies while
    # parsing is stalled, then the application drops the response without
    # draining. The queue's link back must be weak or reader <-> queue
    # survives as a cycle that only the collector can reclaim.
    loop = asyncio.get_running_loop()
    out = WebSocketDataQueue(protocol, 2**16, loop=loop)
    parser = WebSocketReader(out, 1024 * 1024, compress=True, decode_text=False)

    parser.feed_data(_compressed_burst(b"\0" * (512 * 1024), 4))
    parser.feed_eof()
    # `parser` deliberately never appears in an assert: pytest's assertion
    # rewriting keeps temporaries for the failure message, and a lingering
    # reference to it would mask the very thing under test.
    stalled = out._stalled_reader
    assert stalled is not None

    ref = weakref.ref(parser)
    del parser, stalled
    # `out` deliberately stays alive across the collection: a strong link back
    # would keep the reader reachable from a live root, so this proves the link
    # is weak rather than merely testing reclamation timing. Collect instead of
    # disabling the gc -- PyPy has no refcounting to reclaim eagerly, and can
    # need more than one pass to clear the weakref.
    for _ in range(3):
        gc.collect()

    assert ref() is None, "queue kept the stalled reader alive"
    assert out._stalled_reader is not None and out._stalled_reader() is None


async def test_burst_under_high_water_is_parsed_in_one_read(
    protocol: BaseProtocol,
) -> None:
    # Ordinary pipelined traffic that fits under the mark must not be stalled
    # or split across reads by the backpressure check.
    loop = asyncio.get_running_loop()
    out = WebSocketDataQueue(protocol, 2**16, loop=loop)
    parser = WebSocketReader(out, 1024 * 1024, compress=False, decode_text=True)

    parser.feed_data(build_frame(b"hello", WSMsgType.TEXT, mask=True) * 50)

    assert len(out._buffer) == 50
    assert protocol._reading_paused is False
