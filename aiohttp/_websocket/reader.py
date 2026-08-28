"""Reader for WebSocket protocol versions 13 and 8."""

import asyncio
import builtins
import sys
import weakref
from collections import deque
from typing import Final

from mypy_extensions import i64, mypyc_attr

from ..base_protocol import BaseProtocol
from ..compression_utils import TooManyMembersError, ZLibDecompressor
from ..helpers import _EXC_SENTINEL, set_exception
from ..log import ws_logger
from ..streams import EofStream
from ._wrbase import _InterpretedReadMixin, _WeakrefBase
from .helpers import (
    UNPACK_CLOSE_CODE as _UNPACK_CLOSE_CODE,
    UNPACK_LEN3 as _UNPACK_LEN3,
    websocket_mask as _websocket_mask,
)
from .models import (
    WS_DEFLATE_TRAILING as _WS_DEFLATE_TRAILING,
    WebSocketError,
    WSCloseCode,
    WSMessage,
    WSMessageBinary as _WSMessageBinary,
    WSMessageClose as _WSMessageClose,
    WSMessagePing as _WSMessagePing,
    WSMessagePong as _WSMessagePong,
    WSMessageText as _WSMessageText,
    WSMessageTextBytes as _WSMessageTextBytes,
    WSMsgType,
)

# Per-frame imported names: Final re-binds turn globals-dict lookups into
# static loads.  Use sites below are unchanged.
UNPACK_CLOSE_CODE: Final = _UNPACK_CLOSE_CODE
UNPACK_LEN3: Final = _UNPACK_LEN3
websocket_mask: Final = _websocket_mask
WS_DEFLATE_TRAILING: Final = _WS_DEFLATE_TRAILING
WSMessageBinary: Final = _WSMessageBinary
WSMessageClose: Final = _WSMessageClose
WSMessagePing: Final = _WSMessagePing
WSMessagePong: Final = _WSMessagePong
WSMessageText: Final = _WSMessageText
WSMessageTextBytes: Final = _WSMessageTextBytes

ALLOWED_CLOSE_CODES: Final = {int(i) for i in WSCloseCode} - {
    int(WSCloseCode.ABNORMAL_CLOSURE)
}

# States for the reader, used to parse the WebSocket frame.
READ_HEADER: Final = 1
READ_PAYLOAD_LENGTH: Final = 2
READ_PAYLOAD_MASK: Final = 3
READ_PAYLOAD: Final = 4

# Largest declared payload length the reader can represent: the compiled
# reader stores it in a Py_ssize_t, which holds 2**31-1 on the 32-bit builds
# (the win32 and armv7l wheels) and 2**63-1 everywhere else.
# TODO: Remove when we drop 32 bit support.
MAX_PAYLOAD_LEN: Final = sys.maxsize

WS_MSG_TYPE_BINARY: Final = WSMsgType.BINARY
WS_MSG_TYPE_TEXT: Final = WSMsgType.TEXT

# WSMsgType values as literal Final ints (guarded below) so mypyc inlines them
OP_CODE_NOT_SET: Final = -1
OP_CODE_CONTINUATION: Final = 0
OP_CODE_TEXT: Final = 1
OP_CODE_BINARY: Final = 2
OP_CODE_CLOSE: Final = 8
OP_CODE_PING: Final = 9
OP_CODE_PONG: Final = 10
assert (
    OP_CODE_CONTINUATION,
    OP_CODE_TEXT,
    OP_CODE_BINARY,
    OP_CODE_CLOSE,
    OP_CODE_PING,
    OP_CODE_PONG,
) == (
    WSMsgType.CONTINUATION,
    WSMsgType.TEXT,
    WSMsgType.BINARY,
    WSMsgType.CLOSE,
    WSMsgType.PING,
    WSMsgType.PONG,
), "OP_CODE_* literals out of sync with WSMsgType"

EMPTY_FRAME_ERROR: Final = (True, b"")
EMPTY_FRAME: Final = (False, b"")

COMPRESSED_NOT_SET: Final = -1
COMPRESSED_FALSE: Final = 0
COMPRESSED_TRUE: Final = 1

TUPLE_NEW: Final = tuple.__new__

# Overhead added to each message to ensure that tiny messages can't use
# unreasonable amounts of memory.
MSG_SIZE_OVERHEAD: Final = 128

STALLED_READER_COLLECTED: Final = (
    "WebSocketReader was garbage collected while stalled; "
    "callers of set_parser() must hold a strong reference"
)


@mypyc_attr(allow_interpreted_subclasses=True)
class WebSocketDataQueue(_InterpretedReadMixin):
    """WebSocketDataQueue resumes and pauses an underlying stream.

    It is a destination for WebSocket data.
    """

    def __init__(
        self, protocol: BaseProtocol, limit: int, *, loop: asyncio.AbstractEventLoop
    ) -> None:
        self._size: i64 = 0
        self._protocol = protocol
        self._limit: i64 = limit * 2
        self._loop = loop
        self._eof = False
        self._waiter: asyncio.Future[None] | None = None
        self._exception: type[BaseException] | BaseException | None = None
        self._buffer: deque[WSMessage] = deque()
        self._get_buffer = self._buffer.popleft
        self._put_buffer = self._buffer.append
        self._stalled_reader: "weakref.ref[WebSocketReader] | None" = None

    def is_eof(self) -> bool:
        return self._eof

    def exception(self) -> type[BaseException] | BaseException | None:
        return self._exception

    def set_exception(
        self,
        exc: type[BaseException] | BaseException,
        exc_cause: builtins.BaseException = _EXC_SENTINEL,
    ) -> None:
        self._eof = True
        self._exception = exc
        if (waiter := self._waiter) is not None:
            self._waiter = None
            set_exception(waiter, exc, exc_cause)

    def _release_waiter(self) -> None:
        if (waiter := self._waiter) is None:
            return
        self._waiter = None
        if not waiter.done():
            waiter.set_result(None)

    def feed_eof(self) -> None:
        self._eof = True
        self._release_waiter()
        self._exception = None  # Break cyclic references

    def feed_data(self, data: "WSMessage") -> None:
        # Unbox into the typed local before adding, so mypyc unboxes once
        # and keeps the sum in C instead of a tagged-int add.
        size: i64 = data.size
        self._size += size + MSG_SIZE_OVERHEAD
        self._put_buffer(data)
        self._release_waiter()
        if self._size > self._limit and not self._protocol._reading_paused:
            self._protocol.pause_reading()

    def _read_from_buffer(self) -> WSMessage:
        if self._buffer:
            data = self._get_buffer()
            size: i64 = data.size
            self._size -= size + MSG_SIZE_OVERHEAD
            if self._stalled_reader is not None and self._size <= self._limit // 2:
                # Resume parsing once the queue drains to the low-water mark.
                # Each resume re-slices the parser's unparsed tail, so waiting
                # for headroom makes a drain cost one copy per batch of
                # messages instead of one per message.
                if (reader := self._stalled_reader()) is not None:
                    reader.feed_data(b"")
                else:
                    # The stash died with the reader. Deliver what was already
                    # queued, then surface the contract violation on the next
                    # read instead of hanging. Log as well, since a caller that
                    # stops reading early never sees the deferred exception. A
                    # real failure that was already recorded stays the reported
                    # cause.
                    self._stalled_reader = None
                    ws_logger.warning(STALLED_READER_COLLECTED)
                    if self._exception is None:
                        self.set_exception(RuntimeError(STALLED_READER_COLLECTED))
            # Resuming the transport while a stash remains would admit
            # another socket read into the tail for every couple of messages
            # drained, moving the memory bound from the queue into the tail.
            if (
                self._stalled_reader is None
                and self._size < self._limit
                and self._protocol._reading_paused
            ):
                self._protocol.resume_reading()
            return data
        if self._exception is not None:
            raise self._exception
        raise EofStream


@mypyc_attr(allow_interpreted_subclasses=True)
class WebSocketReader(_WeakrefBase):
    def __init__(
        self,
        queue: WebSocketDataQueue,
        max_msg_size: int,
        compress: bool,
        decode_text: bool,
    ) -> None:
        self.queue = queue
        self._max_msg_size: i64 = max_msg_size
        self._decode_text = decode_text
        # Parked on the queue while parsing is stalled; created once so
        # stalling does not allocate.
        self._weak_self = weakref.ref(self)
        # mypyc's generated dealloc never calls PyObject_ClearWeakRefs
        # (https://github.com/mypyc/mypyc/issues/1102), so a refcount death
        # with live weakrefs leaves them dangling and the next deref
        # crashes.  The self reference forces collection through the cycle
        # collector, which clears weakrefs before deallocation.  This is
        # NOT version-gated: crashes were observed on 3.11 (macOS), 3.12
        # (Windows) and 3.14 (Windows), while the same 3.14 cleared refs on
        # Linux -- interpreter forgiveness is platform/patch dependent and
        # cannot be relied on anywhere.  Cost: the reader and its buffers
        # are reclaimed by full GC passes, not refcounting.  Never break
        # this cycle manually; remove when the mypyc issue is resolved.
        self._gc_cycle = self

        self._exc: Exception | None = None
        self._partial = bytearray()
        self._state: i64 = READ_HEADER

        self._opcode: i64 = OP_CODE_NOT_SET
        self._frame_fin = False
        self._frame_opcode: i64 = OP_CODE_NOT_SET
        self._payload_fragments: list[bytes] = []
        # Limit number of fragments, so a large number of tiny fragments
        # doesn't exceed reasonable memory usage.
        self._max_fragments: i64 = max(1024, max_msg_size // 256) if max_msg_size else 0
        self._frame_payload_len: i64 = 0

        self._tail: bytes = b""
        self._has_mask = False
        self._frame_mask: bytes | None = None
        self._payload_bytes_to_read: i64 = 0
        self._payload_len_flag: i64 = 0
        self._compressed: i64 = COMPRESSED_NOT_SET
        self._decompressobj: ZLibDecompressor | None = None
        self._compress = compress

    def feed_eof(self) -> None:
        self.queue.feed_eof()

    # data can be bytearray on Windows because proactor event loop uses bytearray
    # and asyncio types this to Union[bytes, bytearray, memoryview] so we need
    # coerce data to bytes if it is not
    def feed_data(self, data: bytes | bytearray | memoryview) -> tuple[bool, bytes]:
        if type(data) is not bytes:
            data = bytes(data)

        if self._exc is not None:
            return True, data

        try:
            self._feed_data(data)
        except Exception as exc:
            self._exc = exc
            set_exception(self.queue, exc)
            return EMPTY_FRAME_ERROR

        return EMPTY_FRAME

    def _handle_frame(
        self,
        fin: bool,
        opcode: i64,
        payload: bytes | bytearray,
        compressed: i64,
    ) -> None:
        msg: WSMessage
        if opcode in (OP_CODE_TEXT, OP_CODE_BINARY, OP_CODE_CONTINUATION):
            # Validate continuation frames before processing
            if opcode == OP_CODE_CONTINUATION and self._opcode == OP_CODE_NOT_SET:
                raise WebSocketError(
                    WSCloseCode.PROTOCOL_ERROR,
                    "Continuation frame for non started message",
                )

            # load text/binary
            if not fin:
                # got partial frame payload
                if opcode != OP_CODE_CONTINUATION:
                    self._opcode = opcode
                self._partial += payload
                return

            has_partial = bool(self._partial)
            if opcode == OP_CODE_CONTINUATION:
                opcode = self._opcode
                self._opcode = OP_CODE_NOT_SET
            # previous frame was non finished
            # we should get continuation opcode
            elif has_partial:
                raise WebSocketError(
                    WSCloseCode.PROTOCOL_ERROR,
                    "The opcode in non-fin frame is expected "
                    f"to be zero, got {opcode!r}",
                )

            assembled_payload: bytes | bytearray
            if has_partial:
                assembled_payload = self._partial + payload
                self._partial.clear()
            else:
                assembled_payload = payload

            # Decompress process must to be done after all packets
            # received.
            if compressed != 0:
                if not self._decompressobj:
                    self._decompressobj = ZLibDecompressor(suppress_deflate_header=True)
                # XXX: It's possible that the zlib backend (isal is known to
                # do this, maybe others too?) will return max_length bytes,
                # but internally buffer more data such that the payload is
                # >max_length, so we return one extra byte and if we're able
                # to do that, then the message is too big.
                try:
                    payload_merged = self._decompressobj.decompress_sync(
                        assembled_payload + WS_DEFLATE_TRAILING,
                        (
                            self._max_msg_size + 1
                            if self._max_msg_size != 0
                            else self._max_msg_size
                        ),
                    )
                except TooManyMembersError as exc:
                    raise WebSocketError(
                        WSCloseCode.MESSAGE_TOO_BIG,
                        "Compressed message has too many deflate members",
                    ) from exc
                if self._max_msg_size != 0 and len(payload_merged) > self._max_msg_size:
                    raise WebSocketError(
                        WSCloseCode.MESSAGE_TOO_BIG,
                        f"Decompressed message exceeds size limit {self._max_msg_size}",
                    )
            elif type(assembled_payload) is bytes:
                payload_merged = assembled_payload
            else:
                payload_merged = bytes(assembled_payload)

            size = len(payload_merged)
            if opcode == OP_CODE_TEXT:
                if self._decode_text:
                    try:
                        text = payload_merged.decode("utf-8")
                    except UnicodeDecodeError as exc:
                        raise WebSocketError(
                            WSCloseCode.INVALID_TEXT, "Invalid UTF-8 text message"
                        ) from exc

                    # XXX: The Text and Binary messages here can be a performance
                    # bottleneck, so we use tuple.__new__ to improve performance.
                    # This is not type safe, but many tests should fail in
                    # test_client_ws_functional.py if this is wrong.
                    msg = TUPLE_NEW(WSMessageText, (text, size, "", WS_MSG_TYPE_TEXT))
                else:
                    # Return raw bytes for TEXT messages when decode_text=False
                    msg = TUPLE_NEW(
                        WSMessageTextBytes, (payload_merged, size, "", WS_MSG_TYPE_TEXT)
                    )
            else:
                msg = TUPLE_NEW(
                    WSMessageBinary, (payload_merged, size, "", WS_MSG_TYPE_BINARY)
                )

            self.queue.feed_data(msg)
        elif opcode == OP_CODE_CLOSE:
            payload_len = len(payload)
            if payload_len >= 2:
                close_code = UNPACK_CLOSE_CODE(payload[:2])[0]
                # https://datatracker.ietf.org/doc/html/rfc6455#section-7.4.2
                if close_code > 4999 or (
                    close_code < 3000 and close_code not in ALLOWED_CLOSE_CODES
                ):
                    raise WebSocketError(
                        WSCloseCode.PROTOCOL_ERROR,
                        f"Invalid close code: {close_code}",
                    )
                try:
                    close_message = payload[2:].decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise WebSocketError(
                        WSCloseCode.INVALID_TEXT, "Invalid UTF-8 text message"
                    ) from exc
                msg = WSMessageClose(
                    data=close_code, size=payload_len, extra=close_message
                )
            elif payload:
                raise WebSocketError(
                    WSCloseCode.PROTOCOL_ERROR,
                    f"Invalid close frame: {fin} {opcode} {payload!r}",
                )
            else:
                msg = WSMessageClose(data=0, size=payload_len, extra="")

            self.queue.feed_data(msg)
        elif opcode == OP_CODE_PING:
            self.queue.feed_data(
                WSMessagePing(data=bytes(payload), size=len(payload), extra="")
            )
        elif opcode == OP_CODE_PONG:
            self.queue.feed_data(
                WSMessagePong(data=bytes(payload), size=len(payload), extra="")
            )
        else:
            raise WebSocketError(
                WSCloseCode.PROTOCOL_ERROR, f"Unexpected opcode={opcode!r}"
            )

    def _feed_data(self, data: bytes) -> None:
        """Return the next frame from the socket."""
        self.queue._stalled_reader = None
        if self._tail:
            data, self._tail = self._tail + data, b""

        start_pos: i64 = 0
        data_len: i64 = len(data)

        while True:
            if start_pos < data_len and self.queue._size > self.queue._limit:
                # Over the high-water mark with unparsed bytes left: stash the
                # remainder and stall. Gating on unparsed bytes keeps a read
                # that ended on a frame boundary from arming an empty stall,
                # which would hold the transport paused with nothing to drain.
                self.queue._stalled_reader = self._weak_self
                break

            # read header
            if self._state == READ_HEADER:
                if data_len - start_pos < 2:
                    break
                first_byte: i64 = data[start_pos]
                second_byte: i64 = data[start_pos + 1]
                start_pos += 2

                fin = (first_byte >> 7) & 1
                rsv1 = (first_byte >> 6) & 1
                rsv2 = (first_byte >> 5) & 1
                rsv3 = (first_byte >> 4) & 1
                opcode = first_byte & 0xF

                # frame-fin = %x0 ; more frames of this message follow
                #           / %x1 ; final frame of this message
                # frame-rsv1 = %x0 ;
                #    1 bit, MUST be 0 unless negotiated otherwise
                # frame-rsv2 = %x0 ;
                #    1 bit, MUST be 0 unless negotiated otherwise
                # frame-rsv3 = %x0 ;
                #    1 bit, MUST be 0 unless negotiated otherwise
                #
                # Remove rsv1 from this test for deflate development
                if rsv2 != 0 or rsv3 != 0 or (rsv1 != 0 and not self._compress):
                    raise WebSocketError(
                        WSCloseCode.PROTOCOL_ERROR,
                        "Received frame with non-zero reserved bits",
                    )

                if opcode not in (
                    OP_CODE_CONTINUATION,
                    OP_CODE_TEXT,
                    OP_CODE_BINARY,
                    OP_CODE_CLOSE,
                    OP_CODE_PING,
                    OP_CODE_PONG,
                ):
                    raise WebSocketError(
                        WSCloseCode.PROTOCOL_ERROR,
                        f"Unexpected opcode={opcode!r}",
                    )

                if opcode > 0x7 and fin == 0:
                    raise WebSocketError(
                        WSCloseCode.PROTOCOL_ERROR,
                        "Received fragmented control frame",
                    )

                has_mask = (second_byte >> 7) & 1
                length = second_byte & 0x7F

                # Control frames MUST have a payload
                # length of 125 bytes or less
                if opcode > 0x7 and length > 125:
                    raise WebSocketError(
                        WSCloseCode.PROTOCOL_ERROR,
                        "Control frame payload cannot be larger than 125 bytes",
                    )

                # Control frames (opcode > 0x7) may be interleaved between the
                # fragments of a data message and never carry the per-message
                # compressed bit, so they must not touch the compression state.
                # https://datatracker.ietf.org/doc/html/rfc6455#section-5.4
                # https://datatracker.ietf.org/doc/html/rfc7692#section-6.1
                if opcode > 0x7:
                    if rsv1 != 0:
                        raise WebSocketError(
                            WSCloseCode.PROTOCOL_ERROR,
                            "Received frame with non-zero reserved bits",
                        )
                else:
                    # Set compress status if last package is FIN
                    # OR set compress status if this is first fragment
                    # Raise error if not first fragment with rsv1 = 0x1
                    if self._frame_fin or self._compressed == COMPRESSED_NOT_SET:
                        self._compressed = (
                            COMPRESSED_TRUE if rsv1 != 0 else COMPRESSED_FALSE
                        )
                    elif rsv1 != 0:
                        raise WebSocketError(
                            WSCloseCode.PROTOCOL_ERROR,
                            "Received frame with non-zero reserved bits",
                        )
                    self._frame_fin = bool(fin)

                self._frame_opcode = opcode
                self._has_mask = bool(has_mask)
                self._payload_len_flag = length
                self._state = READ_PAYLOAD_LENGTH

            # read payload length
            if self._state == READ_PAYLOAD_LENGTH:
                len_flag: i64 = self._payload_len_flag
                if len_flag == 126:
                    if data_len - start_pos < 2:
                        break
                    first_byte = data[start_pos]
                    second_byte = data[start_pos + 1]
                    start_pos += 2
                    self._payload_bytes_to_read = first_byte << 8 | second_byte
                elif len_flag > 126:
                    if data_len - start_pos < 8:
                        break
                    # The declared length is an unsigned 64-bit integer that
                    # does not necessarily fit _payload_bytes_to_read.
                    frame_len = UNPACK_LEN3(data, start_pos)[0]
                    if frame_len > MAX_PAYLOAD_LEN:
                        raise WebSocketError(
                            WSCloseCode.MESSAGE_TOO_BIG,
                            f"Message size {int(frame_len) + len(self._partial)} "
                            f"exceeds limit {self._max_msg_size if self._max_msg_size != 0 else MAX_PAYLOAD_LEN}",
                        )
                    self._payload_bytes_to_read = frame_len
                    start_pos += 8
                else:
                    self._payload_bytes_to_read = len_flag

                # Reject oversized data frames before buffering any payload
                # bytes. Control frames are capped at 125 bytes (checked in
                # READ_HEADER) so only text/binary/continuation need this.
                if self._max_msg_size != 0 and self._frame_opcode in (
                    OP_CODE_TEXT,
                    OP_CODE_BINARY,
                    OP_CODE_CONTINUATION,
                ):
                    partial_len: i64 = len(self._partial)
                    # payload_bytes_to_read is an i64 C value, use
                    # subtraction here to avoid an integer overflow.
                    if self._payload_bytes_to_read >= self._max_msg_size - partial_len:
                        # i64 is sticky in mixed arithmetic: int(i64) + i64
                        # would coerce back to i64 and wrap for a declared
                        # length near 2**63, so box both operands first.
                        raise WebSocketError(
                            WSCloseCode.MESSAGE_TOO_BIG,
                            f"Message size {int(self._payload_bytes_to_read) + int(partial_len)} "
                            f"exceeds limit {self._max_msg_size}",
                        )

                self._state = READ_PAYLOAD_MASK if self._has_mask else READ_PAYLOAD

            # read payload mask
            if self._state == READ_PAYLOAD_MASK:
                if data_len - start_pos < 4:
                    break
                self._frame_mask = data[start_pos : start_pos + 4]
                start_pos += 4
                self._state = READ_PAYLOAD

            if self._state == READ_PAYLOAD:
                chunk_len: i64 = data_len - start_pos
                if self._payload_bytes_to_read >= chunk_len:
                    f_end_pos = data_len
                    self._payload_bytes_to_read -= chunk_len
                else:
                    f_end_pos = start_pos + self._payload_bytes_to_read
                    self._payload_bytes_to_read = 0

                had_fragments = self._frame_payload_len
                self._frame_payload_len += f_end_pos - start_pos
                f_start_pos = start_pos
                start_pos = f_end_pos

                if self._payload_bytes_to_read != 0:
                    # If we don't have a complete frame, we need to save the
                    # data for the next call to feed_data.
                    self._payload_fragments.append(data[f_start_pos:f_end_pos])
                    if (
                        self._max_fragments != 0
                        and len(self._payload_fragments) > self._max_fragments
                        and not self.queue._protocol._reading_paused
                    ):
                        self.queue._protocol.pause_reading()
                    break

                payload: bytes | bytearray
                if had_fragments != 0:
                    # We have to join the payload fragments get the payload
                    self._payload_fragments.append(data[f_start_pos:f_end_pos])
                    if self._has_mask:
                        assert self._frame_mask is not None
                        payload_bytearray = bytearray(b"".join(self._payload_fragments))
                        websocket_mask(self._frame_mask, payload_bytearray)
                        payload = payload_bytearray
                    else:
                        payload = b"".join(self._payload_fragments)
                    self._payload_fragments.clear()
                elif self._has_mask:
                    assert self._frame_mask is not None
                    payload_bytearray = bytearray(data[f_start_pos:f_end_pos])
                    websocket_mask(self._frame_mask, payload_bytearray)
                    payload = payload_bytearray
                else:
                    payload = data[f_start_pos:f_end_pos]

                self._handle_frame(
                    self._frame_fin, self._frame_opcode, payload, self._compressed
                )
                self._frame_payload_len = 0
                self._state = READ_HEADER

        self._tail = data[start_pos:] if start_pos < data_len else b""
