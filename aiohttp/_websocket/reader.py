"""Reader for WebSocket protocol versions 13 and 8."""

from enum import IntEnum
from typing import Final, List, Optional, Set, Tuple

from ..compression_utils import ZLibDecompressor
from ..helpers import set_exception
from ..streams import DataQueue
from .helpers import UNPACK_CLOSE_CODE, UNPACK_LEN2, UNPACK_LEN3, websocket_mask
from .models import (
    WS_DEFLATE_TRAILING,
    WebSocketError,
    WSCloseCode,
    WSMessage,
    WSMsgType,
)

MESSAGE_TYPES_WITH_CONTENT: Final = frozenset(
    {
        WSMsgType.BINARY,
        WSMsgType.TEXT,
        WSMsgType.CONTINUATION,
    }
)

ALLOWED_CLOSE_CODES: Final[Set[int]] = {int(i) for i in WSCloseCode}


class WSParserState(IntEnum):
    READ_HEADER = 1
    READ_PAYLOAD_LENGTH = 2
    READ_PAYLOAD_MASK = 3
    READ_PAYLOAD = 4


class WebSocketReader:
    def __init__(
        self, queue: DataQueue[WSMessage], max_msg_size: int, compress: bool = True
    ) -> None:
        self.queue = queue
        self._max_msg_size = max_msg_size

        self._exc: Optional[BaseException] = None
        self._partial = bytearray()
        self._state = WSParserState.READ_HEADER

        self._opcode: Optional[int] = None
        self._frame_fin = False
        self._frame_opcode: Optional[int] = None
        self._frame_payload = bytearray()

        self._tail: bytes = b""
        self._has_mask = False
        self._frame_mask: Optional[bytes] = None
        self._payload_length = 0
        self._payload_length_flag = 0
        self._compressed: Optional[bool] = None
        self._decompressobj: Optional[ZLibDecompressor] = None
        self._compress = compress

    def feed_eof(self) -> None:
        self.queue.feed_eof()

    def feed_data(self, data: bytes) -> Tuple[bool, bytes]:
        if self._exc:
            return True, data

        try:
            self._feed_data(data)
        except Exception as exc:
            self._exc = exc
            set_exception(self.queue, exc)
            return True, b""

        return False, b""

    def _feed_data(self, data: bytes) -> None:
        for fin, opcode, payload, compressed in self.parse_frame(data):
            if opcode in MESSAGE_TYPES_WITH_CONTENT:
                # load text/binary
                is_continuation = opcode == WSMsgType.CONTINUATION
                if not fin:
                    # got partial frame payload
                    if not is_continuation:
                        self._opcode = opcode
                    self._partial += payload
                    if self._max_msg_size and len(self._partial) >= self._max_msg_size:
                        raise WebSocketError(
                            WSCloseCode.MESSAGE_TOO_BIG,
                            "Message size {} exceeds limit {}".format(
                                len(self._partial), self._max_msg_size
                            ),
                        )
                    continue

                has_partial = bool(self._partial)
                if is_continuation:
                    if self._opcode is None:
                        raise WebSocketError(
                            WSCloseCode.PROTOCOL_ERROR,
                            "Continuation frame for non started message",
                        )
                    opcode = self._opcode
                    self._opcode = None
                # previous frame was non finished
                # we should get continuation opcode
                elif has_partial:
                    raise WebSocketError(
                        WSCloseCode.PROTOCOL_ERROR,
                        "The opcode in non-fin frame is expected "
                        "to be zero, got {!r}".format(opcode),
                    )

                if has_partial:
                    assembled_payload = self._partial + payload
                    self._partial.clear()
                else:
                    assembled_payload = payload

                if self._max_msg_size and len(assembled_payload) >= self._max_msg_size:
                    raise WebSocketError(
                        WSCloseCode.MESSAGE_TOO_BIG,
                        "Message size {} exceeds limit {}".format(
                            len(assembled_payload), self._max_msg_size
                        ),
                    )

                # Decompress process must to be done after all packets
                # received.
                if compressed:
                    if not self._decompressobj:
                        self._decompressobj = ZLibDecompressor(
                            suppress_deflate_header=True
                        )
                    payload_merged = self._decompressobj.decompress_sync(
                        assembled_payload + WS_DEFLATE_TRAILING, self._max_msg_size
                    )
                    if self._decompressobj.unconsumed_tail:
                        left = len(self._decompressobj.unconsumed_tail)
                        raise WebSocketError(
                            WSCloseCode.MESSAGE_TOO_BIG,
                            "Decompressed message size {} exceeds limit {}".format(
                                self._max_msg_size + left, self._max_msg_size
                            ),
                        )
                else:
                    payload_merged = bytes(assembled_payload)

                if opcode == WSMsgType.TEXT:
                    try:
                        text = payload_merged.decode("utf-8")
                    except UnicodeDecodeError as exc:
                        raise WebSocketError(
                            WSCloseCode.INVALID_TEXT, "Invalid UTF-8 text message"
                        ) from exc

                    # tuple.__new__ is used to avoid the overhead of the lambda
                    msg = tuple.__new__(WSMessage, (WSMsgType.TEXT, text, ""))
                    self.queue.feed_data(msg, len(text))
                    continue

                # tuple.__new__ is used to avoid the overhead of the lambda
                msg = tuple.__new__(WSMessage, (WSMsgType.BINARY, payload_merged, ""))
                self.queue.feed_data(msg, len(payload_merged))
            elif opcode == WSMsgType.CLOSE:
                if len(payload) >= 2:
                    close_code = UNPACK_CLOSE_CODE(payload[:2])[0]
                    if close_code < 3000 and close_code not in ALLOWED_CLOSE_CODES:
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
                    msg = tuple.__new__(
                        WSMessage, (WSMsgType.CLOSE, close_code, close_message)
                    )
                elif payload:
                    raise WebSocketError(
                        WSCloseCode.PROTOCOL_ERROR,
                        f"Invalid close frame: {fin} {opcode} {payload!r}",
                    )
                else:
                    msg = tuple.__new__(WSMessage, (WSMsgType.CLOSE, 0, ""))

                self.queue.feed_data(msg, 0)

            elif opcode == WSMsgType.PING:
                msg = tuple.__new__(WSMessage, (WSMsgType.PING, payload, ""))
                self.queue.feed_data(msg, len(payload))

            elif opcode == WSMsgType.PONG:
                msg = tuple.__new__(WSMessage, (WSMsgType.PONG, payload, ""))
                self.queue.feed_data(msg, len(payload))

            else:
                raise WebSocketError(
                    WSCloseCode.PROTOCOL_ERROR, f"Unexpected opcode={opcode!r}"
                )

    def parse_frame(
        self, buf: bytes
    ) -> List[Tuple[bool, Optional[int], bytearray, Optional[bool]]]:
        """Return the next frame from the socket."""
        frames: List[Tuple[bool, Optional[int], bytearray, Optional[bool]]] = []
        if self._tail:
            buf, self._tail = self._tail + buf, b""

        start_pos: int = 0
        buf_length = len(buf)

        while True:
            # read header
            if self._state is WSParserState.READ_HEADER:
                if buf_length - start_pos < 2:
                    break
                data = buf[start_pos : start_pos + 2]
                start_pos += 2
                first_byte, second_byte = data

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
                if rsv2 or rsv3 or (rsv1 and not self._compress):
                    raise WebSocketError(
                        WSCloseCode.PROTOCOL_ERROR,
                        "Received frame with non-zero reserved bits",
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

                # Set compress status if last package is FIN
                # OR set compress status if this is first fragment
                # Raise error if not first fragment with rsv1 = 0x1
                if self._frame_fin or self._compressed is None:
                    self._compressed = True if rsv1 else False
                elif rsv1:
                    raise WebSocketError(
                        WSCloseCode.PROTOCOL_ERROR,
                        "Received frame with non-zero reserved bits",
                    )

                self._frame_fin = bool(fin)
                self._frame_opcode = opcode
                self._has_mask = bool(has_mask)
                self._payload_length_flag = length
                self._state = WSParserState.READ_PAYLOAD_LENGTH

            # read payload length
            if self._state is WSParserState.READ_PAYLOAD_LENGTH:
                length_flag = self._payload_length_flag
                if length_flag == 126:
                    if buf_length - start_pos < 2:
                        break
                    data = buf[start_pos : start_pos + 2]
                    start_pos += 2
                    self._payload_length = UNPACK_LEN2(data)[0]
                elif length_flag > 126:
                    if buf_length - start_pos < 8:
                        break
                    data = buf[start_pos : start_pos + 8]
                    start_pos += 8
                    self._payload_length = UNPACK_LEN3(data)[0]
                else:
                    self._payload_length = length_flag

                self._state = (
                    WSParserState.READ_PAYLOAD_MASK
                    if self._has_mask
                    else WSParserState.READ_PAYLOAD
                )

            # read payload mask
            if self._state is WSParserState.READ_PAYLOAD_MASK:
                if buf_length - start_pos < 4:
                    break
                self._frame_mask = buf[start_pos : start_pos + 4]
                start_pos += 4
                self._state = WSParserState.READ_PAYLOAD

            if self._state is WSParserState.READ_PAYLOAD:
                length = self._payload_length
                payload = self._frame_payload

                chunk_len = buf_length - start_pos
                if length >= chunk_len:
                    self._payload_length = length - chunk_len
                    payload += buf[start_pos:]
                    start_pos = buf_length
                else:
                    self._payload_length = 0
                    payload += buf[start_pos : start_pos + length]
                    start_pos = start_pos + length

                if self._payload_length != 0:
                    break

                if self._has_mask:
                    assert self._frame_mask is not None
                    websocket_mask(self._frame_mask, payload)

                frames.append(
                    (self._frame_fin, self._frame_opcode, payload, self._compressed)
                )
                self._frame_payload = bytearray()
                self._state = WSParserState.READ_HEADER

        self._tail = buf[start_pos:]

        return frames
