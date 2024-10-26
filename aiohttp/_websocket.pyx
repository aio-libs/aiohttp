from cpython cimport PyBytes_AsString


#from cpython cimport PyByteArray_AsString # cython still not exports that
cdef extern from "Python.h":
    char* PyByteArray_AsString(bytearray ba) except NULL

from libc.stdint cimport uint32_t, uint64_t, uintmax_t

from .websocket_models import (
    UNPACK_LEN2,
    UNPACK_LEN3,
    WebSocketError,
    WSCloseCode,
    WSHandshakeError,
    WSParserState,
)


cpdef _websocket_mask_cython(object mask, object data):
    """Note, this function mutates its `data` argument
    """
    cdef:
        Py_ssize_t data_len, i
        # bit operations on signed integers are implementation-specific
        unsigned char * in_buf
        const unsigned char * mask_buf
        uint32_t uint32_msk
        uint64_t uint64_msk

    assert len(mask) == 4

    if not isinstance(mask, bytes):
        mask = bytes(mask)

    if isinstance(data, bytearray):
        data = <bytearray>data
    else:
        data = bytearray(data)

    data_len = len(data)
    in_buf = <unsigned char*>PyByteArray_AsString(data)
    mask_buf = <const unsigned char*>PyBytes_AsString(mask)
    uint32_msk = (<uint32_t*>mask_buf)[0]

    # TODO: align in_data ptr to achieve even faster speeds
    # does it need in python ?! malloc() always aligns to sizeof(long) bytes

    if sizeof(size_t) >= 8:
        uint64_msk = uint32_msk
        uint64_msk = (uint64_msk << 32) | uint32_msk

        while data_len >= 8:
            (<uint64_t*>in_buf)[0] ^= uint64_msk
            in_buf += 8
            data_len -= 8


    while data_len >= 4:
        (<uint32_t*>in_buf)[0] ^= uint32_msk
        in_buf += 4
        data_len -= 4

    for i in range(0, data_len):
        in_buf[i] ^= mask_buf[i]




cdef unsigned int WSParserState_READ_HEADER = WSParserState.READ_HEADER.value
cdef unsigned int WSParserState_READ_PAYLOAD_LENGTH = WSParserState.READ_PAYLOAD_LENGTH.value
cdef unsigned int WSParserState_READ_PAYLOAD_MASK = WSParserState.READ_PAYLOAD_MASK.value
cdef unsigned int WSParserState_READ_PAYLOAD = WSParserState.READ_PAYLOAD.value

cdef class WebSocketReaderBaseCython:

    cdef bytes _tail
    cdef bytes _frame_mask
    cdef bint _compress
    cdef object _compressed
    cdef object _frame_fin
    cdef object _frame_opcode
    cdef bint _has_mask
    cdef unsigned int _payload_length
    cdef unsigned int _payload_length_flag
    cdef unsigned int _state
    cdef bytearray _frame_payload

    def __init__(self):
        self._frame_payload = bytearray()
        self._state = WSParserState_READ_HEADER

    def parse_frame(
        self, buf: bytes
    ) -> List[Tuple[bool, Optional[int], bytearray, Optional[bool]]]:
        """Return the next frame from the socket."""
        frames: List[Tuple[bool, Optional[int], bytearray, Optional[bool]]] = []
        if self._tail:
            buf, self._tail = self._tail + buf, b""

        cdef unsigned int start_pos = 0
        cdef unsigned int buf_length = len(buf)
        cdef unsigned int length
        cdef unsigned int chunk_len
        cdef bytes data
        cdef bytearray payload
        cdef char first_byte
        cdef char second_byte

        while True:
            # read header
            if self._state == WSParserState_READ_HEADER:
                if buf_length - start_pos < 2:
                    break
                data = buf[start_pos : start_pos + 2]
                start_pos += 2
                first_byte = data[0]
                second_byte = data[1]

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
                self._state = WSParserState_READ_PAYLOAD_LENGTH

            # read payload length
            if self._state == WSParserState_READ_PAYLOAD_LENGTH:
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
                    WSParserState_READ_PAYLOAD_MASK
                    if self._has_mask
                    else WSParserState_READ_PAYLOAD
                )

            # read payload mask
            if self._state == WSParserState_READ_PAYLOAD_MASK:
                if buf_length - start_pos < 4:
                    break
                self._frame_mask = buf[start_pos : start_pos + 4]
                start_pos += 4
                self._state = WSParserState_READ_PAYLOAD

            if self._state == WSParserState_READ_PAYLOAD:
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
                    _websocket_mask_cython(self._frame_mask, payload)

                frames.append(
                    (self._frame_fin, self._frame_opcode, payload, self._compressed)
                )
                self._frame_payload = bytearray()
                self._state = WSParserState_READ_HEADER

        self._tail = buf[start_pos:]

        return frames
