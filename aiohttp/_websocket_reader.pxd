
cdef unsigned int READ_HEADER
cdef unsigned int READ_PAYLOAD_LENGTH
cdef unsigned int READ_PAYLOAD_MASK
cdef unsigned int READ_PAYLOAD

cdef class WebSocketReader:

    cdef object queue
    cdef unsigned int _max_msg_size

    cdef BaseException _exc
    cdef bytearray _partial
    cdef unsigned int _state

    cdef object _opcode
    cdef bint _frame_fin
    cdef object _frame_opcode
    cdef bytearray _frame_payload

    cdef bytes _tail
    cdef bint _has_mask
    cdef bytes _frame_mask
    cdef unsigned int _payload_length
    cdef unsigned int _payload_length_flag
    cdef object _compressed
    cdef object _decompressobj
    cdef bint _compress

    @cython.locals(
        start_pos=unsigned int,
        buf_len=unsigned int,
        length=unsigned int,
        chunk_size=unsigned int,
        data=bytes,
        payload=bytearray,
        first_byte=char
        second_byte=char
    )
    cpdef parse_frame(self, bytes buf)
