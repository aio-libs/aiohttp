import cython


cdef unsigned int READ_HEADER
cdef unsigned int READ_PAYLOAD_LENGTH
cdef unsigned int READ_PAYLOAD_MASK
cdef unsigned int READ_PAYLOAD

cdef object UNPACK_LEN2
cdef object UNPACK_LEN3

cdef object WSMsgType

cdef object WSMessageText
cdef object WSMessageBinary

cdef class WebSocketReader:

    cdef object queue
    cdef unsigned int _max_msg_size

    cdef object _exc
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

    cpdef feed_data(self, bytes data)

    @cython.locals(
        is_continuation=bint,
        fin=bint,
        has_partial=bint,
        payload_merged=bytes
    )
    cpdef _feed_data(self, bytes data)

    @cython.locals(
        start_pos="unsigned int",
        buf_len="unsigned int",
        length="unsigned int",
        chunk_size="unsigned int",
        buf_length="unsigned int",
        data=bytes,
        payload=bytearray,
        first_byte=char,
        second_byte=char
    )
    cpdef parse_frame(self, bytes buf)
