import cython


cdef class WebSocketReader:

    cdef public object queue
    cdef int _max_msg_size
    cdef object _exc
    cdef bytearray _partial
    cdef object _state
    cdef object _opcode
    cdef object _frame_fin
    cdef object _frame_opcode
    cdef bytearray _frame_payload
    cdef bytes _tail
    cdef bint _has_mask
    cdef bytes _frame_mask
    cdef int _payload_length
    cdef int _payload_length_flag
    cdef object _compressed
    cdef object _decompressobj
    cdef bint _compress

    @cython.locals(
        start_pos="unsigned int",
        buf_length="unsigned char",
        first_byte="unsigned char",
        second_byte="unsigned char",
        fin="unsigned char",
        rsv1="unsigned char",
        rsv2="unsigned char",
        rsv3="unsigned char",
        opcode="unsigned char",
        has_mask=bint,
        length="unsigned int",
        chunk_len="unsigned int"
    )
    cpdef parse_frame(self, bytes buf)
