from cpython cimport PyBytes_FromStringAndSize, PyBytes_AsString
from cpython.ref cimport PyObject

cdef extern from "Python.h":
    char* PyByteArray_AsString(object bytearray) except NULL


def _websocket_mask_cython(bytes mask, bytearray data):
    cdef Py_ssize_t mask_len, data_len, i
    cdef char * in_buf
    cdef char * out_buf
    cdef char * mask_buf
    cdef bytes ret
    mask_len = len(mask)
    data_len = len(data)
    in_buf = PyByteArray_AsString(data)
    mask_buf = PyBytes_AsString(mask)
    for i in range(0, data_len):
        in_buf[i] = in_buf[i] ^ mask_buf[i % 4]
    return data
