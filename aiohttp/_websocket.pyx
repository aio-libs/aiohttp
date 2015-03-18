from cpython cimport PyBytes_FromStringAndSize, PyBytes_AsString
from cpython.ref cimport PyObject


def _websocket_mask_cython(bytes mask, bytes data):
    cdef Py_ssize_t mask_len, data_len, i
    cdef char * in_buf
    cdef char * out_buf
    cdef char * mask_buf
    cdef bytes ret
    mask_len = len(mask)
    data_len = len(data)
    in_buf = PyBytes_AsString(data)
    mask_buf = PyBytes_AsString(mask)
    ret = PyBytes_FromStringAndSize(NULL, data_len)
    out_buf = PyBytes_AsString(ret)
    for i in range(0, data_len):
        out_buf[i] = in_buf[i] ^ mask_buf[i % 4]
    return ret
