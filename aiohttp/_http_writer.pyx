# cython:  freethreading_compatible = True
cimport cython
from cpython.bytes cimport PyBytes_FromStringAndSize
from cpython.exc cimport PyErr_NoMemory, PyErr_SetObject
from cpython.mem cimport PyMem_Free, PyMem_Malloc, PyMem_Realloc
from cpython.object cimport PyObject
from cpython.unicode cimport PyUnicode_Check, PyUnicode_CheckExact
from libc.stdint cimport uint8_t, uint64_t
from libc.string cimport memcpy
from multidict cimport (
    IStr_CheckExact,
    MultiDictIter_New,
    MultiDictIter_Next,
    multidict_import,
)


# Cython version should be a return type of str,
# Redoing the function signature should help eliminate
# a costly string check Otherwise A new function for the
# Multidict-CAPI should be looked into
cdef extern from "Python.h":
    str PyObject_Str(object obj)


# NOTE: Cython API is Experimental and is held subject to change
#       Depending on different circumstances.
#       Remove this comment when draft is officially over
#       or when 6.7 is released with the official names.
#       This may or may not be what the other authors had in mind.
#       My todos are held subject to removal when Draft is transformed
#       into a real pull request.


# Run first thing so that Capsule imports...
multidict_import()

DEF BUF_SIZE = 16 * 1024  # 16KiB


# ----------------- writer ---------------------------

cdef struct Writer:
    char *buf
    Py_ssize_t size
    Py_ssize_t pos
    bint heap_allocated


cdef inline void _init_writer(Writer* writer, char *buf):
    writer.buf = buf
    writer.size = BUF_SIZE
    writer.pos = 0
    writer.heap_allocated = 0




cdef inline void _release_writer(Writer* writer):
    if writer.heap_allocated:
        PyMem_Free(writer.buf)


cdef inline int _write_byte(Writer* writer, uint8_t ch) except -1:
    cdef char * buf
    cdef Py_ssize_t size

    if writer.pos == writer.size:
        # reallocate
        size = writer.size + BUF_SIZE
        if not writer.heap_allocated:
            buf = <char*>PyMem_Malloc(size)
            if buf == NULL:
                PyErr_NoMemory()
                return -1
            memcpy(buf, writer.buf, writer.size)
        else:
            buf = <char*>PyMem_Realloc(writer.buf, size)
            if buf == NULL:
                PyErr_NoMemory()
                return -1
        writer.buf = buf
        writer.size = size
        writer.heap_allocated = 1
    writer.buf[writer.pos] = <char>ch
    writer.pos += 1
    return 0


cdef inline int _write_utf8(Writer* writer, Py_UCS4 symbol) except -1:
    cdef uint64_t utf = <uint64_t> symbol

    if utf < 0x80:
        return _write_byte(writer, <uint8_t>utf)
    elif utf < 0x800:
        if _write_byte(writer, <uint8_t>(0xc0 | (utf >> 6))) < 0:
            return -1
        return _write_byte(writer,  <uint8_t>(0x80 | (utf & 0x3f)))
    elif 0xD800 <= utf <= 0xDFFF:
        # surogate pair, ignored
        return 0
    elif utf < 0x10000:
        if _write_byte(writer, <uint8_t>(0xe0 | (utf >> 12))) < 0:
            return -1
        if _write_byte(writer, <uint8_t>(0x80 | ((utf >> 6) & 0x3f))) < 0:
            return -1
        return _write_byte(writer, <uint8_t>(0x80 | (utf & 0x3f)))
    elif utf > 0x10FFFF:
        # symbol is too large
        return 0
    else:
        if _write_byte(writer,  <uint8_t>(0xf0 | (utf >> 18))) < 0:
            return -1
        if _write_byte(writer,
                       <uint8_t>(0x80 | ((utf >> 12) & 0x3f))) < 0:
           return -1
        if _write_byte(writer,
                       <uint8_t>(0x80 | ((utf >> 6) & 0x3f))) < 0:
            return -1
        return _write_byte(writer, <uint8_t>(0x80 | (utf & 0x3f)))


cdef inline int _write_str(Writer* writer, str s) except -1:
    cdef Py_UCS4 ch
    if not PyUnicode_Check(s):
        PyErr_SetObject(ValueError, "Invalid status-line: {!r}".format(s))
        return -1
    for ch in s:
        if _write_utf8(writer, ch) < 0:
            return -1
    return 0

cdef inline int _write_str_raise_on_nlcr(Writer* writer, object s) except -1:
    cdef Py_UCS4 ch
    cdef str out_str

    if PyUnicode_CheckExact(s):
        out_str = <str>s
    elif IStr_CheckExact(s):
        out_str = PyObject_Str(s)
    elif not PyUnicode_Check(s):
        PyErr_SetObject(TypeError, "Cannot serialize non-str key {!r}".format(s))
        return -1
    else:
        out_str = str(s)

    for ch in out_str:
        if ch == 0x0D or ch == 0x0A:
            PyErr_SetObject(ValueError,
                "Newline or carriage return detected in headers. "
                "Potential header injection attack."
            )
            return -1

        if _write_utf8(writer, ch) < 0:
            return -1
    return 0

# --------------- _serialize_headers ----------------------

def _serialize_headers(str status_line, headers):
    cdef Writer writer
    cdef PyObject* key
    cdef PyObject* val
    cdef object multidict_iter
    cdef char buf[BUF_SIZE]

    _init_writer(&writer, buf)

    try:
        multidict_iter = MultiDictIter_New(headers)

        if _write_str(&writer, status_line) < 0:
            raise
        if _write_byte(&writer, b'\r') < 0:
            raise
        if _write_byte(&writer, b'\n') < 0:
            raise

        while MultiDictIter_Next(multidict_iter, &key, &val):

            if _write_str_raise_on_nlcr(&writer, <object>key) < 0:
                raise
            if _write_byte(&writer, b':') < 0:
                raise
            if _write_byte(&writer, b' ') < 0:
                raise
            if _write_str_raise_on_nlcr(&writer, <object>val) < 0:
                raise
            if _write_byte(&writer, b'\r') < 0:
                raise
            if _write_byte(&writer, b'\n') < 0:
                raise

        if _write_byte(&writer, b'\r') < 0:
            raise
        if _write_byte(&writer, b'\n') < 0:
            raise

        return PyBytes_FromStringAndSize(writer.buf, writer.pos)
    finally:
        _release_writer(&writer)
