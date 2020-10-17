#cython: language_level=3
#
# Based on https://github.com/MagicStack/httptools
#
from __future__ import absolute_import, print_function

from cpython cimport (
    Py_buffer,
    PyBUF_SIMPLE,
    PyBuffer_Release,
    PyBytes_AsString,
    PyBytes_AsStringAndSize,
    PyObject_GetBuffer,
)
from cpython.mem cimport PyMem_Free, PyMem_Malloc
from libc.limits cimport ULLONG_MAX
from libc.string cimport memcpy

from multidict import CIMultiDict as _CIMultiDict
from multidict import CIMultiDictProxy as _CIMultiDictProxy
from yarl import URL as _URL

from aiohttp import hdrs

from .http_exceptions import (
    BadHttpMessage,
    BadStatusLine,
    ContentLengthError,
    InvalidHeader,
    InvalidURLError,
    LineTooLong,
    PayloadEncodingError,
    TransferEncodingError,
)
from .http_parser import DeflateBuffer as _DeflateBuffer
from .http_writer import HttpVersion as _HttpVersion
from .http_writer import HttpVersion10 as _HttpVersion10
from .http_writer import HttpVersion11 as _HttpVersion11
from .streams import EMPTY_PAYLOAD as _EMPTY_PAYLOAD
from .streams import StreamReader as _StreamReader

cimport cython

from aiohttp cimport _cparser as cparser

include "_headers.pxi"

from aiohttp cimport _find_header

DEF DEFAULT_FREELIST_SIZE = 250

cdef extern from "Python.h":
    int PyByteArray_Resize(object, Py_ssize_t) except -1
    Py_ssize_t PyByteArray_Size(object) except -1
    char* PyByteArray_AsString(object)

__all__ = ('HttpRequestParser', 'HttpResponseParser',
           'RawRequestMessage', 'RawResponseMessage')

cdef object URL = _URL
cdef object URL_build = URL.build
cdef object CIMultiDict = _CIMultiDict
cdef object CIMultiDictProxy = _CIMultiDictProxy
cdef object HttpVersion = _HttpVersion
cdef object HttpVersion10 = _HttpVersion10
cdef object HttpVersion11 = _HttpVersion11
cdef object SEC_WEBSOCKET_KEY1 = hdrs.SEC_WEBSOCKET_KEY1
cdef object CONTENT_ENCODING = hdrs.CONTENT_ENCODING
cdef object EMPTY_PAYLOAD = _EMPTY_PAYLOAD
cdef object StreamReader = _StreamReader
cdef object DeflateBuffer = _DeflateBuffer


cdef inline object extend(object buf, const char* at, size_t length):
    cdef Py_ssize_t s
    cdef char* ptr
    s = PyByteArray_Size(buf)
    PyByteArray_Resize(buf, s + length)
    ptr = PyByteArray_AsString(buf)
    memcpy(ptr + s, at, length)


DEF METHODS_COUNT = 34;

cdef list _http_method = []

for i in range(METHODS_COUNT):
    _http_method.append(
        cparser.http_method_str(<cparser.http_method> i).decode('ascii'))


cdef inline str http_method_str(int i):
    if i < METHODS_COUNT:
        return <str>_http_method[i]
    else:
        return "<unknown>"

cdef inline object find_header(bytes raw_header):
    cdef Py_ssize_t size
    cdef char *buf
    cdef int idx
    PyBytes_AsStringAndSize(raw_header, &buf, &size)
    idx = _find_header.find_header(buf, size)
    if idx == -1:
        return raw_header.decode('utf-8', 'surrogateescape')
    return headers[idx]


@cython.freelist(DEFAULT_FREELIST_SIZE)
cdef class RawRequestMessage:
    cdef readonly str method
    cdef readonly str path
    cdef readonly object version  # HttpVersion
    cdef readonly object headers  # CIMultiDict
    cdef readonly object raw_headers  # tuple
    cdef readonly object should_close
    cdef readonly object compression
    cdef readonly object upgrade
    cdef readonly object chunked
    cdef readonly object url  # yarl.URL

    def __init__(self, method, path, version, headers, raw_headers,
                 should_close, compression, upgrade, chunked, url):
        self.method = method
        self.path = path
        self.version = version
        self.headers = headers
        self.raw_headers = raw_headers
        self.should_close = should_close
        self.compression = compression
        self.upgrade = upgrade
        self.chunked = chunked
        self.url = url

    def __repr__(self):
        info = []
        info.append(("method", self.method))
        info.append(("path", self.path))
        info.append(("version", self.version))
        info.append(("headers", self.headers))
        info.append(("raw_headers", self.raw_headers))
        info.append(("should_close", self.should_close))
        info.append(("compression", self.compression))
        info.append(("upgrade", self.upgrade))
        info.append(("chunked", self.chunked))
        info.append(("url", self.url))
        sinfo = ', '.join(name + '=' + repr(val) for name, val in info)
        return '<RawRequestMessage(' + sinfo + ')>'

    def _replace(self, **dct):
        cdef RawRequestMessage ret
        ret = _new_request_message(self.method,
                                   self.path,
                                   self.version,
                                   self.headers,
                                   self.raw_headers,
                                   self.should_close,
                                   self.compression,
                                   self.upgrade,
                                   self.chunked,
                                   self.url)
        if "method" in dct:
            ret.method = dct["method"]
        if "path" in dct:
            ret.path = dct["path"]
        if "version" in dct:
            ret.version = dct["version"]
        if "headers" in dct:
            ret.headers = dct["headers"]
        if "raw_headers" in dct:
            ret.raw_headers = dct["raw_headers"]
        if "should_close" in dct:
            ret.should_close = dct["should_close"]
        if "compression" in dct:
            ret.compression = dct["compression"]
        if "upgrade" in dct:
            ret.upgrade = dct["upgrade"]
        if "chunked" in dct:
            ret.chunked = dct["chunked"]
        if "url" in dct:
            ret.url = dct["url"]
        return ret

cdef _new_request_message(str method,
                           str path,
                           object version,
                           object headers,
                           object raw_headers,
                           bint should_close,
                           object compression,
                           bint upgrade,
                           bint chunked,
                           object url):
    cdef RawRequestMessage ret
    ret = RawRequestMessage.__new__(RawRequestMessage)
    ret.method = method
    ret.path = path
    ret.version = version
    ret.headers = headers
    ret.raw_headers = raw_headers
    ret.should_close = should_close
    ret.compression = compression
    ret.upgrade = upgrade
    ret.chunked = chunked
    ret.url = url
    return ret


@cython.freelist(DEFAULT_FREELIST_SIZE)
cdef class RawResponseMessage:
    cdef readonly object version  # HttpVersion
    cdef readonly int code
    cdef readonly str reason
    cdef readonly object headers  # CIMultiDict
    cdef readonly object raw_headers  # tuple
    cdef readonly object should_close
    cdef readonly object compression
    cdef readonly object upgrade
    cdef readonly object chunked

    def __init__(self, version, code, reason, headers, raw_headers,
                 should_close, compression, upgrade, chunked):
        self.version = version
        self.code = code
        self.reason = reason
        self.headers = headers
        self.raw_headers = raw_headers
        self.should_close = should_close
        self.compression = compression
        self.upgrade = upgrade
        self.chunked = chunked

    def __repr__(self):
        info = []
        info.append(("version", self.version))
        info.append(("code", self.code))
        info.append(("reason", self.reason))
        info.append(("headers", self.headers))
        info.append(("raw_headers", self.raw_headers))
        info.append(("should_close", self.should_close))
        info.append(("compression", self.compression))
        info.append(("upgrade", self.upgrade))
        info.append(("chunked", self.chunked))
        sinfo = ', '.join(name + '=' + repr(val) for name, val in info)
        return '<RawResponseMessage(' + sinfo + ')>'


cdef _new_response_message(object version,
                           int code,
                           str reason,
                           object headers,
                           object raw_headers,
                           bint should_close,
                           object compression,
                           bint upgrade,
                           bint chunked):
    cdef RawResponseMessage ret
    ret = RawResponseMessage.__new__(RawResponseMessage)
    ret.version = version
    ret.code = code
    ret.reason = reason
    ret.headers = headers
    ret.raw_headers = raw_headers
    ret.should_close = should_close
    ret.compression = compression
    ret.upgrade = upgrade
    ret.chunked = chunked
    return ret


@cython.internal
cdef class HttpParser:

    cdef:
        cparser.http_parser* _cparser
        cparser.http_parser_settings* _csettings

        bytearray _raw_name
        bytearray _raw_value
        bint      _has_value

        object _protocol
        object _loop
        object _timer

        size_t _max_line_size
        size_t _max_field_size
        size_t _max_headers
        bint _response_with_body
        bint _read_until_eof

        bint    _started
        object  _url
        bytearray   _buf
        str     _path
        str     _reason
        object  _headers
        list    _raw_headers
        bint    _upgraded
        list    _messages
        object  _payload
        bint    _payload_error
        object  _payload_exception
        object  _last_error
        bint    _auto_decompress
        int     _limit

        str     _content_encoding

        Py_buffer py_buf

    def __cinit__(self):
        self._cparser = <cparser.http_parser*> \
                                PyMem_Malloc(sizeof(cparser.http_parser))
        if self._cparser is NULL:
            raise MemoryError()

        self._csettings = <cparser.http_parser_settings*> \
                                PyMem_Malloc(sizeof(cparser.http_parser_settings))
        if self._csettings is NULL:
            raise MemoryError()

    def __dealloc__(self):
        PyMem_Free(self._cparser)
        PyMem_Free(self._csettings)

    cdef _init(self, cparser.http_parser_type mode,
                   object protocol, object loop, int limit,
                   object timer=None,
                   size_t max_line_size=8190, size_t max_headers=32768,
                   size_t max_field_size=8190, payload_exception=None,
                   bint response_with_body=True, bint read_until_eof=False,
                   bint auto_decompress=True):
        cparser.http_parser_init(self._cparser, mode)
        self._cparser.data = <void*>self
        self._cparser.content_length = 0

        cparser.http_parser_settings_init(self._csettings)

        self._protocol = protocol
        self._loop = loop
        self._timer = timer

        self._buf = bytearray()
        self._payload = None
        self._payload_error = 0
        self._payload_exception = payload_exception
        self._messages = []

        self._raw_name = bytearray()
        self._raw_value = bytearray()
        self._has_value = False

        self._max_line_size = max_line_size
        self._max_headers = max_headers
        self._max_field_size = max_field_size
        self._response_with_body = response_with_body
        self._read_until_eof = read_until_eof
        self._upgraded = False
        self._auto_decompress = auto_decompress
        self._content_encoding = None

        self._csettings.on_url = cb_on_url
        self._csettings.on_status = cb_on_status
        self._csettings.on_header_field = cb_on_header_field
        self._csettings.on_header_value = cb_on_header_value
        self._csettings.on_headers_complete = cb_on_headers_complete
        self._csettings.on_body = cb_on_body
        self._csettings.on_message_begin = cb_on_message_begin
        self._csettings.on_message_complete = cb_on_message_complete
        self._csettings.on_chunk_header = cb_on_chunk_header
        self._csettings.on_chunk_complete = cb_on_chunk_complete

        self._last_error = None
        self._limit = limit

    cdef _process_header(self):
        if self._raw_name:
            raw_name = bytes(self._raw_name)
            raw_value = bytes(self._raw_value)

            name = find_header(raw_name)
            value = raw_value.decode('utf-8', 'surrogateescape')

            self._headers.add(name, value)

            if name is CONTENT_ENCODING:
                self._content_encoding = value

            PyByteArray_Resize(self._raw_name, 0)
            PyByteArray_Resize(self._raw_value, 0)
            self._has_value = False
            self._raw_headers.append((raw_name, raw_value))

    cdef _on_header_field(self, char* at, size_t length):
        cdef Py_ssize_t size
        cdef char *buf
        if self._has_value:
            self._process_header()

        size = PyByteArray_Size(self._raw_name)
        PyByteArray_Resize(self._raw_name, size + length)
        buf = PyByteArray_AsString(self._raw_name)
        memcpy(buf + size, at, length)

    cdef _on_header_value(self, char* at, size_t length):
        cdef Py_ssize_t size
        cdef char *buf

        size = PyByteArray_Size(self._raw_value)
        PyByteArray_Resize(self._raw_value, size + length)
        buf = PyByteArray_AsString(self._raw_value)
        memcpy(buf + size, at, length)
        self._has_value = True

    cdef _on_headers_complete(self):
        self._process_header()

        method = http_method_str(self._cparser.method)
        should_close = not cparser.http_should_keep_alive(self._cparser)
        upgrade = self._cparser.upgrade
        chunked = self._cparser.flags & cparser.F_CHUNKED

        raw_headers = tuple(self._raw_headers)
        headers = CIMultiDictProxy(self._headers)

        if upgrade or self._cparser.method == 5: # cparser.CONNECT:
            self._upgraded = True

        # do not support old websocket spec
        if SEC_WEBSOCKET_KEY1 in headers:
            raise InvalidHeader(SEC_WEBSOCKET_KEY1)

        encoding = None
        enc = self._content_encoding
        if enc is not None:
            self._content_encoding = None
            enc = enc.lower()
            if enc in ('gzip', 'deflate', 'br'):
                encoding = enc

        if self._cparser.type == cparser.HTTP_REQUEST:
            msg = _new_request_message(
                method, self._path,
                self.http_version(), headers, raw_headers,
                should_close, encoding, upgrade, chunked, self._url)
        else:
            msg = _new_response_message(
                self.http_version(), self._cparser.status_code, self._reason,
                headers, raw_headers, should_close, encoding,
                upgrade, chunked)

        if (ULLONG_MAX > self._cparser.content_length > 0 or chunked or
                self._cparser.method == 5 or  # CONNECT: 5
                (self._cparser.status_code >= 199 and
                 self._cparser.content_length == ULLONG_MAX and
                 self._read_until_eof)
        ):
            payload = StreamReader(
                self._protocol, timer=self._timer, loop=self._loop,
                limit=self._limit)
        else:
            payload = EMPTY_PAYLOAD

        self._payload = payload
        if encoding is not None and self._auto_decompress:
            self._payload = DeflateBuffer(payload, encoding)

        if not self._response_with_body:
            payload = EMPTY_PAYLOAD

        self._messages.append((msg, payload))

    cdef _on_message_complete(self):
        self._payload.feed_eof()
        self._payload = None

    cdef _on_chunk_header(self):
        self._payload.begin_http_chunk_receiving()

    cdef _on_chunk_complete(self):
        self._payload.end_http_chunk_receiving()

    cdef object _on_status_complete(self):
        pass

    cdef inline http_version(self):
        cdef cparser.http_parser* parser = self._cparser

        if parser.http_major == 1:
            if parser.http_minor == 0:
                return HttpVersion10
            elif parser.http_minor == 1:
                return HttpVersion11

        return HttpVersion(parser.http_major, parser.http_minor)

    ### Public API ###

    def feed_eof(self):
        cdef bytes desc

        if self._payload is not None:
            if self._cparser.flags & cparser.F_CHUNKED:
                raise TransferEncodingError(
                    "Not enough data for satisfy transfer length header.")
            elif self._cparser.flags & cparser.F_CONTENTLENGTH:
                raise ContentLengthError(
                    "Not enough data for satisfy content length header.")
            elif self._cparser.http_errno != cparser.HPE_OK:
                desc = cparser.http_errno_description(
                    <cparser.http_errno> self._cparser.http_errno)
                raise PayloadEncodingError(desc.decode('latin-1'))
            else:
                self._payload.feed_eof()
        elif self._started:
            self._on_headers_complete()
            if self._messages:
                return self._messages[-1][0]

    def feed_data(self, data):
        cdef:
            size_t data_len
            size_t nb

        PyObject_GetBuffer(data, &self.py_buf, PyBUF_SIMPLE)
        data_len = <size_t>self.py_buf.len

        nb = cparser.http_parser_execute(
            self._cparser,
            self._csettings,
            <char*>self.py_buf.buf,
            data_len)

        PyBuffer_Release(&self.py_buf)

        if (self._cparser.http_errno != cparser.HPE_OK):
            if self._payload_error == 0:
                if self._last_error is not None:
                    ex = self._last_error
                    self._last_error = None
                else:
                    ex = parser_error_from_errno(
                        <cparser.http_errno> self._cparser.http_errno)
                self._payload = None
                raise ex

        if self._messages:
            messages = self._messages
            self._messages = []
        else:
            messages = ()

        if self._upgraded:
            return messages, True, data[nb:]
        else:
            return messages, False, b''

    def set_upgraded(self, val):
        self._upgraded = val


cdef class HttpRequestParser(HttpParser):

    def __init__(self, protocol, loop, int limit, timer=None,
                 size_t max_line_size=8190, size_t max_headers=32768,
                 size_t max_field_size=8190, payload_exception=None,
                 bint response_with_body=True, bint read_until_eof=False,
    ):
         self._init(cparser.HTTP_REQUEST, protocol, loop, limit, timer,
                    max_line_size, max_headers, max_field_size,
                    payload_exception, response_with_body, read_until_eof)

    cdef object _on_status_complete(self):
         cdef Py_buffer py_buf
         if not self._buf:
             return
         self._path = self._buf.decode('utf-8', 'surrogateescape')
         if self._cparser.method == 5:  # CONNECT
             self._url = URL(self._path)
         else:
             PyObject_GetBuffer(self._buf, &py_buf, PyBUF_SIMPLE)
             try:
                 self._url = _parse_url(<char*>py_buf.buf,
                                        py_buf.len)
             finally:
                 PyBuffer_Release(&py_buf)
         PyByteArray_Resize(self._buf, 0)


cdef class HttpResponseParser(HttpParser):

    def __init__(self, protocol, loop, int limit, timer=None,
                 size_t max_line_size=8190, size_t max_headers=32768,
                 size_t max_field_size=8190, payload_exception=None,
                 bint response_with_body=True, bint read_until_eof=False,
                 bint auto_decompress=True
    ):
        self._init(cparser.HTTP_RESPONSE, protocol, loop, limit, timer,
                   max_line_size, max_headers, max_field_size,
                   payload_exception, response_with_body, read_until_eof,
                   auto_decompress)

    cdef object _on_status_complete(self):
        if self._buf:
            self._reason = self._buf.decode('utf-8', 'surrogateescape')
            PyByteArray_Resize(self._buf, 0)
        else:
            self._reason = self._reason or ''

cdef int cb_on_message_begin(cparser.http_parser* parser) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data

    pyparser._started = True
    pyparser._headers = CIMultiDict()
    pyparser._raw_headers = []
    PyByteArray_Resize(pyparser._buf, 0)
    pyparser._path = None
    pyparser._reason = None
    return 0


cdef int cb_on_url(cparser.http_parser* parser,
                   const char *at, size_t length) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data
    try:
        if length > pyparser._max_line_size:
            raise LineTooLong(
                'Status line is too long', pyparser._max_line_size, length)
        extend(pyparser._buf, at, length)
    except BaseException as ex:
        pyparser._last_error = ex
        return -1
    else:
        return 0


cdef int cb_on_status(cparser.http_parser* parser,
                      const char *at, size_t length) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data
    cdef str reason
    try:
        if length > pyparser._max_line_size:
            raise LineTooLong(
                'Status line is too long', pyparser._max_line_size, length)
        extend(pyparser._buf, at, length)
    except BaseException as ex:
        pyparser._last_error = ex
        return -1
    else:
        return 0


cdef int cb_on_header_field(cparser.http_parser* parser,
                            const char *at, size_t length) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data
    cdef Py_ssize_t size
    try:
        pyparser._on_status_complete()
        size = len(pyparser._raw_name) + length
        if size > pyparser._max_field_size:
            raise LineTooLong(
                'Header name is too long', pyparser._max_field_size, size)
        pyparser._on_header_field(at, length)
    except BaseException as ex:
        pyparser._last_error = ex
        return -1
    else:
        return 0


cdef int cb_on_header_value(cparser.http_parser* parser,
                            const char *at, size_t length) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data
    cdef Py_ssize_t size
    try:
        size = len(pyparser._raw_value) + length
        if size > pyparser._max_field_size:
            raise LineTooLong(
                'Header value is too long', pyparser._max_field_size, size)
        pyparser._on_header_value(at, length)
    except BaseException as ex:
        pyparser._last_error = ex
        return -1
    else:
        return 0


cdef int cb_on_headers_complete(cparser.http_parser* parser) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data
    try:
        pyparser._on_status_complete()
        pyparser._on_headers_complete()
    except BaseException as exc:
        pyparser._last_error = exc
        return -1
    else:
        if pyparser._cparser.upgrade or pyparser._cparser.method == 5: # CONNECT
            return 2
        else:
            return 0


cdef int cb_on_body(cparser.http_parser* parser,
                    const char *at, size_t length) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data
    cdef bytes body = at[:length]
    try:
        pyparser._payload.feed_data(body, length)
    except BaseException as exc:
        if pyparser._payload_exception is not None:
            pyparser._payload.set_exception(pyparser._payload_exception(str(exc)))
        else:
            pyparser._payload.set_exception(exc)
        pyparser._payload_error = 1
        return -1
    else:
        return 0


cdef int cb_on_message_complete(cparser.http_parser* parser) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data
    try:
        pyparser._started = False
        pyparser._on_message_complete()
    except BaseException as exc:
        pyparser._last_error = exc
        return -1
    else:
        return 0


cdef int cb_on_chunk_header(cparser.http_parser* parser) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data
    try:
        pyparser._on_chunk_header()
    except BaseException as exc:
        pyparser._last_error = exc
        return -1
    else:
        return 0


cdef int cb_on_chunk_complete(cparser.http_parser* parser) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data
    try:
        pyparser._on_chunk_complete()
    except BaseException as exc:
        pyparser._last_error = exc
        return -1
    else:
        return 0


cdef parser_error_from_errno(cparser.http_errno errno):
    cdef bytes desc = cparser.http_errno_description(errno)

    if errno in (cparser.HPE_CB_message_begin,
                 cparser.HPE_CB_url,
                 cparser.HPE_CB_header_field,
                 cparser.HPE_CB_header_value,
                 cparser.HPE_CB_headers_complete,
                 cparser.HPE_CB_body,
                 cparser.HPE_CB_message_complete,
                 cparser.HPE_CB_status,
                 cparser.HPE_CB_chunk_header,
                 cparser.HPE_CB_chunk_complete):
        cls = BadHttpMessage

    elif errno == cparser.HPE_INVALID_STATUS:
        cls = BadStatusLine

    elif errno == cparser.HPE_INVALID_METHOD:
        cls = BadStatusLine

    elif errno == cparser.HPE_INVALID_URL:
        cls = InvalidURLError

    else:
        cls = BadHttpMessage

    return cls(desc.decode('latin-1'))


def parse_url(url):
    cdef:
        Py_buffer py_buf
        char* buf_data

    PyObject_GetBuffer(url, &py_buf, PyBUF_SIMPLE)
    try:
        buf_data = <char*>py_buf.buf
        return _parse_url(buf_data, py_buf.len)
    finally:
        PyBuffer_Release(&py_buf)


cdef _parse_url(char* buf_data, size_t length):
    cdef:
        cparser.http_parser_url* parsed
        int res
        str schema = None
        str host = None
        object port = None
        str path = None
        str query = None
        str fragment = None
        str user = None
        str password = None
        str userinfo = None
        object result = None
        int off
        int ln

    parsed = <cparser.http_parser_url*> \
                        PyMem_Malloc(sizeof(cparser.http_parser_url))
    if parsed is NULL:
        raise MemoryError()
    cparser.http_parser_url_init(parsed)
    try:
        res = cparser.http_parser_parse_url(buf_data, length, 0, parsed)

        if res == 0:
            if parsed.field_set & (1 << cparser.UF_SCHEMA):
                off = parsed.field_data[<int>cparser.UF_SCHEMA].off
                ln = parsed.field_data[<int>cparser.UF_SCHEMA].len
                schema = buf_data[off:off+ln].decode('utf-8', 'surrogateescape')
            else:
                schema = ''

            if parsed.field_set & (1 << cparser.UF_HOST):
                off = parsed.field_data[<int>cparser.UF_HOST].off
                ln = parsed.field_data[<int>cparser.UF_HOST].len
                host = buf_data[off:off+ln].decode('utf-8', 'surrogateescape')
            else:
                host = ''

            if parsed.field_set & (1 << cparser.UF_PORT):
                port = parsed.port

            if parsed.field_set & (1 << cparser.UF_PATH):
                off = parsed.field_data[<int>cparser.UF_PATH].off
                ln = parsed.field_data[<int>cparser.UF_PATH].len
                path = buf_data[off:off+ln].decode('utf-8', 'surrogateescape')
            else:
                path = ''

            if parsed.field_set & (1 << cparser.UF_QUERY):
                off = parsed.field_data[<int>cparser.UF_QUERY].off
                ln = parsed.field_data[<int>cparser.UF_QUERY].len
                query = buf_data[off:off+ln].decode('utf-8', 'surrogateescape')
            else:
                query = ''

            if parsed.field_set & (1 << cparser.UF_FRAGMENT):
                off = parsed.field_data[<int>cparser.UF_FRAGMENT].off
                ln = parsed.field_data[<int>cparser.UF_FRAGMENT].len
                fragment = buf_data[off:off+ln].decode('utf-8', 'surrogateescape')
            else:
                fragment = ''

            if parsed.field_set & (1 << cparser.UF_USERINFO):
                off = parsed.field_data[<int>cparser.UF_USERINFO].off
                ln = parsed.field_data[<int>cparser.UF_USERINFO].len
                userinfo = buf_data[off:off+ln].decode('utf-8', 'surrogateescape')

                user, sep, password = userinfo.partition(':')

            return URL_build(scheme=schema,
                             user=user, password=password, host=host, port=port,
                             path=path, query=query, fragment=fragment)
        else:
            raise InvalidURLError("invalid url {!r}".format(buf_data))
    finally:
        PyMem_Free(parsed)
