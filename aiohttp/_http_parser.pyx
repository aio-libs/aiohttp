#cython: language_level=3
#
# Based on https://github.com/MagicStack/httptools
#
from __future__ import absolute_import, print_function
from cpython.mem cimport PyMem_Malloc, PyMem_Free
from cpython cimport PyObject_GetBuffer, PyBuffer_Release, PyBUF_SIMPLE, \
                     Py_buffer, PyBytes_AsString

from multidict import CIMultiDict
from yarl import URL

from aiohttp import hdrs
from .http_exceptions import (
    BadHttpMessage, BadStatusLine, InvalidHeader, LineTooLong, InvalidURLError,
    PayloadEncodingError, ContentLengthError, TransferEncodingError)
from .http_writer import HttpVersion, HttpVersion10, HttpVersion11
from .http_parser import RawRequestMessage, RawResponseMessage, DeflateBuffer
from .streams import EMPTY_PAYLOAD, StreamReader

cimport cython
from . cimport _cparser as cparser


__all__ = ('HttpRequestParserC', 'HttpResponseMessageC', 'parse_url')


cdef object URL_build = URL.build

@cython.internal
cdef class HttpParser:

    cdef:
        cparser.http_parser* _cparser
        cparser.http_parser_settings* _csettings

        str _header_name
        str _header_value
        bytes _raw_header_name
        bytes _raw_header_value

        object _protocol
        object _loop
        object _timer

        size_t _max_line_size
        size_t _max_field_size
        size_t _max_headers
        bint _response_with_body

        bint    _started
        object  _url
        bytearray   _buf
        str     _path
        str     _reason
        list    _headers
        list    _raw_headers
        bint    _upgraded
        list    _messages
        object  _payload
        bint    _payload_error
        object  _payload_exception
        object  _last_error
        bint    _auto_decompress

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
                   object protocol, object loop, object timer=None,
                   size_t max_line_size=8190, size_t max_headers=32768,
                   size_t max_field_size=8190, payload_exception=None,
                   response_with_body=True, auto_decompress=True):
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

        self._header_name = None
        self._header_value = None
        self._raw_header_name = None
        self._raw_header_value = None

        self._max_line_size = max_line_size
        self._max_headers = max_headers
        self._max_field_size = max_field_size
        self._response_with_body = response_with_body
        self._upgraded = False
        self._auto_decompress = auto_decompress

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

    cdef _process_header(self):
        if self._header_name is not None:
            name = self._header_name
            value = self._header_value

            self._header_name = self._header_value = None
            self._headers.append((name, value))

            raw_name = self._raw_header_name
            raw_value = self._raw_header_value

            self._raw_header_name = self._raw_header_value = None
            self._raw_headers.append((raw_name, raw_value))

    cdef _on_header_field(self, str field, bytes raw_field):
        if self._header_value is not None:
            self._process_header()
            self._header_value = None

        if self._header_name is None:
            self._header_name = field
            self._raw_header_name = raw_field
        else:
            self._header_name += field
            self._raw_header_name += raw_field

    cdef _on_header_value(self, str val, bytes raw_val):
        if self._header_value is None:
            self._header_value = val
            self._raw_header_value = raw_val
        else:
            self._header_value += val
            self._raw_header_value += raw_val

    cdef _on_headers_complete(self,
                              ENCODING='utf-8',
                              ENCODING_ERR='surrogateescape',
                              CONTENT_ENCODING=hdrs.CONTENT_ENCODING,
                              SEC_WEBSOCKET_KEY1=hdrs.SEC_WEBSOCKET_KEY1,
                              SUPPORTED=('gzip', 'deflate', 'br')):
        self._process_header()

        method = cparser.http_method_str(<cparser.http_method> self._cparser.method)
        should_close = not bool(cparser.http_should_keep_alive(self._cparser))
        upgrade = bool(self._cparser.upgrade)
        chunked = bool(self._cparser.flags & cparser.F_CHUNKED)

        raw_headers = tuple(self._raw_headers)
        headers = CIMultiDict(self._headers)

        if upgrade or self._cparser.method == 5: # cparser.CONNECT:
            self._upgraded = True

        # do not support old websocket spec
        if SEC_WEBSOCKET_KEY1 in headers:
            raise InvalidHeader(SEC_WEBSOCKET_KEY1)

        encoding = None
        enc = headers.get(CONTENT_ENCODING)
        if enc:
            enc = enc.lower()
            if enc in SUPPORTED:
                encoding = enc

        if self._cparser.type == cparser.HTTP_REQUEST:
            msg = RawRequestMessage(
                method.decode(ENCODING, ENCODING_ERR), self._path,
                self.http_version(), headers, raw_headers,
                should_close, encoding, upgrade, chunked, self._url)
        else:
            msg = RawResponseMessage(
                self.http_version(), self._cparser.status_code, self._reason,
                headers, raw_headers, should_close, encoding,
                upgrade, chunked)

        if (self._cparser.content_length > 0 or chunked or
                self._cparser.method == 5):  # CONNECT: 5
            payload = StreamReader(
                self._protocol, timer=self._timer, loop=self._loop)
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

    ### Public API ###

    def http_version(self):
        cdef cparser.http_parser* parser = self._cparser

        if parser.http_major == 1:
            if parser.http_minor == 0:
                return HttpVersion10
            elif parser.http_minor == 1:
                return HttpVersion11

        return HttpVersion(parser.http_major, parser.http_minor)

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

        # i am not sure about cparser.HPE_INVALID_METHOD,
        #  seems get err for valid request
        # test_client_functional.py::test_post_data_with_bytesio_file
        if (self._cparser.http_errno != cparser.HPE_OK and
                (self._cparser.http_errno != cparser.HPE_INVALID_METHOD or
                 self._cparser.method == 0)):
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


cdef class HttpRequestParserC(HttpParser):

    def __init__(self, protocol, loop, timer=None,
                 size_t max_line_size=8190, size_t max_headers=32768,
                 size_t max_field_size=8190, payload_exception=None,
                 response_with_body=True, read_until_eof=False):
         self._init(cparser.HTTP_REQUEST, protocol, loop, timer,
                    max_line_size, max_headers, max_field_size,
                    payload_exception, response_with_body)

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
         self._buf.clear()


cdef class HttpResponseParserC(HttpParser):

    def __init__(self, protocol, loop, timer=None,
                 size_t max_line_size=8190, size_t max_headers=32768,
                 size_t max_field_size=8190, payload_exception=None,
                 response_with_body=True, read_until_eof=False,
                 auto_decompress=True):
        self._init(cparser.HTTP_RESPONSE, protocol, loop, timer,
                   max_line_size, max_headers, max_field_size,
                   payload_exception, response_with_body, auto_decompress)

    cdef object _on_status_complete(self):
        if self._buf:
            self._reason = self._buf.decode('utf-8', 'surrogateescape')
            self._buf.clear()


cdef int cb_on_message_begin(cparser.http_parser* parser) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data

    pyparser._started = True
    pyparser._headers = []
    pyparser._raw_headers = []
    pyparser._buf.clear()
    pyparser._path = None
    pyparser._reason = None
    return 0


cdef int cb_on_url(cparser.http_parser* parser,
                   const char *at, size_t length) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data
    try:
        if length > pyparser._max_line_size:
            raise LineTooLong(
                'Status line is too long', pyparser._max_line_size)
        pyparser._buf.extend(at[:length])
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
                'Status line is too long', pyparser._max_line_size)
        pyparser._buf.extend(at[:length])
    except BaseException as ex:
        pyparser._last_error = ex
        return -1
    else:
        return 0


cdef int cb_on_header_field(cparser.http_parser* parser,
                            const char *at, size_t length) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data
    try:
        pyparser._on_status_complete()
        if length > pyparser._max_field_size:
            raise LineTooLong(
                'Header name is too long', pyparser._max_field_size)
        pyparser._on_header_field(
            at[:length].decode('utf-8', 'surrogateescape'), at[:length])
    except BaseException as ex:
        pyparser._last_error = ex
        return -1
    else:
        return 0


cdef int cb_on_header_value(cparser.http_parser* parser,
                            const char *at, size_t length) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data
    try:
        if pyparser._header_value is not None:
            if len(pyparser._header_value) + length > pyparser._max_field_size:
                raise LineTooLong(
                    'Header value is too long', pyparser._max_field_size)
        elif length > pyparser._max_field_size:
            raise LineTooLong(
                'Header value is too long', pyparser._max_field_size)
        pyparser._on_header_value(
            at[:length].decode('utf-8', 'surrogateescape'), at[:length])
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


def _parse_url(char* buf_data, size_t length):
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
