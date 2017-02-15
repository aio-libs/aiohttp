#cython: language_level=3
#
# Based on https://github.com/MagicStack/httptools
#
from __future__ import print_function
from cpython.mem cimport PyMem_Malloc, PyMem_Free
from cpython cimport PyObject_GetBuffer, PyBuffer_Release, PyBUF_SIMPLE, \
                     Py_buffer, PyBytes_AsString

from multidict import CIMultiDict

from aiohttp import hdrs
from .errors import (
    BadHttpMessage, BadStatusLine, InvalidHeader, LineTooLong, InvalidURLError)
from .protocol import (
    HttpVersion, HttpVersion10, HttpVersion11,
    RawRequestMessage, DeflateBuffer, URL)
from .streams import EMPTY_PAYLOAD, FlowControlStreamReader

cimport cython
from . cimport _cparser as cparser


__all__ = ('HttpRequestParser', 'parse_url')


@cython.internal
cdef class HttpParser:

    cdef:
        cparser.http_parser* _cparser
        cparser.http_parser_settings* _csettings

        str _current_header_name
        str _current_header_value

        object _protocol
        object _loop

        size_t _max_line_size
        size_t _max_field_size
        size_t _max_headers

        object  _url
        str     _path
        list    _headers
        bint    _upgraded
        list    _messages
        object  _payload
        object _last_error

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
                   object protocol, object loop,
                   size_t max_line_size=8190, size_t max_headers=32768,
                   size_t max_field_size=8190):
        cparser.http_parser_init(self._cparser, mode)
        self._cparser.data = <void*>self
        self._cparser.content_length = 0

        cparser.http_parser_settings_init(self._csettings)

        self._protocol = protocol
        self._loop = loop

        self._payload = None
        self._messages = []

        self._current_header_name = None
        self._current_header_value = None
        self._max_line_size = max_line_size
        self._max_headers = max_headers
        self._max_field_size = max_field_size
        self._upgraded = False

        self._csettings.on_url = cb_on_url
        self._csettings.on_header_field = cb_on_header_field
        self._csettings.on_header_value = cb_on_header_value
        self._csettings.on_headers_complete = cb_on_headers_complete
        self._csettings.on_body = cb_on_body
        self._csettings.on_message_begin = cb_on_message_begin
        self._csettings.on_message_complete = cb_on_message_complete

        self._last_error = None

    cdef _process_header(self):
        if self._current_header_name is not None:
            header_name = self._current_header_name
            header_value = self._current_header_value

            self._current_header_name = self._current_header_value = None
            self._headers.append((header_name, header_value))

    cdef _on_header_field(self, str field):
        self._process_header()
        self._current_header_name = field

    cdef _on_header_value(self, str val):
        if self._current_header_value is None:
            self._current_header_value = val
        else:
            # This is unlikely, as mostly HTTP headers are one-line
            self._current_header_value += val

    cdef _on_headers_complete(self):
        self._process_header()

        method = cparser.http_method_str(<cparser.http_method> self._cparser.method)
        should_close = not bool(cparser.http_should_keep_alive(self._cparser))
        upgrade = bool(self._cparser.upgrade)
        chunked = bool(self._cparser.flags & cparser.F_CHUNKED)

        headers = CIMultiDict(self._headers)

        if upgrade or self._cparser.method == 5: # cparser.CONNECT:
            self._upgraded = True

        encoding = None
        enc = headers.get(hdrs.CONTENT_ENCODING)
        if enc:
           enc = enc.lower()
           if enc in ('gzip', 'deflate'):
                encoding = enc

        msg = RawRequestMessage(
            method.decode('utf-8', 'surrogateescape'), self._path,
            self.http_version(), headers, self._headers,
            should_close, encoding, upgrade, chunked, self._url)

        if (self._cparser.content_length > 0 or chunked or
                self._cparser.method == 5):  # CONNECT: 5
            payload = FlowControlStreamReader(self._protocol, loop=self._loop)
        else:
            payload = EMPTY_PAYLOAD

        self._payload = payload
        if encoding is not None:
            self._payload = DeflateBuffer(payload, encoding)

        self._messages.append((msg, payload))

    cdef _on_message_complete(self):
        self._payload.feed_eof()
        self._payload = None

    cdef _on_chunk_header(self):
        if (self._current_header_value is not None or
            self._current_header_name is not None):
            raise BadHttpMessage('invalid headers state')

        if self._proto_on_chunk_header is not None:
            self._proto_on_chunk_header()

    cdef _on_chunk_complete(self):
        self._maybe_call_on_header()

        if self._proto_on_chunk_complete is not None:
            self._proto_on_chunk_complete()

    ### Public API ###

    def http_version(self):
        cdef cparser.http_parser* parser = self._cparser

        if parser.http_major == 1:
            if parser.http_minor == 0:
                return HttpVersion10
            elif parser.http_minor == 1:
                return HttpVersion11

        return HttpVersion(parser.http_major, parser.http_minor)

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
            ex = parser_error_from_errno(
                <cparser.http_errno> self._cparser.http_errno)
            if self._last_error is not None:
                ex.__context__ = self._last_error
                self._last_error = None
            raise ex

        if self._messages:
            messages = self._messages
            self._messages = []
        else:
            messages = ()

        if self._upgraded:
            return messages, True, data[nb:]
        else:
            return messages, False, None


cdef class HttpRequestParser(HttpParser):

    def __init__(self, protocol, loop,
                 size_t max_line_size=8190, size_t max_headers=32768,
                 size_t max_field_size=8190):
         self._init(cparser.HTTP_REQUEST, protocol, loop,
                    max_line_size, max_headers, max_field_size)
        #self._proto_on_url = getattr(protocol, 'on_url', None)
        #if self._proto_on_url is not None:
        #    self._csettings.on_url = cb_on_url

    def get_method(self):
        cdef cparser.http_parser* parser = self._cparser
        return cparser.http_method_str(<cparser.http_method> parser.method)


cdef int cb_on_message_begin(cparser.http_parser* parser) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data

    pyparser._headers = []
    return 0


cdef int cb_on_url(cparser.http_parser* parser,
                   const char *at, size_t length) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data
    try:
        pyparser._url = _parse_url(at[:length], length)
        pyparser._path = at[:length].decode('utf-8', 'surrogateescape')
    except BaseException as ex:
        pyparser._last_error = ex
        return -1
    else:
        return 0


cdef int cb_on_status(cparser.http_parser* parser,
                      const char *at, size_t length) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data
    try:
        pyparser._proto_on_status(
            at[:length].decode('utf-8', 'surrogateescape'))
    except BaseException as ex:
        pyparser._last_error = ex
        return -1
    else:
        return 0


cdef int cb_on_header_field(cparser.http_parser* parser,
                            const char *at, size_t length) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data
    try:
        if length > pyparser._max_field_size:
            raise LineTooLong()
        pyparser._on_header_field(at[:length].decode('utf-8', 'surrogateescape'))
    except BaseException as ex:
        pyparser._last_error = ex
        return -1
    else:
        return 0


cdef int cb_on_header_value(cparser.http_parser* parser,
                            const char *at, size_t length) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data
    try:
        if length > pyparser._max_field_size:
            raise LineTooLong()
        pyparser._on_header_value(at[:length].decode('utf-8', 'surrogateescape'))
    except BaseException as ex:
        pyparser._last_error = ex
        return -1
    else:
        return 0


cdef int cb_on_headers_complete(cparser.http_parser* parser) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data
    try:
        pyparser._on_headers_complete()
    except BaseException as ex:
        pyparser._last_error = ex
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
    except BaseException as ex:
        pyparser._last_error = ex
        return -1
    else:
        return 0


cdef int cb_on_message_complete(cparser.http_parser* parser) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data
    try:
        pyparser._on_message_complete()
    except BaseException as ex:
        pyparser._last_error = ex
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
        str userinfo = None
        object result = None
        int off
        int ln

    parsed = <cparser.http_parser_url*> \
                        PyMem_Malloc(sizeof(cparser.http_parser_url))
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

            return URL(schema, host, port, path, query, fragment, userinfo)
        else:
            raise InvalidURLError("invalid url {!r}".format(buf_data))
    finally:
        PyMem_Free(parsed)
