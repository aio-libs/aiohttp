"""Http related parsers and protocol."""

import asyncio
import collections
import http.server
import re
import string
import sys
import zlib
from abc import ABC, abstractmethod
from wsgiref.handlers import format_date_time

from multidict import CIMultiDict, istr

import aiohttp

from . import errors, hdrs
from .helpers import create_future
from .log import internal_logger

__all__ = ('HttpMessage', 'Request', 'Response',
           'HttpVersion', 'HttpVersion10', 'HttpVersion11',
           'RawRequestMessage', 'RawResponseMessage',
           'HttpRequestParser', 'HttpResponseParser', 'HttpPayloadParser')

ASCIISET = set(string.printable)
METHRE = re.compile('[A-Z0-9$-_.]+')
VERSRE = re.compile(r'HTTP/(\d+).(\d+)')
HDRRE = re.compile(rb'[\x00-\x1F\x7F()<>@,;:\[\]={} \t\\\\\"]')
EOF_MARKER = object()
EOL_MARKER = object()
STATUS_LINE_READY = object()

RESPONSES = http.server.BaseHTTPRequestHandler.responses

HttpVersion = collections.namedtuple(
    'HttpVersion', ['major', 'minor'])
HttpVersion10 = HttpVersion(1, 0)
HttpVersion11 = HttpVersion(1, 1)

RawStatusLineMessage = collections.namedtuple(
    'RawStatusLineMessage', ['method', 'path', 'version'])

RawRequestMessage = collections.namedtuple(
    'RawRequestMessage',
    ['method', 'path', 'version', 'headers', 'raw_headers',
     'should_close', 'compression'])


RawResponseMessage = collections.namedtuple(
    'RawResponseMessage',
    ['version', 'code', 'reason', 'headers', 'raw_headers',
     'should_close', 'compression'])


class HttpParser:

    def __init__(self, max_line_size=8190, max_headers=32768,
                 max_field_size=8190):
        self.max_line_size = max_line_size
        self.max_headers = max_headers
        self.max_field_size = max_field_size

    def parse_headers(self, lines):
        """Parses RFC 5322 headers from a stream.

        Line continuations are supported. Returns list of header name
        and value pairs. Header name is in upper case.
        """
        close_conn = None
        encoding = None
        headers = CIMultiDict()
        raw_headers = []

        lines_idx = 1
        line = lines[1]

        while line:
            header_length = len(line)

            # Parse initial header name : value pair.
            try:
                bname, bvalue = line.split(b':', 1)
            except ValueError:
                raise errors.InvalidHeader(line) from None

            bname = bname.strip(b' \t').upper()
            if HDRRE.search(bname):
                raise errors.InvalidHeader(bname)

            # next line
            lines_idx += 1
            line = lines[lines_idx]

            # consume continuation lines
            continuation = line and line[0] in (32, 9)  # (' ', '\t')

            if continuation:
                bvalue = [bvalue]
                while continuation:
                    header_length += len(line)
                    if header_length > self.max_field_size:
                        raise errors.LineTooLong(
                            'request header field {}'.format(
                                bname.decode("utf8", "xmlcharrefreplace")),
                            self.max_field_size)
                    bvalue.append(line)

                    # next line
                    lines_idx += 1
                    line = lines[lines_idx]
                    continuation = line[0] in (32, 9)  # (' ', '\t')
                bvalue = b'\r\n'.join(bvalue)
            else:
                if header_length > self.max_field_size:
                    raise errors.LineTooLong(
                        'request header field {}'.format(
                            bname.decode("utf8", "xmlcharrefreplace")),
                        self.max_field_size)

            bvalue = bvalue.strip()

            name = istr(bname.decode('utf-8', 'surrogateescape'))
            value = bvalue.decode('utf-8', 'surrogateescape')

            # keep-alive and encoding
            if name == hdrs.CONNECTION:
                v = value.lower()
                if v == 'close':
                    close_conn = True
                elif v == 'keep-alive':
                    close_conn = False
            elif name == hdrs.CONTENT_ENCODING:
                enc = value.lower()
                if enc in ('gzip', 'deflate'):
                    encoding = enc

            headers.add(name, value)
            raw_headers.append((bname, bvalue))

        return headers, raw_headers, close_conn, encoding


class HttpRequestParser(HttpParser):
    """Read request status line. Exception errors.BadStatusLine
    could be raised in case of any errors in status line.
    Returns RawRequestMessage.
    """

    def __call__(self, out, buf):
        # read HTTP message (request line + headers)
        try:
            raw_data = yield from buf.readuntil(
                b'\r\n\r\n', self.max_headers)
        except errors.LineLimitExceededParserError as exc:
            raise errors.LineTooLong('request header', exc.limit) from None

        lines = raw_data.split(b'\r\n')

        # request line
        line = lines[0].decode('utf-8', 'surrogateescape')
        try:
            method, path, version = line.split(None, 2)
        except ValueError:
            raise errors.BadStatusLine(line) from None

        # method
        method = method.upper()
        if not METHRE.match(method):
            raise errors.BadStatusLine(method)

        # version
        try:
            if version.startswith('HTTP/'):
                n1, n2 = version[5:].split('.', 1)
                version = HttpVersion(int(n1), int(n2))
            else:
                raise errors.BadStatusLine(version)
        except:
            raise errors.BadStatusLine(version)

        # read headers
        headers, raw_headers, close, compression = self.parse_headers(lines)
        if close is None:  # then the headers weren't set in the request
            if version <= HttpVersion10:  # HTTP 1.0 must asks to not close
                close = True
            else:  # HTTP 1.1 must ask to close.
                close = False

        out.feed_data(
            RawRequestMessage(
                method, path, version, headers, raw_headers,
                close, compression),
            len(raw_data))
        out.feed_eof()


class HttpResponseParser(HttpParser):
    """Read response status line and headers.

    BadStatusLine could be raised in case of any errors in status line.
    Returns RawResponseMessage"""

    def __call__(self, out, buf):
        # read HTTP message (response line + headers)
        try:
            raw_data = yield from buf.readuntil(
                b'\r\n\r\n', self.max_line_size + self.max_headers)
        except errors.LineLimitExceededParserError as exc:
            raise errors.LineTooLong('response header', exc.limit) from None

        lines = raw_data.split(b'\r\n')

        line = lines[0].decode('utf-8', 'surrogateescape')
        try:
            version, status = line.split(None, 1)
        except ValueError:
            raise errors.BadStatusLine(line) from None
        else:
            try:
                status, reason = status.split(None, 1)
            except ValueError:
                reason = ''

        # version
        match = VERSRE.match(version)
        if match is None:
            raise errors.BadStatusLine(line)
        version = HttpVersion(int(match.group(1)), int(match.group(2)))

        # The status code is a three-digit number
        try:
            status = int(status)
        except ValueError:
            raise errors.BadStatusLine(line) from None

        if status < 100 or status > 999:
            raise errors.BadStatusLine(line)

        # read headers
        headers, raw_headers, close, compression = self.parse_headers(lines)

        if close is None:
            close = version <= HttpVersion10

        out.feed_data(
            RawResponseMessage(
                version, status, reason.strip(),
                headers, raw_headers, close, compression),
            len(raw_data))
        out.feed_eof()


class HttpPayloadParser:

    def __init__(self, message, length=None, compression=True,
                 readall=False, response_with_body=True):
        self.message = message
        self.length = length
        self.compression = compression
        self.readall = readall
        self.response_with_body = response_with_body

    def __call__(self, out, buf):
        # payload params
        length = self.message.headers.get(hdrs.CONTENT_LENGTH, self.length)
        if hdrs.SEC_WEBSOCKET_KEY1 in self.message.headers:
            length = 8

        # payload decompression wrapper
        if (self.response_with_body and
                self.compression and self.message.compression):
            out = DeflateBuffer(out, self.message.compression)

        # payload parser
        if not self.response_with_body:
            # don't parse payload if it's not expected to be received
            pass

        elif 'chunked' in self.message.headers.get(
                hdrs.TRANSFER_ENCODING, ''):
            yield from self.parse_chunked_payload(out, buf)

        elif length is not None:
            try:
                length = int(length)
            except ValueError:
                raise errors.InvalidHeader(hdrs.CONTENT_LENGTH) from None

            if length < 0:
                raise errors.InvalidHeader(hdrs.CONTENT_LENGTH)
            elif length > 0:
                yield from self.parse_length_payload(out, buf, length)
        else:
            if self.readall and getattr(self.message, 'code', 0) != 204:
                yield from self.parse_eof_payload(out, buf)
            elif getattr(self.message, 'method', None) in ('PUT', 'POST'):
                internal_logger.warning(  # pragma: no cover
                    'Content-Length or Transfer-Encoding header is required')

        out.feed_eof()

    def parse_chunked_payload(self, out, buf):
        """Chunked transfer encoding parser."""
        while True:
            # read next chunk size
            line = yield from buf.readuntil(b'\r\n', 8192)

            i = line.find(b';')
            if i >= 0:
                line = line[:i]  # strip chunk-extensions
            else:
                line = line.strip()
            try:
                size = int(line, 16)
            except ValueError:
                raise errors.TransferEncodingError(line) from None

            if size == 0:  # eof marker
                break

            # read chunk and feed buffer
            while size:
                chunk = yield from buf.readsome(size)
                out.feed_data(chunk, len(chunk))
                size = size - len(chunk)

            # toss the CRLF at the end of the chunk
            yield from buf.skip(2)

        # read and discard trailer up to the CRLF terminator
        yield from buf.skipuntil(b'\r\n')

    def parse_length_payload(self, out, buf, length=0):
        """Read specified amount of bytes."""
        required = length
        while required:
            chunk = yield from buf.readsome(required)
            out.feed_data(chunk, len(chunk))
            required -= len(chunk)

    def parse_eof_payload(self, out, buf):
        """Read all bytes until eof."""
        try:
            while True:
                chunk = yield from buf.readsome()
                out.feed_data(chunk, len(chunk))
        except aiohttp.EofStream:
            pass


class DeflateBuffer:
    """DeflateStream decompress stream and feed data into specified stream."""

    def __init__(self, out, encoding):
        self.out = out
        self.size = 0
        zlib_mode = (16 + zlib.MAX_WBITS
                     if encoding == 'gzip' else -zlib.MAX_WBITS)

        self.zlib = zlib.decompressobj(wbits=zlib_mode)

    def feed_data(self, chunk, size):
        self.size += size
        try:
            chunk = self.zlib.decompress(chunk)
        except Exception:
            raise errors.ContentEncodingError('deflate')

        if chunk:
            self.out.feed_data(chunk, len(chunk))

    def feed_eof(self):
        chunk = self.zlib.flush()

        if chunk or self.size > 0:
            self.out.feed_data(chunk, len(chunk))
            if not self.zlib.eof:
                raise errors.ContentEncodingError('deflate')

        self.out.feed_eof()


class WriteBuffer:

    def __init__(self, loop):
        if loop is None:
            loop = asyncio.get_event_loop()

        self.loop = loop
        self.transport = None
        self.length = None
        self.chunked = False
        self.buffer_size = 0
        self.output_length = 0

        self._buffer = []
        self._compress = None
        self._drain_waiter = None

    def set_transport(self, transport):
        self.transport = transport
        for chunk in self._buffer:
            transport.write(chunk)

        self._buffer = []

        if self._drain_maiter is not None:
            waiter, self._drain_maiter = self._drain_maiter, None
            if not waiter.done():
                waiter.set_result(None)

    def enable_chunking(self):
        self.chunked = True

    def enable_compression(self, encoding='deflate'):
        zlib_mode = (16 + zlib.MAX_WBITS
                     if encoding == 'gzip' else -zlib.MAX_WBITS)
        self._compress = zlib.compressobj(wbits=zlib_mode)

    def write(self, chunk, *, drain=True):
        """Writes chunk of data to a stream.

        write_eof() indicates end of stream.
        writer can't be used after write_eof() method being called.
        write() return drain future.
        """
        assert isinstance(chunk, (bytes, bytearray, memoryview)), \
            'chunk argument must be a bytes-like object, not %r' % \
            type(chunk).__name__

        if self._compress is not None:
            chunk = self._compress.compress(chunk)
            if not chunk:
                return ()

        if self.length is not None:
            chunk_len = len(chunk)
            if self.length >= chunk_len:
                self.length = self.length - chunk_len
            else:
                chunk = chunk[:self.length]
                self.length = 0
                if not chunk:
                    return ()

        if self.chunked:
            chunk_len = ('%x\r\n' % len(chunk)).encode('ascii')
            chunk = chunk_len + chunk + b'\r\n'

        if chunk:
            size = len(chunk)
            self.buffer_size += size
            self.output_length += size
            if self.transport is not None:
                self.transport.write(chunk)
            else:
                self._buffer.append(chunk)

            if self.buffer_size > 64 * 1024 and drain:
                self.buffer_size = 0
                return self.drain()

        return ()

    def write_data(self, chunk):
        size = len(chunk)
        self.buffer_size += size
        self.output_length += size
        if self.transport is not None:
            self.transport.write(chunk)
        else:
            self._buffer.append(chunk)

    def write_eof(self):
        chunk = None
        if self._compress:
            chunk = self._compress.flush()
            if chunk and self.chunked:
                chunk_len = ('%x\r\n' % len(chunk)).encode('ascii')
                chunk = chunk_len + chunk + b'\r\n0\r\n\r\n'
                self.output_length += len(chunk)
        else:
            if self.chunked:
                chunk = b'0\r\n\r\n'
                self.output_length += 5

        if chunk:
            if self.transport is not None:
                self.transport.write(chunk)
            else:
                self._buffer.append(chunk)

        return self.drain()

    @asyncio.coroutine
    def drain(self):
        if self.transport is not None:
            yield from self.transport.drain()
        else:
            if self._buffer:
                if self._drain_waiter is None:
                    self._drain_waiter = create_future(self._loop)

                yield from self._drain_waiter


class HttpMessage(ABC, WriteBuffer):
    """HttpMessage allows to write headers and payload to a stream."""

    HOP_HEADERS = None  # Must be set by subclass.

    SERVER_SOFTWARE = 'Python/{0[0]}.{0[1]} aiohttp/{1}'.format(
        sys.version_info, aiohttp.__version__)

    upgrade = False  # Connection: UPGRADE
    websocket = False  # Upgrade: WEBSOCKET
    has_chunked_hdr = False  # Transfer-encoding: chunked

    def __init__(self, transport, version, close, loop=None):
        super().__init__(loop)

        self.transport = transport
        self._version = version
        self.closing = close
        self.keepalive = None
        self.length = None
        self.headers = CIMultiDict()
        self.headers_sent = False
        self._cache = {}

    @property
    @abstractmethod
    def status_line(self):
        return b''

    @abstractmethod
    def autochunked(self):
        return False

    @property
    def version(self):
        return self._version

    @property
    def body_length(self):
        return self.output_length

    def force_close(self):
        self.closing = True
        self.keepalive = False

    def keep_alive(self):
        if self.keepalive is None:
            if self.version < HttpVersion10:
                # keep alive not supported at all
                return False
            if self.version == HttpVersion10:
                if self.headers.get(hdrs.CONNECTION) == 'keep-alive':
                    return True
                else:  # no headers means we close for Http 1.0
                    return False
            else:
                return not self.closing
        else:
            return self.keepalive

    def is_headers_sent(self):
        return self.headers_sent

    def add_header(self, name, value):
        """Analyze headers. Calculate content length,
        removes hop headers, etc."""
        assert not self.headers_sent, 'headers have been sent already'
        assert isinstance(name, str), \
            'Header name should be a string, got {!r}'.format(name)
        assert set(name).issubset(ASCIISET), \
            'Header name should contain ASCII chars, got {!r}'.format(name)
        assert isinstance(value, str), \
            'Header {!r} should have string value, got {!r}'.format(
                name, value)

        name = istr(name)
        value = value.strip()

        if name == hdrs.CONTENT_LENGTH:
            self.length = int(value)

        if name == hdrs.TRANSFER_ENCODING:
            self.has_chunked_hdr = value.lower().strip() == 'chunked'

        if name == hdrs.CONNECTION:
            val = value.lower()
            # handle websocket
            if 'upgrade' in val:
                self.upgrade = True
            # connection keep-alive
            elif 'close' in val:
                self.keepalive = False
            elif 'keep-alive' in val:
                self.keepalive = True

        elif name == hdrs.UPGRADE:
            if 'websocket' in value.lower():
                self.websocket = True
            self.headers[name] = value

        elif name not in self.HOP_HEADERS:
            # ignore hop-by-hop headers
            self.headers.add(name, value)

    def add_headers(self, *headers):
        """Adds headers to a HTTP message."""
        for name, value in headers:
            self.add_header(name, value)

    def send_headers(self, _sep=': ', _end='\r\n'):
        """Writes headers to a stream. Constructs payload writer."""
        # Chunked response is only for HTTP/1.1 clients or newer
        # and there is no Content-Length header is set.
        # Do not use chunked responses when the response is guaranteed to
        # not have a response body (304, 204).
        assert not self.headers_sent, 'headers have been sent already'
        self.headers_sent = True

        if not self.chunked and self.autochunked():
            self.enable_chunking()

        if self.chunked:
            self.headers[hdrs.TRANSFER_ENCODING] = 'chunked'

        self._add_default_headers()

        # status + headers
        headers = self.status_line + ''.join(
            [k + _sep + v + _end for k, v in self.headers.items()])
        headers = headers.encode('utf-8') + b'\r\n'

        self.write_data(headers)

    def _add_default_headers(self):
        # set the connection header
        connection = None
        if self.upgrade:
            connection = 'Upgrade'
        elif not self.closing if self.keepalive is None else self.keepalive:
            if self.version == HttpVersion10:
                connection = 'keep-alive'
        else:
            if self.version == HttpVersion11:
                connection = 'close'

        if connection is not None:
            self.headers[hdrs.CONNECTION] = connection


class Response(HttpMessage):
    """Create HTTP response message.

    Transport is a socket stream transport. status is a response status code,
    status has to be integer value. http_version is a tuple that represents
    HTTP version, (1, 0) stands for HTTP/1.0 and (1, 1) is for HTTP/1.1
    """

    HOP_HEADERS = ()

    @staticmethod
    def calc_reason(status, *, _RESPONSES=RESPONSES):
        record = _RESPONSES.get(status)
        if record is not None:
            reason = record[0]
        else:
            reason = str(status)
        return reason

    def __init__(self, transport, status,
                 http_version=HttpVersion11,
                 close=False, reason=None, loop=None):
        super().__init__(transport, http_version, close, loop=loop)

        self._status = status
        if reason is None:
            reason = self.calc_reason(status)

        self._reason = reason

    @property
    def status(self):
        return self._status

    @property
    def reason(self):
        return self._reason

    @property
    def status_line(self):
        version = self.version
        return 'HTTP/{}.{} {} {}\r\n'.format(
            version[0], version[1], self.status, self.reason)

    def autochunked(self):
        return (self.length is None and
                self._version >= HttpVersion11 and
                self.status not in (304, 204))

    def _add_default_headers(self):
        super()._add_default_headers()

        if hdrs.DATE not in self.headers:
            # format_date_time(None) is quite expensive
            self.headers.setdefault(hdrs.DATE, format_date_time(None))
        self.headers.setdefault(hdrs.SERVER, self.SERVER_SOFTWARE)


class WebResponse(Response):
    """For usage in aiohttp.web only"""

    def _add_default_headers(self):
        pass


class Request(HttpMessage):

    HOP_HEADERS = ()

    def __init__(self, transport, method, path,
                 http_version=HttpVersion11, close=False, loop=None):
        # set the default for HTTP 0.9 to be different
        # will only be overwritten with keep-alive header
        if http_version < HttpVersion10:
            close = True

        super().__init__(transport, http_version, close, loop=loop)

        self._method = method
        self._path = path

    @property
    def method(self):
        return self._method

    @property
    def path(self):
        return self._path

    @property
    def status_line(self):
        return '{0} {1} HTTP/{2[0]}.{2[1]}\r\n'.format(
            self.method, self.path, self.version)

    def autochunked(self):
        return (self.length is None and
                self._version >= HttpVersion11)
