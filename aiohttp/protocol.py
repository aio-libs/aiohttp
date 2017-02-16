"""Http related parsers and protocol."""

import asyncio
import collections
import http.server
import re
import string
import sys
import zlib
from abc import ABC, abstractmethod
from enum import IntEnum
from urllib.parse import SplitResult
from wsgiref.handlers import format_date_time

import yarl
from multidict import CIMultiDict, istr

import aiohttp

from . import errors, hdrs
from .helpers import create_future
from .log import internal_logger
from .streams import EMPTY_PAYLOAD, FlowControlStreamReader

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
SERVER_SOFTWARE = 'Python/{0[0]}.{0[1]} aiohttp/{1}'.format(
    sys.version_info, aiohttp.__version__)

RESPONSES = http.server.BaseHTTPRequestHandler.responses

PARSE_NONE = 0
PARSE_LENGTH = 1
PARSE_CHUNKED = 2
PARSE_UNTIL_EOF = 3


class ChunkState(IntEnum):
    PARSE_CHUNKED_SIZE = 0
    PARSE_CHUNKED_CHUNK = 1
    PARSE_CHUNKED_CHUNK_EOF = 2
    PARSE_CHUNKED_TRAILERS = 3


HttpVersion = collections.namedtuple(
    'HttpVersion', ['major', 'minor'])
HttpVersion10 = HttpVersion(1, 0)
HttpVersion11 = HttpVersion(1, 1)

RawRequestMessage = collections.namedtuple(
    'RawRequestMessage',
    ['method', 'path', 'version', 'headers', 'raw_headers',
     'should_close', 'compression', 'upgrade', 'chunked', 'url'])


RawResponseMessage = collections.namedtuple(
    'RawResponseMessage',
    ['version', 'code', 'reason', 'headers', 'raw_headers',
     'should_close', 'compression', 'upgrade', 'chunked'])


class HttpParser:

    def __init__(self, protocol=None, loop=None,
                 max_line_size=8190, max_headers=32768, max_field_size=8190,
                 timer=None, code=None, method=None,
                 readall=False, response_with_body=True):
        self.protocol = protocol
        self.loop = loop
        self.max_line_size = max_line_size
        self.max_headers = max_headers
        self.max_field_size = max_field_size
        self.timer = timer
        self.code = code
        self.method = method
        self.readall = readall
        self.response_with_body = response_with_body

        self._lines = []
        self._tail = b''
        self._upgraded = False
        self._payload = None
        self._payload_parser = None

    def feed_data(self, data,
                  SEP=b'\r\n', EMPTY=b'',
                  CONTENT_LENGTH=hdrs.CONTENT_LENGTH,
                  METH_CONNECT=hdrs.METH_CONNECT,
                  SEC_WEBSOCKET_KEY1=hdrs.SEC_WEBSOCKET_KEY1):

        messages = []

        if self._tail:
            data, self._tail = self._tail + data, b''

        data_len = len(data)
        start_pos = 0
        loop = self.loop

        while start_pos < data_len:

            # read HTTP message (request/response line + headers), \r\n\r\n
            # and split by lines
            if self._payload_parser is None and not self._upgraded:
                pos = data.find(SEP, start_pos)
                if pos >= start_pos:
                    # line found
                    self._lines.append(data[start_pos:pos])

                    # \r\n\r\n found
                    start_pos = pos + 2
                    if data[start_pos:start_pos+2] == SEP:
                        self._lines.append(EMPTY)

                        try:
                            msg = self.parse_message(self._lines)
                        finally:
                            self._lines.clear()

                        # payload length
                        length = msg.headers.get(CONTENT_LENGTH)
                        if length is not None:
                            try:
                                length = int(length)
                            except ValueError:
                                raise errors.InvalidHeader(CONTENT_LENGTH)
                            if length < 0:
                                raise errors.InvalidHeader(CONTENT_LENGTH)

                        # do not support old websocket spec
                        if SEC_WEBSOCKET_KEY1 in msg.headers:
                            raise errors.InvalidHeader(SEC_WEBSOCKET_KEY1)

                        self._upgraded = msg.upgrade

                        method = getattr(msg, 'method', self.method)

                        # calculate payload
                        if ((length is not None and length > 0) or
                                msg.chunked and not msg.upgrade):
                            payload = FlowControlStreamReader(
                                self.protocol, timer=self.timer, loop=loop)
                            payload_parser = HttpPayloadParser(
                                payload, length=length,
                                chunked=msg.chunked, method=method,
                                compression=msg.compression,
                                code=self.code, readall=self.readall,
                                response_with_body=self.response_with_body)
                            if not payload_parser.done:
                                self._payload_parser = payload_parser
                        elif method == METH_CONNECT:
                            payload = FlowControlStreamReader(
                                self.protocol, timer=self.timer, loop=loop)
                            self._upgraded = True
                            self._payload_parser = HttpPayloadParser(
                                payload, method=msg.method,
                                compression=msg.compression, readall=True)
                        else:
                            payload = EMPTY_PAYLOAD

                        messages.append((msg, payload))

                        start_pos = start_pos+2
                else:
                    self._tail = data[start_pos:]
                    data = EMPTY
                    break

            # no parser, just store
            elif self._payload_parser is None and self._upgraded:
                assert not self._lines
                break

            # feed payload
            elif data and start_pos < data_len:
                assert not self._lines
                eof, data = self._payload_parser.feed_data(
                    data[start_pos:])
                if eof:
                    start_pos = 0
                    data_len = len(data)
                    self._payload_parser = None
                    break
            else:
                break

        if data and start_pos < data_len:
            data = data[start_pos:]
        else:
            data = EMPTY

        return messages, self._upgraded, data

    def parse_headers(self, lines):
        """Parses RFC 5322 headers from a stream.

        Line continuations are supported. Returns list of header name
        and value pairs. Header name is in upper case.
        """
        headers = CIMultiDict()
        raw_headers = []

        lines_idx = 1
        line = lines[1]
        line_count = len(lines)

        while line:
            header_length = len(line)

            # Parse initial header name : value pair.
            try:
                bname, bvalue = line.split(b':', 1)
            except ValueError:
                raise errors.InvalidHeader(line) from None

            bname = bname.strip(b' \t')
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
                    if lines_idx < line_count:
                        line = lines[lines_idx]
                        if line:
                            continuation = line[0] in (32, 9)  # (' ', '\t')
                    else:
                        line = b''
                        break
                bvalue = b''.join(bvalue)
            else:
                if header_length > self.max_field_size:
                    raise errors.LineTooLong(
                        'request header field {}'.format(
                            bname.decode("utf8", "xmlcharrefreplace")),
                        self.max_field_size)

            bvalue = bvalue.strip()
            name = istr(bname.decode('utf-8', 'surrogateescape'))
            value = bvalue.decode('utf-8', 'surrogateescape')

            headers.add(name, value)
            raw_headers.append((bname, bvalue))

        close_conn = None
        encoding = None
        upgrade = False
        chunked = False
        raw_headers = tuple(raw_headers)

        # keep-alive
        conn = headers.get(hdrs.CONNECTION)
        if conn:
            v = conn.lower()
            if v == 'close':
                close_conn = True
            elif v == 'keep-alive':
                close_conn = False
            elif v == 'upgrade':
                upgrade = True

        # encoding
        enc = headers.get(hdrs.CONTENT_ENCODING)
        if enc:
            enc = enc.lower()
            if enc in ('gzip', 'deflate'):
                encoding = enc

        # chunking
        te = headers.get(hdrs.TRANSFER_ENCODING)
        if te and 'chunked' in te.lower():
            chunked = True

        return headers, raw_headers, close_conn, encoding, upgrade, chunked


class HttpRequestParser(HttpParser):
    """Read request status line. Exception errors.BadStatusLine
    could be raised in case of any errors in status line.
    Returns RawRequestMessage.
    """

    def parse_message(self, lines):
        if len(lines[0]) > self.max_line_size:
            raise errors.LineTooLong(
                'Status line is too long', self.max_line_size)

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
        headers, raw_headers, \
            close, compression, upgrade, chunked = self.parse_headers(lines)

        if close is None:  # then the headers weren't set in the request
            if version <= HttpVersion10:  # HTTP 1.0 must asks to not close
                close = True
            else:  # HTTP 1.1 must ask to close.
                close = False

        return RawRequestMessage(
            method, path, version, headers, raw_headers,
            close, compression, upgrade, chunked, yarl.URL(path))


class HttpResponseParser(HttpParser):
    """Read response status line and headers.

    BadStatusLine could be raised in case of any errors in status line.
    Returns RawResponseMessage"""

    def parse_message(self, lines):
        if len(lines[0]) > self.max_line_size:
            raise errors.LineTooLong(
                'Status line is too long', self.max_line_size)

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

        if status > 999:
            raise errors.BadStatusLine(line)

        # read headers
        headers, raw_headers, \
            close, compression, upgrade, chunked = self.parse_headers(lines)

        if close is None:
            close = version <= HttpVersion10

        return RawResponseMessage(
            version, status, reason.strip(),
            headers, raw_headers, close, compression, upgrade, chunked)


class HttpPayloadParser:

    def __init__(self, payload,
                 length=None, chunked=False, compression=None,
                 code=None, method=None,
                 readall=False, response_with_body=True):
        self.payload = payload

        self._length = 0
        self._type = PARSE_NONE
        self._chunk = ChunkState.PARSE_CHUNKED_SIZE
        self._chunk_size = 0
        self._chunk_tail = b''
        self.done = False

        # payload decompression wrapper
        if (response_with_body and compression):
            payload = DeflateBuffer(payload, compression)

        # payload parser
        if not response_with_body:
            # don't parse payload if it's not expected to be received
            self._type = PARSE_NONE
            payload.feed_eof()
            self.done = True

        elif chunked:
            self._type = PARSE_CHUNKED
        elif length is not None:
            self._type = PARSE_LENGTH
            self._length = length
            if self._length == 0:
                payload.feed_eof()
                self.done = True
        else:
            if readall and code != 204:
                self._type = PARSE_UNTIL_EOF
            elif method in ('PUT', 'POST'):
                internal_logger.warning(  # pragma: no cover
                    'Content-Length or Transfer-Encoding header is required')
                self._type = PARSE_NONE
                payload.feed_eof()
                self.done = True

        self.payload = payload

    def feed_eof(self):
        if self._type == PARSE_UNTIL_EOF:
            self.payload.feed_eof()

    def feed_data(self, chunk, SEP=b'\r\n', CHUNK_EXT=b';'):
        # Read specified amount of bytes
        if self._type == PARSE_LENGTH:
            required = self._length
            chunk_len = len(chunk)

            if required >= chunk_len:
                self._length = required - chunk_len
                self.payload.feed_data(chunk, chunk_len)
                if self._length == 0:
                    self.payload.feed_eof()
                    return True, b''
            else:
                self._length = 0
                self.payload.feed_data(chunk[:required], required)
                self.payload.feed_eof()
                return True, chunk[required:]

        # Chunked transfer encoding parser
        elif self._type == PARSE_CHUNKED:
            if self._chunk_tail:
                chunk = self._chunk_tail + chunk
                self._chunk_tail = b''

            while chunk:

                # read next chunk size
                if self._chunk == ChunkState.PARSE_CHUNKED_SIZE:
                    pos = chunk.find(SEP)
                    if pos >= 0:
                        if pos > 0:
                            i = chunk.find(CHUNK_EXT, 0, pos)
                            if i >= 0:
                                size = chunk[:i]  # strip chunk-extensions
                            else:
                                size = chunk[:pos]
                        else:
                            size = chunk[:pos]

                        try:
                            size = int(size, 16)
                        except ValueError:
                            exc = errors.TransferEncodingError(chunk[:pos])
                            self.payload.set_exception(exc)
                            raise exc from None

                        chunk = chunk[pos+2:]
                        if size == 0:  # eof marker
                            self._chunk = ChunkState.PARSE_CHUNKED_TRAILERS
                        else:
                            self._chunk = ChunkState.PARSE_CHUNKED_CHUNK
                            self._chunk_size = size
                    else:
                        self._chunk_tail = chunk
                        return False, None

                # read chunk and feed buffer
                if self._chunk == ChunkState.PARSE_CHUNKED_CHUNK:
                    required = self._chunk_size
                    chunk_len = len(chunk)

                    if required >= chunk_len:
                        self._chunk_size = required - chunk_len
                        if self._chunk_size == 0:
                            self._chunk = ChunkState.PARSE_CHUNKED_CHUNK_EOF

                        self.payload.feed_data(chunk, chunk_len)
                        return False, None
                    else:
                        self._chunk_size = 0
                        self.payload.feed_data(chunk[:required], required)
                        chunk = chunk[required:]
                        self._chunk = ChunkState.PARSE_CHUNKED_CHUNK_EOF

                # toss the CRLF at the end of the chunk
                if self._chunk == ChunkState.PARSE_CHUNKED_CHUNK_EOF:
                    if chunk[:2] == SEP:
                        chunk = chunk[2:]
                        self._chunk = ChunkState.PARSE_CHUNKED_SIZE
                    else:
                        self._chunk_tail = chunk
                        return False, None

                # read and discard trailer up to the CRLF terminator
                if self._chunk == ChunkState.PARSE_CHUNKED_TRAILERS:
                    pos = chunk.find(SEP)
                    if pos >= 0:
                        self.payload.feed_eof()
                        return True, chunk[pos+2:]
                    else:
                        self._chunk_tail = chunk
                        return False, None

        # Read all bytes until eof
        elif self._type == PARSE_UNTIL_EOF:
            self.payload.feed_data(chunk, len(chunk))

        return False, None


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


class PayloadWriter:

    def __init__(self, stream, loop):
        if loop is None:
            loop = asyncio.get_event_loop()

        self._stream = stream
        self._transport = None

        self.loop = loop
        self.length = None
        self.chunked = False
        self.buffer_size = 0
        self.output_length = 0

        self._buffer = []
        self._compress = None
        self._drain_waiter = None

        if self._stream.available:
            self._transport = self._stream.transport
            self._stream.available = False
        else:
            self._stream.acquire(self.set_transport)

    def set_transport(self, transport):
        self._transport = transport

        chunk = b''.join(self._buffer)
        if chunk:
            transport.write(chunk)
            self._buffer.clear()

        if self._drain_waiter is not None:
            waiter, self._drain_maiter = self._drain_maiter, None
            if not waiter.done():
                waiter.set_result(None)

    @property
    def tcp_nodelay(self):
        return self._stream.tcp_nodelay

    def set_tcp_nodelay(self, value):
        self._stream.set_tcp_nodelay(value)

    @property
    def tcp_cork(self):
        return self._stream.tcp_cork

    def set_tcp_cork(self, value):
        self._stream.set_tcp_cork(value)

    def enable_chunking(self):
        self.chunked = True

    def enable_compression(self, encoding='deflate'):
        zlib_mode = (16 + zlib.MAX_WBITS
                     if encoding == 'gzip' else -zlib.MAX_WBITS)
        self._compress = zlib.compressobj(wbits=zlib_mode)

    def buffer_data(self, chunk):
        if chunk:
            size = len(chunk)
            self.buffer_size += size
            self.output_length += size
            self._buffer.append(chunk)

    def _write(self, chunk):
        size = len(chunk)
        self.buffer_size += size
        self.output_length += size

        if self._transport is not None:
            if self._buffer:
                self._buffer.append(chunk)
                self._transport.write(b''.join(self._buffer))
                self._buffer.clear()
            else:
                self._transport.write(chunk)
        else:
            self._buffer.append(chunk)

    def write(self, chunk, *, drain=True, LIMIT=64*1024):
        """Writes chunk of data to a stream.

        write_eof() indicates end of stream.
        writer can't be used after write_eof() method being called.
        write() return drain future.
        """
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

        if chunk:
            if self.chunked:
                chunk_len = ('%x\r\n' % len(chunk)).encode('ascii')
                chunk = chunk_len + chunk + b'\r\n'

            self._write(chunk)

            if self.buffer_size > LIMIT and drain:
                self.buffer_size = 0
                return self.drain()

        return ()

    @asyncio.coroutine
    def write_eof(self, chunk=b''):
        if self._compress:
            if chunk:
                chunk = self._compress.compress(chunk)

            chunk = chunk + self._compress.flush()
            if chunk and self.chunked:
                chunk_len = ('%x\r\n' % len(chunk)).encode('ascii')
                chunk = chunk_len + chunk + b'\r\n0\r\n\r\n'
        else:
            if self.chunked:
                if chunk:
                    chunk_len = ('%x\r\n' % len(chunk)).encode('ascii')
                    chunk = chunk_len + chunk + b'\r\n0\r\n\r\n'
                else:
                    chunk = b'0\r\n\r\n'

        if chunk:
            self.buffer_data(chunk)

        yield from self.drain(True)

        self._transport = None
        self._stream.release()

    @asyncio.coroutine
    def drain(self, last=False):
        if self._transport is not None:
            if self._buffer:
                self._transport.write(b''.join(self._buffer))
                if not last:
                    self._buffer.clear()
            yield from self._stream.drain()
        else:
            if self._buffer:
                if self._drain_waiter is None:
                    self._drain_waiter = create_future(self.loop)

                yield from self._drain_waiter


class HttpMessage(ABC, PayloadWriter):
    """HttpMessage allows to write headers and payload to a stream."""

    HOP_HEADERS = None  # Must be set by subclass.

    SERVER_SOFTWARE = 'Python/{0[0]}.{0[1]} aiohttp/{1}'.format(
        sys.version_info, aiohttp.__version__)

    upgrade = False  # Connection: UPGRADE
    websocket = False  # Upgrade: WEBSOCKET
    has_chunked_hdr = False  # Transfer-encoding: chunked

    def __init__(self, transport, version, close, loop=None):
        super().__init__(transport, loop)

        self._version = version
        self.closing = close
        self.keepalive = None
        self.length = None
        self.headers = CIMultiDict()
        self.headers_sent = False

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
            if self._version < HttpVersion10:
                # keep alive not supported at all
                return False
            if self._version == HttpVersion10:
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
            self.has_chunked_hdr = value.lower() == 'chunked'

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

        self.buffer_data(headers)

    def _add_default_headers(self):
        # set the connection header
        connection = None
        if self.upgrade:
            connection = 'Upgrade'
        elif not self.closing if self.keepalive is None else self.keepalive:
            if self._version == HttpVersion10:
                connection = 'keep-alive'
        else:
            if self._version == HttpVersion11:
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

    def __init__(self, transport, status,
                 http_version=HttpVersion11,
                 close=False, reason=None, loop=None, _RESPONSES=RESPONSES):
        super().__init__(transport, http_version, close, loop=loop)

        self._status = status
        if reason is None:
            try:
                reason = _RESPONSES[status][0]
            except:
                reason = ''

        self._reason = reason

    @property
    def status(self):
        return self._status

    @property
    def reason(self):
        return self._reason

    @property
    def status_line(self):
        version = self._version
        return 'HTTP/{}.{} {} {}\r\n'.format(
            version[0], version[1], self._status, self._reason)

    def autochunked(self):
        return (self.length is None and
                self._version >= HttpVersion11 and
                self._status not in (304, 204))

    def _add_default_headers(self):
        super()._add_default_headers()

        if hdrs.DATE not in self.headers:
            # format_date_time(None) is quite expensive
            self.headers.setdefault(hdrs.DATE, format_date_time(None))
        self.headers.setdefault(hdrs.SERVER, self.SERVER_SOFTWARE)


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
            self._method, self._path, self._version)

    def autochunked(self):
        return (self.length is None and
                self._version >= HttpVersion11)


class URL(yarl.URL):

    def __init__(self, schema, netloc, port, path, query, fragment, userinfo):
        self._strict = False

        if port:
            netloc += ':{}'.format(port)
        if userinfo:
            netloc = yarl.quote(
                userinfo, safe='@:',
                protected=':', strict=False) + '@' + netloc

        if path:
            path = yarl.quote(path, safe='@:', protected='/', strict=False)

        if query:
            query = yarl.quote(
                query, safe='=+&?/:@',
                protected=yarl.PROTECT_CHARS, qs=True, strict=False)

        if fragment:
            fragment = yarl.quote(fragment, safe='?/:@', strict=False)

        self._val = SplitResult(
            schema or '',  # scheme
            netloc=netloc, path=path, query=query, fragment=fragment)
        self._cache = {}
