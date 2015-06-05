"""Http related parsers and protocol."""

import collections
import functools
import http.server
import itertools
import re
import string
import sys
import zlib
from wsgiref.handlers import format_date_time

import aiohttp
from . import errors, hdrs
from .multidict import CIMultiDict
from .log import internal_logger

__all__ = ('HttpMessage', 'Request', 'Response',
           'HttpVersion', 'HttpVersion10', 'HttpVersion11',
           'RawRequestMessage', 'RawResponseMessage',
           'HttpPrefixParser', 'HttpRequestParser', 'HttpResponseParser',
           'HttpPayloadParser')

ASCIISET = set(string.printable)
METHRE = re.compile('[A-Z0-9$-_.]+')
VERSRE = re.compile('HTTP/(\d+).(\d+)')
HDRRE = re.compile('[\x00-\x1F\x7F()<>@,;:\[\]={} \t\\\\\"]')
CONTINUATION = (' ', '\t')
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
    ['method', 'path', 'version', 'headers', 'should_close', 'compression'])


RawResponseMessage = collections.namedtuple(
    'RawResponseMessage',
    ['version', 'code', 'reason', 'headers', 'should_close', 'compression'])


class HttpParser:

    def __init__(self, max_line_size=8190, max_headers=32768,
                 max_field_size=8190):
        self.max_line_size = max_line_size
        self.max_headers = max_headers
        self.max_field_size = max_field_size

    def parse_headers(self, lines):
        """Parses RFC2822 headers from a stream.

        Line continuations are supported. Returns list of header name
        and value pairs. Header name is in upper case.
        """
        close_conn = None
        encoding = None
        headers = CIMultiDict()

        lines_idx = 1
        line = lines[1]

        while line:
            header_length = len(line)

            # Parse initial header name : value pair.
            try:
                name, value = line.split(':', 1)
            except ValueError:
                raise errors.InvalidHeader(line) from None

            name = name.strip(' \t').upper()
            if HDRRE.search(name):
                raise errors.InvalidHeader(name)

            # next line
            lines_idx += 1
            line = lines[lines_idx]

            # consume continuation lines
            continuation = line and line[0] in CONTINUATION

            if continuation:
                value = [value]
                while continuation:
                    header_length += len(line)
                    if header_length > self.max_field_size:
                        raise errors.LineTooLong(
                            'limit request headers fields size')
                    value.append(line)

                    # next line
                    lines_idx += 1
                    line = lines[lines_idx]
                    continuation = line[0] in CONTINUATION
                value = '\r\n'.join(value)
            else:
                if header_length > self.max_field_size:
                    raise errors.LineTooLong(
                        'limit request headers fields size')

            value = value.strip()

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

        return headers, close_conn, encoding


class HttpPrefixParser:
    """Waits for 'HTTP' prefix (non destructive)"""

    def __init__(self, allowed_methods=()):
        self.allowed_methods = [m.upper() for m in allowed_methods]

    def __call__(self, out, buf):
        raw_data = yield from buf.waituntil(b' ', 12)
        method = raw_data.decode('ascii', 'surrogateescape').strip()

        # method
        method = method.upper()
        if not METHRE.match(method):
            raise errors.BadStatusLine(method)

        # allowed method
        if self.allowed_methods and method not in self.allowed_methods:
            raise errors.HttpMethodNotAllowed(message=method)

        out.feed_data(method, len(method))
        out.feed_eof()


class HttpRequestParser(HttpParser):
    """Read request status line. Exception errors.BadStatusLine
    could be raised in case of any errors in status line.
    Returns RawRequestMessage.
    """

    def __call__(self, out, buf):
        # read http message (request line + headers)
        try:
            raw_data = yield from buf.readuntil(
                b'\r\n\r\n', self.max_headers)
        except errors.LineLimitExceededParserError as exc:
            raise errors.LineTooLong(exc.limit) from None

        lines = raw_data.decode(
            'utf-8', 'surrogateescape').split('\r\n')

        # request line
        line = lines[0]
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
        headers, close, compression = self.parse_headers(lines)
        if close is None:  # then the headers weren't set in the request
            if version <= HttpVersion10:  # HTTP 1.0 must asks to not close
                close = True
            else:  # HTTP 1.1 must ask to close.
                close = False

        out.feed_data(
            RawRequestMessage(
                method, path, version, headers, close, compression),
            len(raw_data))
        out.feed_eof()


class HttpResponseParser(HttpParser):
    """Read response status line and headers.

    BadStatusLine could be raised in case of any errors in status line.
    Returns RawResponseMessage"""

    def __call__(self, out, buf):
        # read http message (response line + headers)
        try:
            raw_data = yield from buf.readuntil(
                b'\r\n\r\n', self.max_line_size + self.max_headers)
        except errors.LineLimitExceededParserError as exc:
            raise errors.LineTooLong(exc.limit) from None

        lines = raw_data.decode(
            'utf-8', 'surrogateescape').split('\r\n')

        line = lines[0]
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
        headers, close, compression = self.parse_headers(lines)

        if close is None:
            close = version <= HttpVersion10

        out.feed_data(
            RawResponseMessage(
                version, status, reason.strip(),
                headers, close, compression),
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
        if self.compression and self.message.compression:
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
        zlib_mode = (16 + zlib.MAX_WBITS
                     if encoding == 'gzip' else -zlib.MAX_WBITS)

        self.zlib = zlib.decompressobj(wbits=zlib_mode)

    def feed_data(self, chunk, size):
        try:
            chunk = self.zlib.decompress(chunk)
        except Exception:
            raise errors.ContentEncodingError('deflate')

        if chunk:
            self.out.feed_data(chunk, len(chunk))

    def feed_eof(self):
        chunk = self.zlib.flush()
        self.out.feed_data(chunk, len(chunk))
        if not self.zlib.eof:
            raise errors.ContentEncodingError('deflate')

        self.out.feed_eof()


def wrap_payload_filter(func):
    """Wraps payload filter and piped filters.

    Filter is a generator that accepts arbitrary chunks of data,
    modify data and emit new stream of data.

    For example we have stream of chunks: ['1', '2', '3', '4', '5'],
    we can apply chunking filter to this stream:

    ['1', '2', '3', '4', '5']
      |
    response.add_chunking_filter(2)
      |
    ['12', '34', '5']

    It is possible to use different filters at the same time.

    For a example to compress incoming stream with 'deflate' encoding
    and then split data and emit chunks of 8192 bytes size chunks:

      >>> response.add_compression_filter('deflate')
      >>> response.add_chunking_filter(8192)

    Filters do not alter transfer encoding.

    Filter can receive types types of data, bytes object or EOF_MARKER.

      1. If filter receives bytes object, it should process data
         and yield processed data then yield EOL_MARKER object.
      2. If Filter received EOF_MARKER, it should yield remaining
         data (buffered) and then yield EOF_MARKER.
    """
    @functools.wraps(func)
    def wrapper(self, *args, **kw):
        new_filter = func(self, *args, **kw)

        filter = self.filter
        if filter is not None:
            next(new_filter)
            self.filter = filter_pipe(filter, new_filter)
        else:
            self.filter = new_filter

        next(self.filter)

    return wrapper


def filter_pipe(filter, filter2, *,
                EOF_MARKER=EOF_MARKER, EOL_MARKER=EOL_MARKER):
    """Creates pipe between two filters.

    filter_pipe() feeds first filter with incoming data and then
    send yielded from first filter data into filter2, results of
    filter2 are being emitted.

      1. If filter_pipe receives bytes object, it sends it to the first filter.
      2. Reads yielded values from the first filter until it receives
         EOF_MARKER or EOL_MARKER.
      3. Each of this values is being send to second filter.
      4. Reads yielded values from second filter until it receives EOF_MARKER
         or EOL_MARKER. Each of this values yields to writer.
    """
    chunk = yield

    while True:
        eof = chunk is EOF_MARKER
        chunk = filter.send(chunk)

        while chunk is not EOL_MARKER:
            chunk = filter2.send(chunk)

            while chunk not in (EOF_MARKER, EOL_MARKER):
                yield chunk
                chunk = next(filter2)

            if chunk is not EOF_MARKER:
                if eof:
                    chunk = EOF_MARKER
                else:
                    chunk = next(filter)
            else:
                break

        chunk = yield EOL_MARKER


class HttpMessage:
    """HttpMessage allows to write headers and payload to a stream.

    For example, lets say we want to read file then compress it with deflate
    compression and then send it with chunked transfer encoding, code may look
    like this:

       >>> response = aiohttp.Response(transport, 200)

    We have to use deflate compression first:

      >>> response.add_compression_filter('deflate')

    Then we want to split output stream into chunks of 1024 bytes size:

      >>> response.add_chunking_filter(1024)

    We can add headers to response with add_headers() method. add_headers()
    does not send data to transport, send_headers() sends request/response
    line and then sends headers:

      >>> response.add_headers(
      ...     ('Content-Disposition', 'attachment; filename="..."'))
      >>> response.send_headers()

    Now we can use chunked writer to write stream to a network stream.
    First call to write() method sends response status line and headers,
    add_header() and add_headers() method unavailable at this stage:

    >>> with open('...', 'rb') as f:
    ...     chunk = fp.read(8192)
    ...     while chunk:
    ...         response.write(chunk)
    ...         chunk = fp.read(8192)

    >>> response.write_eof()

    """

    writer = None

    # 'filter' is being used for altering write() behaviour,
    # add_chunking_filter adds deflate/gzip compression and
    # add_compression_filter splits incoming data into a chunks.
    filter = None

    HOP_HEADERS = None  # Must be set by subclass.

    SERVER_SOFTWARE = 'Python/{0[0]}.{0[1]} aiohttp/{1}'.format(
        sys.version_info, aiohttp.__version__)

    status = None
    status_line = b''
    upgrade = False  # Connection: UPGRADE
    websocket = False  # Upgrade: WEBSOCKET
    has_chunked_hdr = False  # Transfer-encoding: chunked

    # subclass can enable auto sending headers with write() call,
    # this is useful for wsgi's start_response implementation.
    _send_headers = False

    def __init__(self, transport, version, close):
        self.transport = transport
        self.version = version
        self.closing = close
        self.keepalive = None
        self.chunked = False
        self.length = None
        self.headers = CIMultiDict()
        self.headers_sent = False
        self.output_length = 0
        self._output_size = 0

    def force_close(self):
        self.closing = True
        self.keepalive = False

    def enable_chunked_encoding(self):
        self.chunked = True

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

        name = name.strip().upper()
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
        """Adds headers to a http message."""
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

        if self.chunked or (self.length is None and
                            self.version >= HttpVersion11 and
                            self.status not in (304, 204)):
            self.writer = self._write_chunked_payload()
            self.headers[hdrs.TRANSFER_ENCODING] = 'chunked'

        elif self.length is not None:
            self.writer = self._write_length_payload(self.length)

        else:
            self.writer = self._write_eof_payload()

        next(self.writer)

        self._add_default_headers()

        # status + headers
        headers = ''.join(itertools.chain(
            (self.status_line,),
            *((k, _sep, v, _end) for k, v in self.headers.items())))
        headers = headers.encode('utf-8') + b'\r\n'

        self.output_length += len(headers)
        self.transport.write(headers)

    def _add_default_headers(self):
        # set the connection header
        if self.upgrade:
            connection = 'upgrade'
        elif not self.closing if self.keepalive is None else self.keepalive:
            connection = 'keep-alive'
        else:
            connection = 'close'

        self.headers[hdrs.CONNECTION] = connection

    def write(self, chunk, *,
              drain=False, EOF_MARKER=EOF_MARKER, EOL_MARKER=EOL_MARKER):
        """Writes chunk of data to a stream by using different writers.

        writer uses filter to modify chunk of data.
        write_eof() indicates end of stream.
        writer can't be used after write_eof() method being called.
        write() return drain future.
        """
        assert (isinstance(chunk, (bytes, bytearray)) or
                chunk is EOF_MARKER), chunk

        size = self.output_length

        if self._send_headers and not self.headers_sent:
            self.send_headers()

        assert self.writer is not None, 'send_headers() is not called.'

        if self.filter:
            chunk = self.filter.send(chunk)
            while chunk not in (EOF_MARKER, EOL_MARKER):
                if chunk:
                    self.writer.send(chunk)
                chunk = next(self.filter)
        else:
            if chunk is not EOF_MARKER:
                self.writer.send(chunk)

        self._output_size += self.output_length - size

        if self._output_size > 64 * 1024:
            if drain:
                self._output_size = 0
                return self.transport.drain()

        return ()

    def write_eof(self):
        self.write(EOF_MARKER)
        try:
            self.writer.throw(aiohttp.EofStream())
        except StopIteration:
            pass

        return self.transport.drain()

    def _write_chunked_payload(self):
        """Write data in chunked transfer encoding."""
        while True:
            try:
                chunk = yield
            except aiohttp.EofStream:
                self.transport.write(b'0\r\n\r\n')
                self.output_length += 5
                break

            chunk = bytes(chunk)
            chunk_len = '{:x}\r\n'.format(len(chunk)).encode('ascii')
            self.transport.write(chunk_len)
            self.transport.write(chunk)
            self.transport.write(b'\r\n')
            self.output_length += len(chunk_len) + len(chunk) + 2

    def _write_length_payload(self, length):
        """Write specified number of bytes to a stream."""
        while True:
            try:
                chunk = yield
            except aiohttp.EofStream:
                break

            if length:
                l = len(chunk)
                if length >= l:
                    self.transport.write(chunk)
                    self.output_length += l
                    length = length-l
                else:
                    self.transport.write(chunk[:length])
                    self.output_length += length
                    length = 0

    def _write_eof_payload(self):
        while True:
            try:
                chunk = yield
            except aiohttp.EofStream:
                break

            self.transport.write(chunk)
            self.output_length += len(chunk)

    @wrap_payload_filter
    def add_chunking_filter(self, chunk_size=16*1024, *,
                            EOF_MARKER=EOF_MARKER, EOL_MARKER=EOL_MARKER):
        """Split incoming stream into chunks."""
        buf = bytearray()
        chunk = yield

        while True:
            if chunk is EOF_MARKER:
                if buf:
                    yield buf

                yield EOF_MARKER

            else:
                buf.extend(chunk)

                while len(buf) >= chunk_size:
                    chunk = bytes(buf[:chunk_size])
                    del buf[:chunk_size]
                    yield chunk

                chunk = yield EOL_MARKER

    @wrap_payload_filter
    def add_compression_filter(self, encoding='deflate', *,
                               EOF_MARKER=EOF_MARKER, EOL_MARKER=EOL_MARKER):
        """Compress incoming stream with deflate or gzip encoding."""
        zlib_mode = (16 + zlib.MAX_WBITS
                     if encoding == 'gzip' else -zlib.MAX_WBITS)
        zcomp = zlib.compressobj(wbits=zlib_mode)

        chunk = yield
        while True:
            if chunk is EOF_MARKER:
                yield zcomp.flush()
                chunk = yield EOF_MARKER

            else:
                yield zcomp.compress(chunk)
                chunk = yield EOL_MARKER


class Response(HttpMessage):
    """Create http response message.

    Transport is a socket stream transport. status is a response status code,
    status has to be integer value. http_version is a tuple that represents
    http version, (1, 0) stands for HTTP/1.0 and (1, 1) is for HTTP/1.1
    """

    HOP_HEADERS = ()

    @staticmethod
    def calc_reason(status):
        record = RESPONSES.get(status)
        if record is not None:
            reason = record[0]
        else:
            reason = str(status)
        return reason

    def __init__(self, transport, status,
                 http_version=HttpVersion11, close=False, reason=None):
        super().__init__(transport, http_version, close)

        self.status = status
        if reason is None:
            reason = self.calc_reason(status)

        self.reason = reason
        self.status_line = 'HTTP/{}.{} {} {}\r\n'.format(
            http_version[0], http_version[1], status, reason)

    def _add_default_headers(self):
        super()._add_default_headers()

        if hdrs.DATE not in self.headers:
            # format_date_time(None) is quite expensive
            self.headers.setdefault(hdrs.DATE, format_date_time(None))
        self.headers.setdefault(hdrs.SERVER, self.SERVER_SOFTWARE)


class Request(HttpMessage):

    HOP_HEADERS = ()

    def __init__(self, transport, method, path,
                 http_version=HttpVersion11, close=False):
        # set the default for HTTP 1.0 to be different
        # will only be overwritten with keep-alive header
        if http_version < HttpVersion11:
            close = True

        super().__init__(transport, http_version, close)

        self.method = method
        self.path = path
        self.status_line = '{0} {1} HTTP/{2[0]}.{2[1]}\r\n'.format(
            method, path, http_version)

    def _add_default_headers(self):
        super()._add_default_headers()

        self.headers.setdefault(hdrs.USER_AGENT, self.SERVER_SOFTWARE)
