"""Http related parsers and protocol."""

import asyncio
import collections
import http.server
import string
import sys
import zlib
from urllib.parse import SplitResult
from wsgiref.handlers import format_date_time

import yarl
from multidict import CIMultiDict, istr

import aiohttp

from . import hdrs
from .helpers import create_future, noop

__all__ = ('RESPONSES', 'SERVER_SOFTWARE',
           'HttpMessage', 'Request', 'Response', 'PayloadWriter',
           'HttpVersion', 'HttpVersion10', 'HttpVersion11')

ASCIISET = set(string.printable)
SERVER_SOFTWARE = 'Python/{0[0]}.{0[1]} aiohttp/{1}'.format(
    sys.version_info, aiohttp.__version__)

RESPONSES = http.server.BaseHTTPRequestHandler.responses

HttpVersion = collections.namedtuple(
    'HttpVersion', ['major', 'minor'])
HttpVersion10 = HttpVersion(1, 0)
HttpVersion11 = HttpVersion(1, 1)


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
                return noop()

        if self.length is not None:
            chunk_len = len(chunk)
            if self.length >= chunk_len:
                self.length = self.length - chunk_len
            else:
                chunk = chunk[:self.length]
                self.length = 0
                if not chunk:
                    return noop()

        if chunk:
            if self.chunked:
                chunk_len = ('%x\r\n' % len(chunk)).encode('ascii')
                chunk = chunk_len + chunk + b'\r\n'

            self._write(chunk)

            if self.buffer_size > LIMIT and drain:
                self.buffer_size = 0
                return self.drain()

        return noop()

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


class HttpMessage(PayloadWriter):
    """HttpMessage allows to write headers and payload to a stream."""

    HOP_HEADERS = None  # Must be set by subclass.

    SERVER_SOFTWARE = 'Python/{0[0]}.{0[1]} aiohttp/{1}'.format(
        sys.version_info, aiohttp.__version__)

    upgrade = False  # Connection: UPGRADE
    websocket = False  # Upgrade: WEBSOCKET
    has_chunked_hdr = False  # Transfer-encoding: chunked

    def __init__(self, transport, version, close, loop=None):
        super().__init__(transport, loop)

        self.version = version
        self.closing = close
        self.keepalive = None
        self.length = None
        self.headers = CIMultiDict()
        self.headers_sent = False

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

    def __init__(self, transport, status,
                 http_version=HttpVersion11,
                 close=False, reason=None, loop=None, _RESPONSES=RESPONSES):
        super().__init__(transport, http_version, close, loop=loop)

        self.status = status
        if reason is None:
            try:
                reason = _RESPONSES[status][0]
            except:
                reason = ''

        self.reason = reason

    @property
    def status_line(self):
        version = self.version
        return 'HTTP/{}.{} {} {}\r\n'.format(
            version[0], version[1], self.status, self.reason)

    def autochunked(self):
        return (self.length is None and
                self.version >= HttpVersion11 and
                self.status not in (304, 204))

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

        self.method = method
        self.path = path

    @property
    def status_line(self):
        return '{0} {1} HTTP/{2[0]}.{2[1]}\r\n'.format(
            self.method, self.path, self.version)

    def autochunked(self):
        return (self.length is None and
                self.version >= HttpVersion11)


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
