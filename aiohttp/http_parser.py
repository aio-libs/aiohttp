import collections
import re
import string
import zlib
from enum import IntEnum

import yarl
from multidict import CIMultiDict

from . import hdrs
from .helpers import NO_EXTENSIONS
from .http_exceptions import (BadStatusLine, ContentEncodingError,
                              ContentLengthError, InvalidHeader, LineTooLong,
                              TransferEncodingError)
from .http_writer import HttpVersion, HttpVersion10
from .log import internal_logger
from .streams import EMPTY_PAYLOAD, FlowControlStreamReader


__all__ = (
    'HttpParser', 'HttpRequestParser', 'HttpResponseParser',
    'RawRequestMessage', 'RawResponseMessage')

ASCIISET = set(string.printable)
METHRE = re.compile('[A-Z0-9$-_.]+')
VERSRE = re.compile(r'HTTP/(\d+).(\d+)')
HDRRE = re.compile(rb'[\x00-\x1F\x7F()<>@,;:\[\]={} \t\\\\\"]')

RawRequestMessage = collections.namedtuple(
    'RawRequestMessage',
    ['method', 'path', 'version', 'headers', 'raw_headers',
     'should_close', 'compression', 'upgrade', 'chunked', 'url'])

RawResponseMessage = collections.namedtuple(
    'RawResponseMessage',
    ['version', 'code', 'reason', 'headers', 'raw_headers',
     'should_close', 'compression', 'upgrade', 'chunked'])


class ParseState(IntEnum):

    PARSE_NONE = 0
    PARSE_LENGTH = 1
    PARSE_CHUNKED = 2
    PARSE_UNTIL_EOF = 3


class ChunkState(IntEnum):
    PARSE_CHUNKED_SIZE = 0
    PARSE_CHUNKED_CHUNK = 1
    PARSE_CHUNKED_CHUNK_EOF = 2
    PARSE_MAYBE_TRAILERS = 3
    PARSE_TRAILERS = 4


class HttpParser:

    def __init__(self, protocol=None, loop=None,
                 max_line_size=8190, max_headers=32768, max_field_size=8190,
                 timer=None, code=None, method=None, readall=False,
                 payload_exception=None,
                 response_with_body=True, read_until_eof=False):
        self.protocol = protocol
        self.loop = loop
        self.max_line_size = max_line_size
        self.max_headers = max_headers
        self.max_field_size = max_field_size
        self.timer = timer
        self.code = code
        self.method = method
        self.readall = readall
        self.payload_exception = payload_exception
        self.response_with_body = response_with_body
        self.read_until_eof = read_until_eof

        self._lines = []
        self._tail = b''
        self._upgraded = False
        self._payload = None
        self._payload_parser = None

    def feed_eof(self):
        if self._payload_parser is not None:
            self._payload_parser.feed_eof()
            self._payload_parser = None
        else:
            # try to extract partial message
            if self._tail:
                self._lines.append(self._tail)

            if self._lines:
                if self._lines[-1] != '\r\n':
                    self._lines.append('')
                try:
                    return self.parse_message(self._lines)
                except:
                    return None

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
                # consume \r\n
                if pos == start_pos and not self._lines:
                    start_pos = pos + 2
                    continue

                if pos >= start_pos:
                    # line found
                    self._lines.append(data[start_pos:pos])
                    start_pos = pos + 2

                    # \r\n\r\n found
                    if self._lines[-1] == EMPTY:
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
                                raise InvalidHeader(CONTENT_LENGTH)
                            if length < 0:
                                raise InvalidHeader(CONTENT_LENGTH)

                        # do not support old websocket spec
                        if SEC_WEBSOCKET_KEY1 in msg.headers:
                            raise InvalidHeader(SEC_WEBSOCKET_KEY1)

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
                            if (getattr(msg, 'code', 100) >= 199 and
                                    length is None and self.read_until_eof):
                                payload = FlowControlStreamReader(
                                    self.protocol, timer=self.timer, loop=loop)
                                payload_parser = HttpPayloadParser(
                                    payload, length=length,
                                    chunked=msg.chunked, method=method,
                                    compression=msg.compression,
                                    code=self.code, readall=True,
                                    response_with_body=self.response_with_body)
                                if not payload_parser.done:
                                    self._payload_parser = payload_parser
                            else:
                                payload = EMPTY_PAYLOAD

                        messages.append((msg, payload))
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
                try:
                    eof, data = self._payload_parser.feed_data(
                        data[start_pos:])
                except BaseException as exc:
                    if self.payload_exception is not None:
                        self._payload_parser.payload.set_exception(
                            self.payload_exception(str(exc)))
                    else:
                        self._payload_parser.payload.set_exception(exc)

                    eof = True
                    data = b''

                if eof:
                    start_pos = 0
                    data_len = len(data)
                    self._payload_parser = None
                    continue
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
                raise InvalidHeader(line) from None

            bname = bname.strip(b' \t')
            if HDRRE.search(bname):
                raise InvalidHeader(bname)

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
                        raise LineTooLong(
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
                    raise LineTooLong(
                        'request header field {}'.format(
                            bname.decode("utf8", "xmlcharrefreplace")),
                        self.max_field_size)

            bvalue = bvalue.strip()
            name = bname.decode('utf-8', 'surrogateescape')
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


class HttpRequestParserPy(HttpParser):
    """Read request status line. Exception .http_exceptions.BadStatusLine
    could be raised in case of any errors in status line.
    Returns RawRequestMessage.
    """

    def parse_message(self, lines):
        if len(lines[0]) > self.max_line_size:
            raise LineTooLong(
                'Status line is too long', self.max_line_size)

        # request line
        line = lines[0].decode('utf-8', 'surrogateescape')
        try:
            method, path, version = line.split(None, 2)
        except ValueError:
            raise BadStatusLine(line) from None

        # method
        method = method.upper()
        if not METHRE.match(method):
            raise BadStatusLine(method)

        # version
        try:
            if version.startswith('HTTP/'):
                n1, n2 = version[5:].split('.', 1)
                version = HttpVersion(int(n1), int(n2))
            else:
                raise BadStatusLine(version)
        except:
            raise BadStatusLine(version)

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


class HttpResponseParserPy(HttpParser):
    """Read response status line and headers.

    BadStatusLine could be raised in case of any errors in status line.
    Returns RawResponseMessage"""

    def parse_message(self, lines):
        if len(lines[0]) > self.max_line_size:
            raise LineTooLong(
                'Status line is too long', self.max_line_size)

        line = lines[0].decode('utf-8', 'surrogateescape')
        try:
            version, status = line.split(None, 1)
        except ValueError:
            raise BadStatusLine(line) from None
        else:
            try:
                status, reason = status.split(None, 1)
            except ValueError:
                reason = ''

        # version
        match = VERSRE.match(version)
        if match is None:
            raise BadStatusLine(line)
        version = HttpVersion(int(match.group(1)), int(match.group(2)))

        # The status code is a three-digit number
        try:
            status = int(status)
        except ValueError:
            raise BadStatusLine(line) from None

        if status > 999:
            raise BadStatusLine(line)

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
        self._type = ParseState.PARSE_NONE
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
            self._type = ParseState.PARSE_NONE
            payload.feed_eof()
            self.done = True

        elif chunked:
            self._type = ParseState.PARSE_CHUNKED
        elif length is not None:
            self._type = ParseState.PARSE_LENGTH
            self._length = length
            if self._length == 0:
                payload.feed_eof()
                self.done = True
        else:
            if readall and code != 204:
                self._type = ParseState.PARSE_UNTIL_EOF
            elif method in ('PUT', 'POST'):
                internal_logger.warning(  # pragma: no cover
                    'Content-Length or Transfer-Encoding header is required')
                self._type = ParseState.PARSE_NONE
                payload.feed_eof()
                self.done = True

        self.payload = payload

    def feed_eof(self):
        if self._type == ParseState.PARSE_UNTIL_EOF:
            self.payload.feed_eof()
        elif self._type == ParseState.PARSE_LENGTH:
            raise ContentLengthError(
                "Not enough data for satisfy content length header.")
        elif self._type == ParseState.PARSE_CHUNKED:
            raise TransferEncodingError(
                "Not enough data for satisfy transfer length header.")

    def feed_data(self, chunk, SEP=b'\r\n', CHUNK_EXT=b';'):
        # Read specified amount of bytes
        if self._type == ParseState.PARSE_LENGTH:
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
        elif self._type == ParseState.PARSE_CHUNKED:
            if self._chunk_tail:
                chunk = self._chunk_tail + chunk
                self._chunk_tail = b''

            while chunk:

                # read next chunk size
                if self._chunk == ChunkState.PARSE_CHUNKED_SIZE:
                    pos = chunk.find(SEP)
                    if pos >= 0:
                        i = chunk.find(CHUNK_EXT, 0, pos)
                        if i >= 0:
                            size = chunk[:i]  # strip chunk-extensions
                        else:
                            size = chunk[:pos]

                        try:
                            size = int(bytes(size), 16)
                        except ValueError:
                            exc = TransferEncodingError(chunk[:pos])
                            self.payload.set_exception(exc)
                            raise exc from None

                        chunk = chunk[pos+2:]
                        if size == 0:  # eof marker
                            self._chunk = ChunkState.PARSE_MAYBE_TRAILERS
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

                # if stream does not contain trailer, after 0\r\n
                # we should get another \r\n otherwise
                # trailers needs to be skiped until \r\n\r\n
                if self._chunk == ChunkState.PARSE_MAYBE_TRAILERS:
                    if chunk[:2] == SEP:
                        # end of stream
                        self.payload.feed_eof()
                        return True, chunk[2:]
                    else:
                        self._chunk = ChunkState.PARSE_TRAILERS

                # read and discard trailer up to the CRLF terminator
                if self._chunk == ChunkState.PARSE_TRAILERS:
                    pos = chunk.find(SEP)
                    if pos >= 0:
                        chunk = chunk[pos+2:]
                        self._chunk = ChunkState.PARSE_MAYBE_TRAILERS
                    else:
                        self._chunk_tail = chunk
                        return False, None

        # Read all bytes until eof
        elif self._type == ParseState.PARSE_UNTIL_EOF:
            self.payload.feed_data(chunk, len(chunk))

        return False, None


class DeflateBuffer:
    """DeflateStream decompress stream and feed data into specified stream."""

    def __init__(self, out, encoding):
        self.out = out
        self.size = 0
        self.encoding = encoding
        self._started_decoding = False

        zlib_mode = (16 + zlib.MAX_WBITS
                     if encoding == 'gzip' else -zlib.MAX_WBITS)

        self.zlib = zlib.decompressobj(wbits=zlib_mode)

    def set_exception(self, exc):
        self.out.set_exception(exc)

    def feed_data(self, chunk, size):
        self.size += size
        try:
            chunk = self.zlib.decompress(chunk)
        except Exception:
            if not self._started_decoding and self.encoding == 'deflate':
                self.zlib = zlib.decompressobj()
                try:
                    chunk = self.zlib.decompress(chunk)
                except Exception:
                    raise ContentEncodingError(
                        'Can not decode content-encoding: %s' % self.encoding)
            else:
                raise ContentEncodingError(
                    'Can not decode content-encoding: %s' % self.encoding)

        if chunk:
            self._started_decoding = True
            self.out.feed_data(chunk, len(chunk))

    def feed_eof(self):
        chunk = self.zlib.flush()

        if chunk or self.size > 0:
            self.out.feed_data(chunk, len(chunk))
            if not self.zlib.eof:
                raise ContentEncodingError('deflate')

        self.out.feed_eof()


HttpRequestParser = HttpRequestParserPy
HttpResponseParser = HttpResponseParserPy
try:
    from ._http_parser import HttpRequestParserC, HttpResponseParserC
    if not NO_EXTENSIONS:  # pragma: no cover
        HttpRequestParser = HttpRequestParserC
        HttpResponseParser = HttpResponseParserC
except ImportError:  # pragma: no cover
    pass
