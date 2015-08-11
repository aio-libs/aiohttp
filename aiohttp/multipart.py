import asyncio
import binascii
import base64
import json
import io
import mimetypes
import os
import re
import uuid
import warnings
import zlib
from urllib.parse import quote, unquote, urlencode, parse_qsl
from collections import deque, Mapping, Sequence

from .helpers import parse_mimetype
from .multidict import CIMultiDict
from .protocol import HttpParser
from .hdrs import (
    CONTENT_DISPOSITION,
    CONTENT_ENCODING,
    CONTENT_LENGTH,
    CONTENT_TRANSFER_ENCODING,
    CONTENT_TYPE
)


__all__ = ('MultipartReader', 'MultipartWriter',
           'BodyPartReader', 'BodyPartWriter',
           'BadContentDispositionHeader', 'BadContentDispositionParam',
           'parse_content_disposition', 'content_disposition_filename')


CHAR = set(chr(i) for i in range(0, 128))
CTL = set(chr(i) for i in range(0, 32)) | {chr(127), }
SEPARATORS = {'(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']',
              '?', '=', '{', '}', ' ', chr(9)}
TOKEN = CHAR ^ CTL ^ SEPARATORS


class BadContentDispositionHeader(RuntimeWarning):
    pass


class BadContentDispositionParam(RuntimeWarning):
    pass


def parse_content_disposition(header):
    def is_token(string):
        return string and TOKEN >= set(string)

    def is_quoted(string):
        return string[0] == string[-1] == '"'

    def is_rfc5987(string):
        return is_token(string) and string.count("'") == 2

    def is_extended_param(string):
        return string.endswith('*')

    def is_continuous_param(string):
        pos = string.find('*') + 1
        if not pos:
            return False
        substring = string[pos:-1] if string.endswith('*') else string[pos:]
        return substring.isdigit()

    def unescape(text, *, chars=''.join(map(re.escape, CHAR))):
        return re.sub('\\\\([{}])'.format(chars), '\\1', text)

    if not header:
        return None, {}

    disptype, *parts = header.split(';')
    if not is_token(disptype):
        warnings.warn(BadContentDispositionHeader(header))
        return None, {}

    params = {}
    for item in parts:
        if '=' not in item:
            warnings.warn(BadContentDispositionHeader(header))
            return None, {}

        key, value = item.split('=', 1)
        key = key.lower().strip()
        value = value.lstrip()

        if key in params:
            warnings.warn(BadContentDispositionHeader(header))
            return None, {}

        if not is_token(key):
            warnings.warn(BadContentDispositionParam(item))
            continue

        elif is_continuous_param(key):
            if is_quoted(value):
                value = unescape(value[1:-1])
            elif not is_token(value):
                warnings.warn(BadContentDispositionParam(item))
                continue

        elif is_extended_param(key):
            if is_rfc5987(value):
                encoding, _, value = value.split("'", 2)
                encoding = encoding or 'utf-8'
            else:
                warnings.warn(BadContentDispositionParam(item))
                continue

            try:
                value = unquote(value, encoding, 'strict')
            except UnicodeDecodeError:  # pragma: nocover
                warnings.warn(BadContentDispositionParam(item))
                continue

        else:
            if is_quoted(value):
                value = unescape(value[1:-1].lstrip('\\/'))
            elif not is_token(value):
                warnings.warn(BadContentDispositionHeader(header))
                return None, {}

        params[key] = value

    return disptype.lower(), params


def content_disposition_filename(params):
    if not params:
        return None
    elif 'filename*' in params:
        return params['filename*']
    elif 'filename' in params:
        return params['filename']
    else:
        parts = []
        fnparams = sorted((key, value)
                          for key, value in params.items()
                          if key.startswith('filename*'))
        for num, (key, value) in enumerate(fnparams):
            _, tail = key.split('*', 1)
            if tail.endswith('*'):
                tail = tail[:-1]
            if tail == str(num):
                parts.append(value)
            else:
                break
        if not parts:
            return None
        value = ''.join(parts)
        if "'" in value:
            encoding, _, value = value.split("'", 2)
            encoding = encoding or 'utf-8'
            return unquote(value, encoding, 'strict')
        return value


class MultipartResponseWrapper(object):
    """Wrapper around the :class:`MultipartBodyReader` to take care about
    underlying connection and close it when it needs in."""

    def __init__(self, resp, stream):
        self.resp = resp
        self.stream = stream

    def at_eof(self):
        """Returns ``True`` when all response data had been read.

        :rtype: bool
        """
        return self.resp.content.at_eof()

    @asyncio.coroutine
    def next(self):
        """Emits next multipart reader object."""
        item = yield from self.stream.next()
        if self.stream.at_eof():
            yield from self.release()
        return item

    @asyncio.coroutine
    def release(self):
        """Releases the connection gracefully, reading all the content
        to the void."""
        yield from self.resp.release()


class BodyPartReader(object):
    """Multipart reader for single body part."""

    chunk_size = 8192

    def __init__(self, boundary, headers, content):
        self.headers = headers
        self._boundary = boundary
        self._content = content
        self._at_eof = False
        length = self.headers.get(CONTENT_LENGTH, None)
        self._length = int(length) if length is not None else None
        self._read_bytes = 0
        self._unread = deque()

    @asyncio.coroutine
    def next(self):
        item = yield from self.read()
        if not item:
            return None
        return item

    @asyncio.coroutine
    def read(self, *, decode=False):
        """Reads body part data.

        :param bool decode: Decodes data following by encoding
                            method from `Content-Encoding` header. If it missed
                            data remains untouched

        :rtype: bytearray
        """
        if self._at_eof:
            return b''
        data = bytearray()
        if self._length is None:
            while not self._at_eof:
                data.extend((yield from self.readline()))
        else:
            while not self._at_eof:
                data.extend((yield from self.read_chunk(self.chunk_size)))
        if decode:
            return self.decode(data)
        return data

    @asyncio.coroutine
    def read_chunk(self, size=chunk_size):
        """Reads body part content chunk of the specified size.
        The body part must has `Content-Length` header with proper value.

        :param int size: chunk size

        :rtype: bytearray
        """
        if self._at_eof:
            return b''
        assert self._length is not None, \
            'Content-Length required for chunked read'
        chunk_size = min(size, self._length - self._read_bytes)
        chunk = yield from self._content.read(chunk_size)
        self._read_bytes += len(chunk)
        if self._read_bytes == self._length:
            self._at_eof = True
            assert b'\r\n' == (yield from self._content.readline()), \
                'reader did not read all the data or it is malformed'
        return chunk

    @asyncio.coroutine
    def readline(self):
        """Reads body part by line by line.

        :rtype: bytearray
        """
        if self._at_eof:
            return b''

        if self._unread:
            line = self._unread.popleft()
        else:
            line = yield from self._content.readline()

        if line.startswith(self._boundary):
            # the very last boundary may not come with \r\n,
            # so set single rules for everyone
            sline = line.rstrip(b'\r\n')
            boundary = self._boundary
            last_boundary = self._boundary + b'--'
            # ensure that we read exactly the boundary, not something alike
            if sline == boundary or sline == last_boundary:
                self._at_eof = True
                self._unread.append(line)
                return b''
        else:
            next_line = yield from self._content.readline()
            if next_line.startswith(self._boundary):
                line = line[:-2]  # strip CRLF but only once
            self._unread.append(next_line)

        return line

    @asyncio.coroutine
    def release(self):
        """Lke :meth:`read`, but reads all the data to the void.

        :rtype: None
        """
        if self._at_eof:
            return
        if self._length is None:
            while not self._at_eof:
                yield from self.readline()
        else:
            while not self._at_eof:
                yield from self.read_chunk(self.chunk_size)

    @asyncio.coroutine
    def text(self, *, encoding=None):
        """Lke :meth:`read`, but assumes that body part contains text data.

        :param str encoding: Custom text encoding. Overrides specified
                             in charset param of `Content-Type` header

        :rtype: str
        """
        data = yield from self.read(decode=True)
        encoding = encoding or self.get_charset(default='latin1')
        return data.decode(encoding)

    @asyncio.coroutine
    def json(self, *, encoding=None):
        """Lke :meth:`read`, but assumes that body parts contains JSON data.

        :param str encoding: Custom JSON encoding. Overrides specified
                             in charset param of `Content-Type` header
        """
        data = yield from self.read(decode=True)
        if not data:
            return None
        encoding = encoding or self.get_charset(default='utf-8')
        return json.loads(data.decode(encoding))

    @asyncio.coroutine
    def form(self, *, encoding=None):
        """Lke :meth:`read`, but assumes that body parts contains form
        urlencoded data.

        :param str encoding: Custom form encoding. Overrides specified
                             in charset param of `Content-Type` header
        """
        data = yield from self.read(decode=True)
        if not data:
            return None
        encoding = encoding or self.get_charset(default='utf-8')
        return parse_qsl(data.rstrip().decode(encoding), encoding=encoding)

    def at_eof(self):
        """Returns ``True`` if the boundary was reached or
        ``False`` otherwise.

        :rtype: bool
        """
        return self._at_eof

    def decode(self, data):
        """Decodes data according the specified `Content-Encoding`
        or `Content-Transfer-Encoding` headers value.

        Supports ``gzip``, ``deflate`` and ``identity`` encodings for
        `Content-Encoding` header.

        Supports ``base64``, ``quoted-printable`` encodings for
        `Content-Transfer-Encoding` header.

        :param bytearray data: Data to decode.

        :raises: :exc:`RuntimeError` - if encoding is unknown.

        :rtype: bytes
        """
        if CONTENT_TRANSFER_ENCODING in self.headers:
            data = self._decode_content_transfer(data)
        if CONTENT_ENCODING in self.headers:
            return self._decode_content(data)
        return data

    def _decode_content(self, data):
        encoding = self.headers[CONTENT_ENCODING].lower()

        if encoding == 'deflate':
            return zlib.decompress(data, -zlib.MAX_WBITS)
        elif encoding == 'gzip':
            return zlib.decompress(data, 16 + zlib.MAX_WBITS)
        elif encoding == 'identity':
            return data
        else:
            raise RuntimeError('unknown content encoding: {}'.format(encoding))

    def _decode_content_transfer(self, data):
        encoding = self.headers[CONTENT_TRANSFER_ENCODING].lower()

        if encoding == 'base64':
            return base64.b64decode(data)
        elif encoding == 'quoted-printable':
            return binascii.a2b_qp(data)
        else:
            raise RuntimeError('unknown content transfer encoding: {}'
                               ''.format(encoding))

    def get_charset(self, default=None):
        """Returns charset parameter from ``Content-Type`` header or default.
        """
        ctype = self.headers.get(CONTENT_TYPE, '')
        *_, params = parse_mimetype(ctype)
        return params.get('charset', default)

    @property
    def filename(self):
        """Returns filename specified in Content-Disposition header or ``None``
        if missed or header is malformed."""
        _, params = parse_content_disposition(
            self.headers.get(CONTENT_DISPOSITION))
        return content_disposition_filename(params)


class MultipartReader(object):
    """Multipart body reader."""

    #: Response wrapper, used when multipart readers constructs from response.
    response_wrapper_cls = MultipartResponseWrapper
    #: Multipart reader class, used to handle multipart/* body parts.
    #: None points to type(self)
    multipart_reader_cls = None
    #: Body part reader class for non multipart/* content types.
    part_reader_cls = BodyPartReader

    def __init__(self, headers, content):
        self.headers = headers
        self._boundary = ('--' + self._get_boundary()).encode()
        self._content = content
        self._last_part = None
        self._at_eof = False
        self._unread = []

    @classmethod
    def from_response(cls, response):
        """Constructs reader instance from HTTP response.

        :param response: :class:`~aiohttp.client.ClientResponse` instance
        """
        obj = cls.response_wrapper_cls(response, cls(response.headers,
                                                     response.content))
        return obj

    def at_eof(self):
        """Returns ``True`` if the final boundary was reached or
        ``False`` otherwise.

        :rtype: bool
        """
        return self._at_eof

    @asyncio.coroutine
    def next(self):
        """Emits the next multipart body part."""
        if self._at_eof:
            return
        yield from self._maybe_release_last_part()
        yield from self._read_boundary()
        if self._at_eof:  # we just read the last boundary, nothing to do there
            return
        self._last_part = yield from self.fetch_next_part()
        return self._last_part

    @asyncio.coroutine
    def release(self):
        """Reads all the body parts to the void till the final boundary."""
        while not self._at_eof:
            item = yield from self.next()
            if item is None:
                break
            yield from item.release()

    @asyncio.coroutine
    def fetch_next_part(self):
        """Returns the next body part reader."""
        headers = yield from self._read_headers()
        return self._get_part_reader(headers)

    def _get_part_reader(self, headers):
        """Dispatches the response by the `Content-Type` header, returning
        suitable reader instance.

        :param dict headers: Response headers
        """
        ctype = headers.get(CONTENT_TYPE, '')
        mtype, *_ = parse_mimetype(ctype)
        if mtype == 'multipart':
            if self.multipart_reader_cls is None:
                return type(self)(headers, self._content)
            return self.multipart_reader_cls(headers, self._content)
        else:
            return self.part_reader_cls(self._boundary, headers, self._content)

    def _get_boundary(self):
        mtype, *_, params = parse_mimetype(self.headers[CONTENT_TYPE])

        assert mtype == 'multipart', 'multipart/* content type expected'

        if 'boundary' not in params:
            raise ValueError('boundary missed for Content-Type: %s'
                             % self.headers[CONTENT_TYPE])

        boundary = params['boundary']
        if len(boundary) > 70:
            raise ValueError('boundary %r is too long (70 chars max)'
                             % boundary)

        return boundary

    @asyncio.coroutine
    def _readline(self):
        if self._unread:
            return self._unread.pop()
        return (yield from self._content.readline())

    @asyncio.coroutine
    def _read_boundary(self):
        chunk = (yield from self._readline()).rstrip()
        if chunk == self._boundary:
            pass
        elif chunk == self._boundary + b'--':
            self._at_eof = True
        else:
            raise ValueError('Invalid boundary %r, expected %r'
                             % (chunk, self._boundary))

    @asyncio.coroutine
    def _read_headers(self):
        lines = ['']
        while True:
            chunk = yield from self._content.readline()
            chunk = chunk.decode().strip()
            lines.append(chunk)
            if not chunk:
                break
        parser = HttpParser()
        headers, *_ = parser.parse_headers(lines)
        return headers

    @asyncio.coroutine
    def _maybe_release_last_part(self):
        """Ensures that the last read body part is read completely."""
        if self._last_part is not None:
            if not self._last_part.at_eof():
                yield from self._last_part.release()
            self._unread.extend(self._last_part._unread)
            self._last_part = None


class BodyPartWriter(object):
    """Multipart writer for single body part."""

    def __init__(self, obj, headers=None, *, chunk_size=8192):
        if headers is None:
            headers = CIMultiDict()
        elif not isinstance(headers, CIMultiDict):
            headers = CIMultiDict(headers)

        self.obj = obj
        self.headers = headers
        self._chunk_size = chunk_size
        self._fill_headers_with_defaults()

        self._serialize_map = {
            bytes: self._serialize_bytes,
            str: self._serialize_str,
            io.IOBase: self._serialize_io,
            MultipartWriter: self._serialize_multipart,
            ('application', 'json'): self._serialize_json,
            ('application', 'x-www-form-urlencoded'): self._serialize_form
        }

    def _fill_headers_with_defaults(self):
        if CONTENT_TYPE not in self.headers:
            content_type = self._guess_content_type(self.obj)
            if content_type is not None:
                self.headers[CONTENT_TYPE] = content_type

        if CONTENT_LENGTH not in self.headers:
            content_length = self._guess_content_length(self.obj)
            if content_length is not None:
                self.headers[CONTENT_LENGTH] = str(content_length)

        if CONTENT_DISPOSITION not in self.headers:
            filename = self._guess_filename(self.obj)
            if filename is not None:
                self.set_content_disposition('attachment', filename=filename)

    def _guess_content_length(self, obj):
        if isinstance(obj, bytes):
            return len(obj)
        elif isinstance(obj, str):
            *_, params = parse_mimetype(self.headers.get(CONTENT_TYPE))
            charset = params.get('charset', 'us-ascii')
            return len(obj.encode(charset))
        elif isinstance(obj, io.StringIO):
            *_, params = parse_mimetype(self.headers.get(CONTENT_TYPE))
            charset = params.get('charset', 'us-ascii')
            return len(obj.getvalue().encode(charset)) - obj.tell()
        elif isinstance(obj, io.BytesIO):
            return len(obj.getvalue()) - obj.tell()
        elif isinstance(obj, io.IOBase):
            try:
                return os.fstat(obj.fileno()).st_size - obj.tell()
            except (AttributeError, OSError):
                return None
        else:
            return None

    def _guess_content_type(self, obj, default='application/octet-stream'):
        if hasattr(obj, 'name'):
            name = getattr(obj, 'name')
            return mimetypes.guess_type(name)[0]
        elif isinstance(obj, (str, io.StringIO)):
            return 'text/plain; charset=utf-8'
        else:
            return default

    def _guess_filename(self, obj):
        if isinstance(obj, io.IOBase):
            name = getattr(obj, 'name', None)
            if name is not None:
                return os.path.basename(name)

    def serialize(self):
        """Yields byte chunks for body part."""

        has_encoding = (
            CONTENT_ENCODING in self.headers
            and self.headers[CONTENT_ENCODING] != 'identity'
            or CONTENT_TRANSFER_ENCODING in self.headers
        )
        if has_encoding:
            # since we're following streaming approach which doesn't assumes
            # any intermediate buffers, we cannot calculate real content length
            # with the specified content encoding scheme. So, instead of lying
            # about content length and cause reading issues, we have to strip
            # this information.
            self.headers.pop(CONTENT_LENGTH, None)

        if self.headers:
            yield b'\r\n'.join(
                b': '.join(map(lambda i: i.encode('latin1'), item))
                for item in self.headers.items()
            )
        yield b'\r\n\r\n'
        yield from self._maybe_encode_stream(self._serialize_obj())
        yield b'\r\n'

    def _serialize_obj(self):
        obj = self.obj
        mtype, stype, *_ = parse_mimetype(self.headers.get(CONTENT_TYPE))
        serializer = self._serialize_map.get((mtype, stype))
        if serializer is not None:
            return serializer(obj)

        for key in self._serialize_map:
            if not isinstance(key, tuple) and isinstance(obj, key):
                return self._serialize_map[key](obj)
        return self._serialize_default(obj)

    def _serialize_bytes(self, obj):
        yield obj

    def _serialize_str(self, obj):
        *_, params = parse_mimetype(self.headers.get(CONTENT_TYPE))
        yield obj.encode(params.get('charset', 'us-ascii'))

    def _serialize_io(self, obj):
        while True:
            chunk = obj.read(self._chunk_size)
            if not chunk:
                break
            if isinstance(chunk, str):
                yield from self._serialize_str(chunk)
            else:
                yield from self._serialize_bytes(chunk)

    def _serialize_multipart(self, obj):
        yield from obj.serialize()

    def _serialize_json(self, obj):
        *_, params = parse_mimetype(self.headers.get(CONTENT_TYPE))
        yield json.dumps(obj).encode(params.get('charset', 'utf-8'))

    def _serialize_form(self, obj):
        if isinstance(obj, Mapping):
            obj = list(obj.items())
        return self._serialize_str(urlencode(obj, doseq=True))

    def _serialize_default(self, obj):
        raise TypeError('unknown body part type %r' % type(obj))

    def _maybe_encode_stream(self, stream):
        if CONTENT_ENCODING in self.headers:
            stream = self._apply_content_encoding(stream)
        if CONTENT_TRANSFER_ENCODING in self.headers:
            stream = self._apply_content_transfer_encoding(stream)
        yield from stream

    def _apply_content_encoding(self, stream):
        encoding = self.headers[CONTENT_ENCODING].lower()
        if encoding == 'identity':
            yield from stream
        elif encoding in ('deflate', 'gzip'):
            zlib_mode = (16 + zlib.MAX_WBITS
                         if encoding == 'gzip' else
                         -zlib.MAX_WBITS)
            zcomp = zlib.compressobj(wbits=zlib_mode)
            for chunk in stream:
                yield zcomp.compress(chunk)
            else:
                yield zcomp.flush()
        else:
            raise RuntimeError('unknown content encoding: {}'
                               ''.format(encoding))

    def _apply_content_transfer_encoding(self, stream):
        encoding = self.headers[CONTENT_TRANSFER_ENCODING].lower()
        if encoding == 'base64':
            buffer = bytearray()
            while True:
                if buffer:
                    div, mod = divmod(len(buffer), 3)
                    chunk, buffer = buffer[:div * 3], buffer[div * 3:]
                    if chunk:
                        yield base64.b64encode(chunk)
                chunk = next(stream, None)
                if not chunk:
                    if buffer:
                        yield base64.b64encode(buffer[:])
                    return
                buffer.extend(chunk)
        elif encoding == 'quoted-printable':
            for chunk in stream:
                yield binascii.b2a_qp(chunk)
        else:
            raise RuntimeError('unknown content transfer encoding: {}'
                               ''.format(encoding))

    def set_content_disposition(self, disptype, **params):
        """Sets ``Content-Disposition`` header.

        :param str disptype: Disposition type: inline, attachment, form-data.
                            Should be valid extension token (see RFC 2183)
        :param dict params: Disposition params
        """
        if not disptype or not (TOKEN > set(disptype)):
            raise ValueError('bad content disposition type {!r}'
                             ''.format(disptype))
        value = disptype
        if params:
            lparams = []
            for key, val in params.items():
                if not key or not (TOKEN > set(key)):
                    raise ValueError('bad content disposition parameter'
                                     ' {!r}={!r}'.format(key, val))
                qval = quote(val, '')
                if key == 'filename':
                    lparams.append((key, '"%s"' % qval))
                    lparams.append(('filename*', "utf-8''" + qval))
                else:
                    lparams.append((key, "%s" % qval))
            sparams = '; '.join('='.join(pair) for pair in lparams)
            value = '; '.join((value, sparams))
        self.headers[CONTENT_DISPOSITION] = value

    @property
    def filename(self):
        """Returns filename specified in Content-Disposition header or ``None``
        if missed."""
        _, params = parse_content_disposition(
            self.headers.get(CONTENT_DISPOSITION))
        return content_disposition_filename(params)


class MultipartWriter(object):
    """Multipart body writer."""

    #: Body part reader class for non multipart/* content types.
    part_writer_cls = BodyPartWriter

    def __init__(self, subtype='mixed', boundary=None):
        boundary = boundary if boundary is not None else uuid.uuid4().hex
        try:
            boundary.encode('us-ascii')
        except UnicodeEncodeError:
            raise ValueError('boundary should contains ASCII only chars')
        self.headers = CIMultiDict()
        self.headers[CONTENT_TYPE] = 'multipart/{}; boundary="{}"'.format(
            subtype, boundary
        )
        self.parts = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def __iter__(self):
        return iter(self.parts)

    def __len__(self):
        return len(self.parts)

    @property
    def boundary(self):
        *_, params = parse_mimetype(self.headers.get(CONTENT_TYPE))
        return params['boundary'].encode('us-ascii')

    def append(self, obj, headers=None):
        """Adds a new body part to multipart writer."""
        if isinstance(obj, self.part_writer_cls):
            if headers:
                obj.headers.update(headers)
            self.parts.append(obj)
        else:
            if not headers:
                headers = CIMultiDict()
            self.parts.append(self.part_writer_cls(obj, headers))
        return self.parts[-1]

    def append_json(self, obj, headers=None):
        """Helper to append JSON part."""
        if not headers:
            headers = CIMultiDict()
        headers[CONTENT_TYPE] = 'application/json'
        return self.append(obj, headers)

    def append_form(self, obj, headers=None):
        """Helper to append form urlencoded part."""
        if not headers:
            headers = CIMultiDict()
        headers[CONTENT_TYPE] = 'application/x-www-form-urlencoded'
        assert isinstance(obj, (Sequence, Mapping))
        return self.append(obj, headers)

    def serialize(self):
        """Yields multipart byte chunks."""
        if not self.parts:
            yield b''
            return

        for part in self.parts:
            yield b'--' + self.boundary + b'\r\n'
            yield from part.serialize()
        else:
            yield b'--' + self.boundary + b'--\r\n'

        yield b''
