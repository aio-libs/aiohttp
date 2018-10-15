import asyncio
import collections
import datetime
import enum
import json
import math
import time
import warnings
import zlib
from email.utils import parsedate
from http.cookies import SimpleCookie
from typing import (TYPE_CHECKING, Any, Callable, Dict, Iterable,  # noqa
                    Iterator, List, Mapping, MutableMapping, Optional, Tuple,
                    Union, cast)

from multidict import CIMultiDict, CIMultiDictProxy

from . import hdrs, payload
from .helpers import HeadersMixin, rfc822_formatted_time, sentinel
from .http import (RESPONSES, SERVER_SOFTWARE, HttpVersion, HttpVersion10,
                   HttpVersion11)
from .http_writer import StreamWriter
from .typedefs import LooseHeaders, _CIMultiDict


__all__ = ('ContentCoding', 'StreamResponse', 'Response', 'json_response')


class ContentCoding(str, enum.Enum):
    # The content codings that we have support for.
    #
    # Additional registered codings are listed at:
    # https://www.iana.org/assignments/http-parameters/http-parameters.xhtml#content-coding
    deflate = 'deflate'
    gzip = 'gzip'
    identity = 'identity'


############################################################
# HTTP Response classes
############################################################

if TYPE_CHECKING:  # pragma: no cover
    from .web_request import BaseRequest
    BaseStreamResponse = MutableMapping[str, str]
else:
    BaseRequest = object()  # placeholder
    BaseStreamResponse = collections.MutableMapping


class StreamResponse(BaseStreamResponse, HeadersMixin):

    _length_check = True

    def __init__(self, *,
                 status: int=200,
                 reason: Optional[str]=None,
                 headers: Optional[LooseHeaders]=None) -> None:
        self._body = None  # type: Optional[Union[payload.Payload, bytes]]
        self._keep_alive = None  # type: Optional[bool]
        self._chunked = False
        self._compression = False
        self._compression_force = None  # type: Optional[ContentCoding]
        self._cookies = SimpleCookie()

        self._req = None  # type: Optional[BaseRequest]
        self._payload_writer = None  # type: Optional[StreamWriter]
        self._eof_sent = False
        self._body_length = 0
        self._state = {}  # type: Dict[str, str]
        self._content_dict = {}  # type: Dict[str, str]

        if headers is not None:
            self._headers = CIMultiDict(headers)  # type: _CIMultiDict
        else:
            self._headers = CIMultiDict()  # type: _CIMultiDict

        self.set_status(status, reason)

    @property
    def prepared(self) -> bool:
        return self._payload_writer is not None

    @property
    def task(self) -> 'asyncio.Task[None]':
        return getattr(self._req, 'task', None)

    @property
    def status(self) -> int:
        return self._status

    @property
    def chunked(self) -> bool:
        return self._chunked

    @property
    def compression(self) -> bool:
        return self._compression

    @property
    def reason(self) -> str:
        return self._reason

    def set_status(
        self,
        status: int,
        reason: Optional[str]=None,
        _RESPONSES: Mapping[int, Tuple[str, str]]=RESPONSES,
    ) -> None:
        assert not self.prepared, \
            'Cannot change the response status code after ' \
            'the headers have been sent'
        self._status = int(status)
        if reason is None:
            try:
                reason = _RESPONSES[self._status][0]
            except Exception:
                reason = ''
        self._reason = reason

    @property
    def keep_alive(self) -> Optional[bool]:
        return self._keep_alive

    def force_close(self) -> None:
        self._keep_alive = False

    @property
    def body_length(self) -> int:
        return self._body_length

    @property
    def output_length(self) -> int:
        warnings.warn('output_length is deprecated', DeprecationWarning)
        return self._payload_writer.buffer_size  # type: ignore

    def enable_chunked_encoding(self, chunk_size: Optional[int]=None) -> None:
        """Enables automatic chunked transfer encoding."""
        self._chunked = True

        if hdrs.CONTENT_LENGTH in self._headers:
            raise RuntimeError("You can't enable chunked encoding when "
                               "a content length is set")
        if chunk_size is not None:
            warnings.warn('Chunk size is deprecated #1615', DeprecationWarning)

    def enable_compression(
        self,
        force: Optional[Union[bool, ContentCoding]] = None,
    ) -> None:
        """Enables response compression encoding."""
        # Backwards compatibility for when force was a bool <0.17.
        if force is not None:
            if isinstance(force, bool):
                actual_force = ContentCoding.deflate \
                    if force else ContentCoding.identity
            elif isinstance(force, ContentCoding):
                actual_force = force
            else:
                raise ValueError('force should be one of '
                                 'None, bool or ContentEncoding')

            self._compression_force = actual_force

        self._compression = True

    @property
    def headers(self) -> 'CIMultiDict[str]':
        return self._headers

    @property
    def cookies(self) -> SimpleCookie:
        return self._cookies

    def set_cookie(self,
                   name: str,
                   value: str,
                   *,
                   expires: Optional[str]=None,
                   domain: Optional[str]=None,
                   max_age: Optional[Union[str, int]]=None,
                   path: str='/',
                   secure: Optional[str]=None,
                   httponly: Optional[str]=None,
                   version: Optional[str]=None) -> None:
        """Set or update response cookie.

        Sets new cookie or updates existent with new value.
        Also updates only those params which are not None.
        """

        old = self._cookies.get(name)
        if old is not None and old.coded_value == '':
            # deleted cookie
            self._cookies.pop(name, None)

        self._cookies[name] = value
        c = self._cookies[name]

        if expires is not None:
            c['expires'] = expires
        elif c.get('expires') == 'Thu, 01 Jan 1970 00:00:00 GMT':
            del c['expires']

        if domain is not None:
            c['domain'] = domain

        if max_age is not None:
            c['max-age'] = str(max_age)
        elif 'max-age' in c:
            del c['max-age']

        c['path'] = path

        if secure is not None:
            c['secure'] = secure
        if httponly is not None:
            c['httponly'] = httponly
        if version is not None:
            c['version'] = version

    def del_cookie(
        self,
        name: str,
        *,
        domain: Optional[str]=None,
        path: str='/',
    ) -> None:
        """Delete cookie.

        Creates new empty expired cookie.
        """
        # TODO: do we need domain/path here?
        self._cookies.pop(name, None)
        self.set_cookie(name, '', max_age=0,
                        expires="Thu, 01 Jan 1970 00:00:00 GMT",
                        domain=domain, path=path)

    @property
    def content_length(self) -> Optional[int]:
        # Just a placeholder for adding setter
        return super().content_length

    @content_length.setter
    def content_length(self, value: Optional[int]) -> None:
        if value is not None:
            if self._chunked:
                raise RuntimeError("You can't set content length when "
                                   "chunked encoding is enable")
            self._headers[hdrs.CONTENT_LENGTH] = str(value)
        else:
            self._headers.pop(hdrs.CONTENT_LENGTH, None)

    @property
    def content_type(self) -> str:
        # Just a placeholder for adding setter
        return super().content_type

    @content_type.setter
    def content_type(self, value: str) -> None:
        self.content_type  # read header values if needed
        self._content_type = str(value)
        self._generate_content_type_header()

    @property
    def charset(self) -> Optional[str]:
        # Just a placeholder for adding setter
        return super().charset

    @charset.setter
    def charset(self, value: Optional[str]) -> None:
        ctype = self.content_type  # read header values if needed
        if ctype == 'application/octet-stream':
            raise RuntimeError("Setting charset for application/octet-stream "
                               "doesn't make sense, setup content_type first")
        if value is None:
            self._content_dict.pop('charset', None)
        else:
            self._content_dict['charset'] = str(value).lower()
        self._generate_content_type_header()

    @property
    def last_modified(self) -> Optional[datetime.datetime]:
        """The value of Last-Modified HTTP header, or None.

        This header is represented as a `datetime` object.
        """
        httpdate = self.headers.get(hdrs.LAST_MODIFIED)
        if httpdate is not None:
            timetuple = parsedate(httpdate)
            if timetuple is not None:
                return datetime.datetime(*timetuple[:6],
                                         tzinfo=datetime.timezone.utc)
        return None

    @last_modified.setter
    def last_modified(
        self,
        value: Optional[Union[float, str, datetime.datetime]] = None,
    ) -> None:
        if value is None:
            self.headers.pop(hdrs.LAST_MODIFIED, None)
        elif isinstance(value, (int, float)):
            self.headers[hdrs.LAST_MODIFIED] = time.strftime(
                "%a, %d %b %Y %H:%M:%S GMT", time.gmtime(math.ceil(value)))
        elif isinstance(value, datetime.datetime):
            self.headers[hdrs.LAST_MODIFIED] = time.strftime(
                "%a, %d %b %Y %H:%M:%S GMT", value.utctimetuple())
        elif isinstance(value, str):
            self.headers[hdrs.LAST_MODIFIED] = value

    def _generate_content_type_header(
        self,
        CONTENT_TYPE: str=hdrs.CONTENT_TYPE,
    ) -> None:
        params = '; '.join(
            ("%s=%s" % (k, v) for k, v in self._content_dict.items()),
        )
        if params:
            ctype = self.content_type + '; ' + params
        else:
            ctype = self.content_type
        self.headers[CONTENT_TYPE] = ctype

    def _do_start_compression(self, coding: ContentCoding) -> None:
        if coding != ContentCoding.identity and self._payload_writer:
            self.headers[hdrs.CONTENT_ENCODING] = coding.value
            self._payload_writer.enable_compression(coding.value)
            # Compressed payload may have different content length,
            # remove the header
            self._headers.popall(hdrs.CONTENT_LENGTH, None)

    def _start_compression(self, request: BaseRequest) -> None:
        if self._compression_force:
            self._do_start_compression(self._compression_force)
        else:
            accept_encoding = request.headers.get(
                hdrs.ACCEPT_ENCODING,
                '',
            ).lower()
            for coding in list(ContentCoding):
                if coding.value in accept_encoding:
                    self._do_start_compression(coding)
                    return

    async def prepare(self, request: BaseRequest) -> Optional[StreamWriter]:
        if self._eof_sent:
            return None
        if self._payload_writer is not None:
            return self._payload_writer

        await request._prepare_hook(self)
        return await self._start(request)

    async def _start(
        self,
        request: BaseRequest,
        HttpVersion10: HttpVersion=HttpVersion10,
        HttpVersion11: HttpVersion=HttpVersion11,
        CONNECTION: str=hdrs.CONNECTION,
        DATE: str=hdrs.DATE,
        SERVER: str=hdrs.SERVER,
        CONTENT_TYPE: str=hdrs.CONTENT_TYPE,
        CONTENT_LENGTH: str=hdrs.CONTENT_LENGTH,
        SET_COOKIE: str=hdrs.SET_COOKIE,
        SERVER_SOFTWARE: str=SERVER_SOFTWARE,
        TRANSFER_ENCODING: str=hdrs.TRANSFER_ENCODING,
    ) -> StreamWriter:
        self._req = request

        keep_alive = self._keep_alive
        if keep_alive is None:
            keep_alive = request.keep_alive
        self._keep_alive = keep_alive

        version = request.version
        writer = self._payload_writer = request._payload_writer

        headers = self._headers
        for cookie in self._cookies.values():
            value = cookie.output(header='')[1:]
            headers.add(SET_COOKIE, value)

        if self._compression:
            self._start_compression(request)

        if self._chunked:
            if version != HttpVersion11:
                raise RuntimeError(
                    "Using chunked encoding is forbidden "
                    "for HTTP/{0.major}.{0.minor}".format(request.version))
            writer.enable_chunking()
            headers[TRANSFER_ENCODING] = 'chunked'
            if CONTENT_LENGTH in headers:
                del headers[CONTENT_LENGTH]
        elif self._length_check:
            writer.length = self.content_length
            if writer.length is None:
                if version >= HttpVersion11:
                    writer.enable_chunking()
                    headers[TRANSFER_ENCODING] = 'chunked'
                    if CONTENT_LENGTH in headers:
                        del headers[CONTENT_LENGTH]
                else:
                    keep_alive = False

        headers.setdefault(CONTENT_TYPE, 'application/octet-stream')
        headers.setdefault(DATE, rfc822_formatted_time())
        headers.setdefault(SERVER, SERVER_SOFTWARE)

        # connection header
        if CONNECTION not in headers:
            if keep_alive:
                if version == HttpVersion10:
                    headers[CONNECTION] = 'keep-alive'
            else:
                if version == HttpVersion11:
                    headers[CONNECTION] = 'close'

        # status line
        status_line = 'HTTP/{}.{} {} {}'.format(
            version[0], version[1], self._status, self._reason)
        await writer.write_headers(status_line, headers)

        return writer

    async def write(self, data: bytes) -> None:
        assert isinstance(data, (bytes, bytearray, memoryview)), \
            "data argument must be byte-ish (%r)" % type(data)

        if self._eof_sent:
            raise RuntimeError("Cannot call write() after write_eof()")
        if self._payload_writer is None:
            raise RuntimeError("Cannot call write() before prepare()")

        await self._payload_writer.write(data)

    async def drain(self) -> None:
        assert not self._eof_sent, "EOF has already been sent"
        assert self._payload_writer is not None, \
            "Response has not been started"
        warnings.warn("drain method is deprecated, use await resp.write()",
                      DeprecationWarning,
                      stacklevel=2)
        await self._payload_writer.drain()

    async def write_eof(self, data: bytes=b'') -> None:
        assert isinstance(data, (bytes, bytearray, memoryview)), \
            "data argument must be byte-ish (%r)" % type(data)

        if self._eof_sent:
            return

        assert self._payload_writer is not None, \
            "Response has not been started"

        await self._payload_writer.write_eof(data)
        self._eof_sent = True
        self._req = None
        self._body_length = self._payload_writer.output_size
        self._payload_writer = None

    def __repr__(self) -> str:
        if self._eof_sent:
            info = "eof"
        elif self.prepared:
            info = "{} {} ".format(
                getattr(self._req, 'method'),
                getattr(self._req, 'path'),
            )
        else:
            info = "not prepared"
        return "<{} {} {}>".format(self.__class__.__name__,
                                   self.reason, info)

    def __getitem__(self, key: str) -> str:
        return self._state[key]

    def __setitem__(self, key: str, value: str) -> None:
        self._state[key] = value

    def __delitem__(self, key: str) -> None:
        del self._state[key]

    def __len__(self) -> int:
        return len(self._state)

    def __iter__(self) -> Iterator[Tuple[str, str]]:  # type: ignore
        return iter(self._state.items())

    def __hash__(self) -> int:
        return hash(id(self))

    def __eq__(self, other: Any) -> bool:
        return self is other


class Response(StreamResponse):

    def __init__(self, *,
                 body: Any=None,
                 status: int=200,
                 reason: Optional[str]=None,
                 text: Optional[str]=None,
                 headers: Optional[LooseHeaders]=None,
                 content_type: Optional[str]=None,
                 charset: Optional[str]=None) -> None:
        if body is not None and text is not None:
            raise ValueError("body and text are not allowed together")

        if headers is None:
            headers = CIMultiDict()
        elif not isinstance(headers, (CIMultiDict, CIMultiDictProxy)):
            headers = CIMultiDict(headers)
        else:
            headers = cast(_CIMultiDict, headers)

        if content_type is not None and "charset" in content_type:
            raise ValueError("charset must not be in content_type "
                             "argument")

        if text is not None:
            if hdrs.CONTENT_TYPE in headers:
                if content_type or charset:
                    raise ValueError("passing both Content-Type header and "
                                     "content_type or charset params "
                                     "is forbidden")
            else:
                # fast path for filling headers
                if not isinstance(text, str):
                    raise TypeError("text argument must be str (%r)" %
                                    type(text))
                if content_type is None:
                    content_type = 'text/plain'
                if charset is None:
                    charset = 'utf-8'
                headers[hdrs.CONTENT_TYPE] = (
                    content_type + '; charset=' + charset)
                body = text.encode(charset)
                text = None
        else:
            if hdrs.CONTENT_TYPE in headers:
                if content_type is not None or charset is not None:
                    raise ValueError("passing both Content-Type header and "
                                     "content_type or charset params "
                                     "is forbidden")
            else:
                if content_type is not None:
                    if charset is not None:
                        content_type += '; charset=' + charset
                    headers[hdrs.CONTENT_TYPE] = content_type

        super().__init__(status=status, reason=reason, headers=headers)

        if text is not None:
            self.text = text
        else:
            self.body = body

        self._compressed_body = None  # type: Optional[bytes]

    @property
    def body(self) -> Optional[Union[payload.Payload, bytes]]:
        return self._body

    @body.setter
    def body(self,
             body: Optional[Union[bytes, payload.Payload]],
             CONTENT_TYPE: str=hdrs.CONTENT_TYPE,
             CONTENT_LENGTH: str=hdrs.CONTENT_LENGTH) -> None:
        if body is None:
            self._body = None
        elif isinstance(body, (bytes, bytearray, memoryview)):
            self._body = body
        else:
            try:
                self._body = body = payload.PAYLOAD_REGISTRY.get(body)
            except payload.LookupError:
                raise ValueError('Unsupported body type %r' % type(body))

            headers = self._headers

            # set content-length header if needed
            if not self._chunked and CONTENT_LENGTH not in headers:
                size = body.size
                if size is not None:
                    headers[CONTENT_LENGTH] = str(size)

            # set content-type
            if CONTENT_TYPE not in headers:
                headers[CONTENT_TYPE] = body.content_type

            # copy payload headers
            if body.headers:
                for (key, value) in body.headers.items():
                    if key not in headers:
                        headers[key] = value

        self._compressed_body = None

    @property
    def text(self) -> Optional[str]:
        if self._body is None:
            return None
        else:
            if isinstance(self._body, payload.Payload):
                raise ValueError('Cannot extract text from payload')
            else:
                return self._body.decode(self.charset or 'utf-8')

    @text.setter
    def text(self, text: str) -> None:
        assert text is None or isinstance(text, str), \
            "text argument must be str (%r)" % type(text)

        if self.content_type == 'application/octet-stream':
            self.content_type = 'text/plain'
        if self.charset is None:
            self.charset = 'utf-8'

        self._body = text.encode(self.charset)
        self._compressed_body = None

    @property
    def content_length(self) -> Optional[int]:
        if self._chunked:
            return None

        if hdrs.CONTENT_LENGTH in self.headers:
            return super().content_length

        if self._compressed_body is not None:
            # Return length of the compressed body
            return len(self._compressed_body)
        elif self._body is not None:
            if isinstance(self._body, payload.Payload):
                return self._body.size
            else:
                return len(self._body)
        else:
            return 0

    @content_length.setter
    def content_length(self, value: int) -> None:
        raise RuntimeError("Content length is set automatically")

    async def write_eof(self) -> None:  # type: ignore
        if self._eof_sent:
            return

        body = None  # type: Optional[Union[payload.Payload, bytes]]
        if self._compressed_body is not None:
            body = self._compressed_body
        else:
            body = self._body

        if body is not None and self._req is not None:
            if (self._req._method == hdrs.METH_HEAD or
                    self._status in [204, 304]):
                await super().write_eof()
            elif isinstance(body, payload.Payload) and self._payload_writer:
                await body.write(self._payload_writer)
                await super().write_eof()
            elif isinstance(body, bytes):
                await super().write_eof(body)
        else:
            await super().write_eof()

    async def _start(self,  # type: ignore
                     request: BaseRequest) -> StreamWriter:
        if not self._chunked and hdrs.CONTENT_LENGTH not in self._headers:
            if self._body is not None:
                if isinstance(self._body, payload.Payload):
                    self._headers[hdrs.CONTENT_LENGTH] = str(self._body.size)
                else:
                    self._headers[hdrs.CONTENT_LENGTH] = str(len(self._body))
            else:
                self._headers[hdrs.CONTENT_LENGTH] = '0'

        return await super()._start(request)

    def _do_start_compression(self, coding: ContentCoding) -> None:
        if isinstance(self._body, payload.Payload) or self._chunked:
            super()._do_start_compression(coding)
        elif isinstance(self._body, bytes) \
                and coding != ContentCoding.identity:
            # Instead of using _payload_writer.enable_compression,
            # compress the whole body
            zlib_mode = (16 + zlib.MAX_WBITS
                         if coding.value == 'gzip' else -zlib.MAX_WBITS)
            compressobj = zlib.compressobj(wbits=zlib_mode)
            self._compressed_body = compressobj.compress(self._body) +\
                compressobj.flush()
            self._headers[hdrs.CONTENT_ENCODING] = coding.value
            self._headers[hdrs.CONTENT_LENGTH] = \
                str(len(self._compressed_body))


def json_response(data: Dict[str, Any]=sentinel,
                  text: str=None,
                  body: str=None,
                  status: int=200,
                  reason: str=None,
                  headers: Optional[LooseHeaders]=None,
                  content_type: str='application/json',
                  dumps: Callable[..., str]=json.dumps) -> Response:
    if data is not sentinel:
        if text or body:
            raise ValueError(
                "only one of data, text, or body should be specified"
            )
        else:
            text = dumps(data)
    return Response(text=text, body=body, status=status, reason=reason,
                    headers=headers, content_type=content_type)
