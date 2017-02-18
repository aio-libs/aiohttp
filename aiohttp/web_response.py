import asyncio
import datetime
import enum
import json
import math
import time
import warnings
from email.utils import parsedate

from multidict import CIMultiDict, CIMultiDictProxy

from . import hdrs
from .helpers import HeadersMixin, SimpleCookie, sentinel
from .http import (RESPONSES, SERVER_SOFTWARE, HttpVersion10,
                   HttpVersion11, PayloadWriter)

__all__ = ('ContentCoding', 'StreamResponse', 'Response', 'json_response')


class ContentCoding(enum.Enum):
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


class StreamResponse(HeadersMixin):

    def __init__(self, *, status=200, reason=None, headers=None):
        self._body = None
        self._keep_alive = None
        self._chunked = False
        self._compression = False
        self._compression_force = False
        self._cookies = SimpleCookie()

        self._req = None
        self._payload_writer = None
        self._eof_sent = False

        if headers is not None:
            self._headers = CIMultiDict(headers)
        else:
            self._headers = CIMultiDict()

        self.set_status(status, reason)

    @property
    def prepared(self):
        return self._payload_writer is not None

    @property
    def task(self):
        return getattr(self._req, 'task', None)

    @property
    def status(self):
        return self._status

    @property
    def chunked(self):
        return self._chunked

    @property
    def compression(self):
        return self._compression

    @property
    def reason(self):
        return self._reason

    def set_status(self, status, reason=None, _RESPONSES=RESPONSES):
        assert not self.prepared, \
            'Cannot change the response status code after ' \
            'the headers have been sent'
        self._status = int(status)
        if reason is None:
            try:
                reason = _RESPONSES[self._status][0]
            except:
                reason = ''
        self._reason = reason

    @property
    def keep_alive(self):
        return self._keep_alive

    def force_close(self):
        self._keep_alive = False

    @property
    def body_length(self):
        return self._payload_writer.output_length

    @property
    def output_length(self):
        return self._payload_writer.output_length

    def enable_chunked_encoding(self, chunk_size=None):
        """Enables automatic chunked transfer encoding."""
        self._chunked = True
        if chunk_size is not None:
            warnings.warn('Chunk size is deprecated #1615', DeprecationWarning)

    def enable_compression(self, force=None):
        """Enables response compression encoding."""
        # Backwards compatibility for when force was a bool <0.17.
        if type(force) == bool:
            force = ContentCoding.deflate if force else ContentCoding.identity
        elif force is not None:
            assert isinstance(force, ContentCoding), ("force should one of "
                                                      "None, bool or "
                                                      "ContentEncoding")

        self._compression = True
        self._compression_force = force

    @property
    def headers(self):
        return self._headers

    @property
    def cookies(self):
        return self._cookies

    def set_cookie(self, name, value, *, expires=None,
                   domain=None, max_age=None, path='/',
                   secure=None, httponly=None, version=None):
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
            c['max-age'] = max_age
        elif 'max-age' in c:
            del c['max-age']

        c['path'] = path

        if secure is not None:
            c['secure'] = secure
        if httponly is not None:
            c['httponly'] = httponly
        if version is not None:
            c['version'] = version

    def del_cookie(self, name, *, domain=None, path='/'):
        """Delete cookie.

        Creates new empty expired cookie.
        """
        # TODO: do we need domain/path here?
        self._cookies.pop(name, None)
        self.set_cookie(name, '', max_age=0,
                        expires="Thu, 01 Jan 1970 00:00:00 GMT",
                        domain=domain, path=path)

    @property
    def content_length(self):
        # Just a placeholder for adding setter
        return super().content_length

    @content_length.setter
    def content_length(self, value):
        if value is not None:
            value = int(value)
            # TODO: raise error if chunked enabled
            self._headers[hdrs.CONTENT_LENGTH] = str(value)
        else:
            self._headers.pop(hdrs.CONTENT_LENGTH, None)

    @property
    def content_type(self):
        # Just a placeholder for adding setter
        return super().content_type

    @content_type.setter
    def content_type(self, value):
        self.content_type  # read header values if needed
        self._content_type = str(value)
        self._generate_content_type_header()

    @property
    def charset(self):
        # Just a placeholder for adding setter
        return super().charset

    @charset.setter
    def charset(self, value):
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
    def last_modified(self, _LAST_MODIFIED=hdrs.LAST_MODIFIED):
        """The value of Last-Modified HTTP header, or None.

        This header is represented as a `datetime` object.
        """
        httpdate = self.headers.get(_LAST_MODIFIED)
        if httpdate is not None:
            timetuple = parsedate(httpdate)
            if timetuple is not None:
                return datetime.datetime(*timetuple[:6],
                                         tzinfo=datetime.timezone.utc)
        return None

    @last_modified.setter
    def last_modified(self, value):
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

    @property
    def tcp_nodelay(self):
        payload_writer = self._payload_writer
        assert payload_writer is not None, \
            "Cannot get tcp_nodelay for not prepared response"
        return payload_writer.tcp_nodelay

    def set_tcp_nodelay(self, value):
        payload_writer = self._payload_writer
        assert payload_writer is not None, \
            "Cannot set tcp_nodelay for not prepared response"
        payload_writer.set_tcp_nodelay(value)

    @property
    def tcp_cork(self):
        payload_writer = self._payload_writer
        assert payload_writer is not None, \
            "Cannot get tcp_cork for not prepared response"
        return payload_writer.tcp_cork

    def set_tcp_cork(self, value):
        payload_writer = self._payload_writer
        assert payload_writer is not None, \
            "Cannot set tcp_cork for not prepared response"

        payload_writer.set_tcp_cork(value)

    def _generate_content_type_header(self, CONTENT_TYPE=hdrs.CONTENT_TYPE):
        params = '; '.join("%s=%s" % i for i in self._content_dict.items())
        if params:
            ctype = self._content_type + '; ' + params
        else:
            ctype = self._content_type
        self.headers[CONTENT_TYPE] = ctype

    def _do_start_compression(self, coding):
        if coding != ContentCoding.identity:
            self.headers[hdrs.CONTENT_ENCODING] = coding.value
            self._payload_writer.enable_compression(coding.value)
            self._chunked = True

    def _start_compression(self, request):
        if self._compression_force:
            self._do_start_compression(self._compression_force)
        else:
            accept_encoding = request.headers.get(
                hdrs.ACCEPT_ENCODING, '').lower()
            for coding in ContentCoding:
                if coding.value in accept_encoding:
                    self._do_start_compression(coding)
                    return

    @asyncio.coroutine
    def prepare(self, request):
        if self._payload_writer is not None:
            return self._payload_writer

        yield from request._prepare_hook(self)
        return self._start(request)

    def _start(self, request,
               HttpVersion10=HttpVersion10,
               HttpVersion11=HttpVersion11,
               CONNECTION=hdrs.CONNECTION,
               DATE=hdrs.DATE,
               SERVER=hdrs.SERVER,
               CONTENT_TYPE=hdrs.CONTENT_TYPE,
               CONTENT_LENGTH=hdrs.CONTENT_LENGTH,
               SET_COOKIE=hdrs.SET_COOKIE,
               SERVER_SOFTWARE=SERVER_SOFTWARE,
               TRANSFER_ENCODING=hdrs.TRANSFER_ENCODING):
        self._req = request
        keep_alive = self._keep_alive
        if keep_alive is None:
            keep_alive = request.keep_alive
        self._keep_alive = keep_alive
        version = request.version

        writer = self._payload_writer = PayloadWriter(
            request._protocol.writer, request._loop)

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
        else:
            writer.length = self.content_length
            if writer.length is None and version >= HttpVersion11:
                writer.enable_chunking()
                headers[TRANSFER_ENCODING] = 'chunked'
                if CONTENT_LENGTH in headers:
                    del headers[CONTENT_LENGTH]

        headers.setdefault(CONTENT_TYPE, 'application/octet-stream')
        headers.setdefault(DATE, request.time_service.strtime())
        headers.setdefault(SERVER, SERVER_SOFTWARE)
        if CONNECTION not in headers:
            if keep_alive:
                if version == HttpVersion10:
                    headers[CONNECTION] = 'keep-alive'
            else:
                if version == HttpVersion11:
                    headers[CONNECTION] = 'close'

        self._send_headers(version, headers, writer)
        return writer

    def _send_headers(self, version, headers, writer, _sep=': ', _end='\r\n'):
        # Durty hack required for
        # https://github.com/KeepSafe/aiohttp/issues/1093
        # File sender may override it

        status_line = 'HTTP/{}.{} {} {}\r\n'.format(
            version[0], version[1], self._status, self._reason)

        # status + headers
        headers = status_line + ''.join(
            [k + _sep + v + _end for k, v in headers.items()])
        headers = headers.encode('utf-8') + b'\r\n'
        writer.buffer_data(headers)

    def write(self, data):
        assert isinstance(data, (bytes, bytearray, memoryview)), \
            "data argument must be byte-ish (%r)" % type(data)

        if self._eof_sent:
            raise RuntimeError("Cannot call write() after write_eof()")
        if self._payload_writer is None:
            raise RuntimeError("Cannot call write() before start()")

        if data:
            return self._payload_writer.write(data)
        else:
            return ()

    @asyncio.coroutine
    def drain(self):
        assert self._payload_writer is not None, \
            "Response has not been started"
        yield from self._payload_writer.drain()

    @asyncio.coroutine
    def write_eof(self, data=b''):
        assert isinstance(data, (bytes, bytearray, memoryview)), \
            "data argument must be byte-ish (%r)" % type(data)

        if self._eof_sent:
            return

        assert self._payload_writer is not None, \
            "Response has not been started"

        yield from self._payload_writer.write_eof(data)
        self._eof_sent = True
        self._req = None

    def __repr__(self):
        if self.prepared:
            info = "{} {} ".format(self._req.method, self._req.path)
        else:
            info = "not started"
        return "<{} {} {}>".format(self.__class__.__name__,
                                   self.reason, info)


class Response(StreamResponse):

    def __init__(self, *, body=None, status=200,
                 reason=None, text=None, headers=None, content_type=None,
                 charset=None):
        if body is not None and text is not None:
            raise ValueError("body and text are not allowed together")

        if headers is None:
            headers = CIMultiDict()
        elif not isinstance(headers, (CIMultiDict, CIMultiDictProxy)):
            headers = CIMultiDict(headers)

        if content_type is not None and ";" in content_type:
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
            self._body = body

    @property
    def body(self):
        return self._body

    @body.setter
    def body(self, body):
        assert body is None or isinstance(body, (bytes, bytearray)), \
            "body argument must be bytes (%r)" % type(body)
        self._body = body

    @property
    def text(self):
        if self._body is None:
            return None
        return self._body.decode(self.charset or 'utf-8')

    @text.setter
    def text(self, text):
        assert text is None or isinstance(text, str), \
            "text argument must be str (%r)" % type(text)

        if self.content_type == 'application/octet-stream':
            self.content_type = 'text/plain'
        if self.charset is None:
            self.charset = 'utf-8'

        self._body = text.encode(self.charset)

    @property
    def content_length(self):
        if self._chunked:
            return None

        if hdrs.CONTENT_LENGTH in self.headers:
            return super().content_length

        if self._body is not None:
            return len(self._body)
        else:
            return 0

    @content_length.setter
    def content_length(self, value):
        super().content_length = value

    @asyncio.coroutine
    def write_eof(self):
        body = self._body
        if (body is not None and
            (self._req._method == hdrs.METH_HEAD or
             self._status in [204, 304])):
            body = b''

        if body is None:
            body = b''

        yield from super().write_eof(body)

    def _start(self, request):
        if not self._chunked:
            if self._body is not None:
                self._headers[hdrs.CONTENT_LENGTH] = str(len(self._body))
            else:
                self._headers[hdrs.CONTENT_LENGTH] = '0'

        return super()._start(request)


def json_response(data=sentinel, *, text=None, body=None, status=200,
                  reason=None, headers=None, content_type='application/json',
                  dumps=json.dumps):
    if data is not sentinel:
        if text or body:
            raise ValueError(
                "only one of data, text, or body should be specified"
            )
        else:
            text = dumps(data)
    return Response(text=text, body=body, status=status, reason=reason,
                    headers=headers, content_type=content_type)
