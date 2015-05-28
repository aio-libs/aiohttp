__all__ = ('Request', 'StreamResponse', 'Response')

import asyncio
import binascii
import cgi
import collections
import http.cookies
import io
import json
import warnings

from urllib.parse import urlsplit, parse_qsl, unquote
from types import MappingProxyType

from . import hdrs
from .helpers import reify
from .multidict import (CIMultiDictProxy,
                        CIMultiDict,
                        MultiDictProxy,
                        MultiDict)
from .protocol import Response as ResponseImpl, HttpVersion10
from .streams import EOF_MARKER


sentinel = object()


class HeadersMixin:

    _content_type = None
    _content_dict = None
    _stored_content_type = sentinel

    def _parse_content_type(self, raw):
        self._stored_content_type = raw
        if raw is None:
            # default value according to RFC 2616
            self._content_type = 'application/octet-stream'
            self._content_dict = {}
        else:
            self._content_type, self._content_dict = cgi.parse_header(raw)

    @property
    def content_type(self, _CONTENT_TYPE=hdrs.CONTENT_TYPE):
        """The value of content part for Content-Type HTTP header."""
        raw = self.headers.get(_CONTENT_TYPE)
        if self._stored_content_type != raw:
            self._parse_content_type(raw)
        return self._content_type

    @property
    def charset(self, _CONTENT_TYPE=hdrs.CONTENT_TYPE):
        """The value of charset part for Content-Type HTTP header."""
        raw = self.headers.get(_CONTENT_TYPE)
        if self._stored_content_type != raw:
            self._parse_content_type(raw)
        return self._content_dict.get('charset')

    @property
    def content_length(self, _CONTENT_LENGTH=hdrs.CONTENT_LENGTH):
        """The value of Content-Length HTTP header."""
        l = self.headers.get(_CONTENT_LENGTH)
        if l is None:
            return None
        else:
            return int(l)


FileField = collections.namedtuple('Field', 'name filename file content_type')


############################################################
# HTTP Request
############################################################


class Request(dict, HeadersMixin):

    POST_METHODS = {hdrs.METH_PATCH, hdrs.METH_POST, hdrs.METH_PUT,
                    hdrs.METH_TRACE, hdrs.METH_DELETE}

    def __init__(self, app, message, payload, transport, reader, writer, *,
                 _HOST=hdrs.HOST, secure_proxy_ssl_header=None):
        self._app = app
        self._version = message.version
        self._transport = transport
        self._reader = reader
        self._writer = writer
        self._method = message.method
        self._host = message.headers.get(_HOST)
        self._path_qs = message.path
        res = urlsplit(message.path)
        self._path = unquote(res.path)
        self._query_string = res.query
        self._post = None
        self._post_files_cache = None
        self._headers = CIMultiDictProxy(message.headers)
        if self._version < HttpVersion10:
            self._keep_alive = False
        else:
            self._keep_alive = not message.should_close

        # matchdict, route_name, handler
        # or information about traversal lookup
        self._match_info = None  # initialized after route resolving

        self._payload = payload
        self._cookies = None

        self._read_bytes = None
        self._has_body = not payload.at_eof()

        self._secure_proxy_ssl_header = secure_proxy_ssl_header

    @property
    def scheme(self):
        """A string representing the scheme of the request.

        'http' or 'https'.
        """
        if self._transport.get_extra_info('sslcontext'):
            return 'https'
        secure_proxy_ssl_header = self._secure_proxy_ssl_header
        if secure_proxy_ssl_header is not None:
            header, value = secure_proxy_ssl_header
            if self._headers.get(header) == value:
                return 'https'
        return 'http'

    @property
    def method(self):
        """Read only property for getting HTTP method.

        The value is upper-cased str like 'GET', 'POST', 'PUT' etc.
        """
        return self._method

    @property
    def version(self):
        """Read only property for getting HTTP version of request.

        Returns aiohttp.protocol.HttpVersion instance.
        """
        return self._version

    @property
    def host(self):
        """Read only property for getting *HOST* header of request.

        Returns str or None if HTTP request has no HOST header.
        """
        return self._host

    @property
    def path_qs(self):
        """The URL including PATH_INFO and the query string.

        E.g, /app/blog?id=10
        """
        return self._path_qs

    @property
    def path(self):
        """The URL including *PATH INFO* without the host or scheme.

        E.g., ``/app/blog``
        """
        return self._path

    @property
    def query_string(self):
        """The query string in the URL.

        E.g., id=10
        """
        return self._query_string

    @reify
    def GET(self):
        """A multidict with all the variables in the query string.

        Lazy property.
        """
        return MultiDictProxy(MultiDict(parse_qsl(self._query_string)))

    @reify
    def POST(self):
        """A multidict with all the variables in the POST parameters.

        post() methods has to be called before using this attribute.
        """
        if self._post is None:
            raise RuntimeError("POST is not available before post()")
        return self._post

    @property
    def headers(self):
        """A case-insensitive multidict proxy with all headers."""
        return self._headers

    @property
    def keep_alive(self):
        """Is keepalive enabled by client?"""
        return self._keep_alive

    @property
    def match_info(self):
        """Result of route resolving."""
        return self._match_info

    @property
    def app(self):
        """Application instance."""
        return self._app

    @property
    def transport(self):
        """Transport used for request processing."""
        return self._transport

    @property
    def cookies(self):
        """Return request cookies.

        A read-only dictionary-like object.
        """
        if self._cookies is None:
            raw = self.headers.get(hdrs.COOKIE, '')
            parsed = http.cookies.SimpleCookie(raw)
            self._cookies = MappingProxyType(
                {key: val.value for key, val in parsed.items()})
        return self._cookies

    @property
    def payload(self):
        """Return raw payload stream."""
        warnings.warn('use Request.content instead', DeprecationWarning)
        return self._payload

    @property
    def content(self):
        """Return raw payload stream."""
        return self._payload

    @property
    def has_body(self):
        """Return True if request has HTTP BODY, False otherwise."""
        return self._has_body

    @asyncio.coroutine
    def release(self):
        """Release request.

        Eat unread part of HTTP BODY if present.
        """
        chunk = yield from self._payload.readany()
        while chunk is not EOF_MARKER or chunk:
            chunk = yield from self._payload.readany()

    @asyncio.coroutine
    def read(self):
        """Read request body if present.

        Returns bytes object with full request content.
        """
        if self._read_bytes is None:
            body = bytearray()
            while True:
                chunk = yield from self._payload.readany()
                body.extend(chunk)
                if chunk is EOF_MARKER:
                    break
            self._read_bytes = bytes(body)
        return self._read_bytes

    @asyncio.coroutine
    def text(self):
        """Return BODY as text using encoding from .charset."""
        bytes_body = yield from self.read()
        encoding = self.charset or 'utf-8'
        return bytes_body.decode(encoding)

    @asyncio.coroutine
    def json(self, *, loader=json.loads):
        """Return BODY as JSON."""
        body = yield from self.text()
        if not body:
            return loader('{}')
        return loader(body)

    @asyncio.coroutine
    def post(self):
        """Return POST parameters."""
        if self._post is not None:
            return self._post
        if self.method not in self.POST_METHODS:
            self._post = MultiDictProxy(MultiDict())
            return self._post

        content_type = self.content_type
        if (content_type not in ('',
                                 'application/x-www-form-urlencoded',
                                 'multipart/form-data')):
            self._post = MultiDictProxy(MultiDict())
            return self._post

        body = yield from self.read()
        content_charset = self.charset or 'utf-8'

        environ = {'REQUEST_METHOD': self.method,
                   'CONTENT_LENGTH': str(len(body)),
                   'QUERY_STRING': '',
                   'CONTENT_TYPE': self.headers.get(hdrs.CONTENT_TYPE)}

        fs = cgi.FieldStorage(fp=io.BytesIO(body),
                              environ=environ,
                              keep_blank_values=True,
                              encoding=content_charset)

        supported_transfer_encoding = {
            'base64': binascii.a2b_base64,
            'quoted-printable': binascii.a2b_qp
        }

        out = MultiDict()
        for field in fs.list or ():
            transfer_encoding = field.headers.get(
                hdrs.CONTENT_TRANSFER_ENCODING, None)
            if field.filename:
                ff = FileField(field.name,
                               field.filename,
                               field.file,  # N.B. file closed error
                               field.type)
                if self._post_files_cache is None:
                    self._post_files_cache = {}
                self._post_files_cache[field.name] = field
                out.add(field.name, ff)
            else:
                value = field.value
                if transfer_encoding in supported_transfer_encoding:
                    # binascii accepts bytes
                    value = value.encode('utf-8')
                    value = supported_transfer_encoding[
                        transfer_encoding](value)
                out.add(field.name, value)

        self._post = MultiDictProxy(out)
        return self._post

    def __repr__(self):
        return "<{} {} {} >".format(self.__class__.__name__,
                                    self.method, self.path)


############################################################
# HTTP Response classes
############################################################


class StreamResponse(HeadersMixin):

    def __init__(self, *, status=200, reason=None, headers=None):
        self._body = None
        self._keep_alive = None
        self._chunked = False
        self._chunk_size = None
        self._compression = False
        self._compression_force = False
        self._headers = CIMultiDict()
        self._cookies = http.cookies.SimpleCookie()
        self.set_status(status, reason)

        self._req = None
        self._resp_impl = None
        self._eof_sent = False

        if headers is not None:
            self._headers.extend(headers)

    def _copy_cookies(self):
        for cookie in self._cookies.values():
            value = cookie.output(header='')[1:]
            self.headers.add(hdrs.SET_COOKIE, value)

    @property
    def started(self):
        return self._resp_impl is not None

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

    def set_status(self, status, reason=None):
        self._status = int(status)
        if reason is None:
            reason = ResponseImpl.calc_reason(status)
        self._reason = reason

    @property
    def keep_alive(self):
        return self._keep_alive

    def force_close(self):
        self._keep_alive = False

    def enable_chunked_encoding(self, chunk_size=None):
        """Enables automatic chunked transfer encoding."""
        self._chunked = True
        self._chunk_size = chunk_size

    def enable_compression(self, force=False):
        """Enables response compression with `deflate` encoding."""
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
        if domain is not None:
            c['domain'] = domain
        if max_age is not None:
            c['max-age'] = max_age
        if path is not None:
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
        self.set_cookie(name, '', max_age=0, domain=domain, path=path)

    @property
    def content_length(self):
        # Just a placeholder for adding setter
        return super().content_length

    @content_length.setter
    def content_length(self, value):
        if value is not None:
            value = int(value)
            # TODO: raise error if chunked enabled
            self.headers[hdrs.CONTENT_LENGTH] = str(value)
        elif hdrs.CONTENT_LENGTH in self.headers:
            del self.headers[hdrs.CONTENT_LENGTH]

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

    def _generate_content_type_header(self, CONTENT_TYPE=hdrs.CONTENT_TYPE):
        params = '; '.join("%s=%s" % i for i in self._content_dict.items())
        if params:
            ctype = self._content_type + '; ' + params
        else:
            ctype = self._content_type
        self.headers[CONTENT_TYPE] = ctype

    def _start_pre_check(self, request):
        if self._resp_impl is not None:
            if self._req is not request:
                raise RuntimeError(
                    'Response has been started with different request.')
            else:
                return self._resp_impl
        else:
            return None

    def start(self, request):
        resp_impl = self._start_pre_check(request)
        if resp_impl is not None:
            return resp_impl

        self._req = request
        keep_alive = self._keep_alive
        if keep_alive is None:
            keep_alive = request.keep_alive
        self._keep_alive = keep_alive

        resp_impl = self._resp_impl = ResponseImpl(
            request._writer,
            self._status,
            request.version,
            not keep_alive,
            self._reason)

        self._copy_cookies()

        if self._compression:
            if (self._compression_force or
                    'deflate' in request.headers.get(
                        hdrs.ACCEPT_ENCODING, '')):
                resp_impl.add_compression_filter()

        if self._chunked:
            resp_impl.enable_chunked_encoding()
            if self._chunk_size:
                resp_impl.add_chunking_filter(self._chunk_size)

        headers = self.headers.items()
        for key, val in headers:
            resp_impl.add_header(key, val)

        resp_impl.send_headers()
        return resp_impl

    def write(self, data):
        assert isinstance(data, (bytes, bytearray, memoryview)), \
            'data argument must be byte-ish (%r)' % type(data)

        if self._eof_sent:
            raise RuntimeError("Cannot call write() after write_eof()")
        if self._resp_impl is None:
            raise RuntimeError("Cannot call write() before start()")

        if data:
            return self._resp_impl.write(data)
        else:
            return ()

    @asyncio.coroutine
    def drain(self):
        if self._resp_impl is None:
            raise RuntimeError("Response has not been started")
        yield from self._resp_impl.transport.drain()

    @asyncio.coroutine
    def write_eof(self):
        if self._eof_sent:
            return
        if self._resp_impl is None:
            raise RuntimeError("Response has not been started")

        yield from self._resp_impl.write_eof()
        self._eof_sent = True

    def __repr__(self):
        if self.started:
            info = "{} {} ".format(self._req.method, self._req.path)
        else:
            info = "not started"
        return "<{} {} {}>".format(self.__class__.__name__,
                                   self.reason, info)


class Response(StreamResponse):

    def __init__(self, *, body=None, status=200,
                 reason=None, text=None, headers=None, content_type=None):
        super().__init__(status=status, reason=reason, headers=headers)

        if body is not None and text is not None:
            raise ValueError("body and text are not allowed together.")

        if text is not None:
            if hdrs.CONTENT_TYPE not in self.headers:
                # fast path for filling headers
                if not isinstance(text, str):
                    raise TypeError('text argument must be str (%r)' %
                                    type(text))
                if content_type is None:
                    content_type = 'text/plain'
                self.headers[hdrs.CONTENT_TYPE] = (
                    content_type + '; charset=utf-8')
                self._content_type = content_type
                self._content_dict = {'charset': 'utf-8'}
                self.body = text.encode('utf-8')
            else:
                self.text = text
        else:
            if content_type:
                self.content_type = content_type
            if body is not None:
                self.body = body
            else:
                self.body = None

    @property
    def body(self):
        return self._body

    @body.setter
    def body(self, body):
        if body is not None and not isinstance(body, bytes):
            raise TypeError('body argument must be bytes (%r)' % type(body))
        self._body = body
        if body is not None:
            self.content_length = len(body)
        else:
            self.content_length = 0

    @property
    def text(self):
        return self._body.decode(self.charset or 'utf-8')

    @text.setter
    def text(self, text):
        if text is not None and not isinstance(text, str):
            raise TypeError('text argument must be str (%r)' % type(text))

        if self.content_type == 'application/octet-stream':
            self.content_type = 'text/plain'
        if self.charset is None:
            self.charset = 'utf-8'

        self.body = text.encode(self.charset)

    @asyncio.coroutine
    def write_eof(self):
        body = self._body
        if body is not None:
            self.write(body)
        yield from super().write_eof()
