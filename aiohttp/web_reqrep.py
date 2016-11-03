import asyncio
import binascii
import cgi
import collections
import datetime
import enum
import http.cookies
import io
import json
import math
import time
import warnings
from email.utils import parsedate
from types import MappingProxyType

from multidict import CIMultiDict, CIMultiDictProxy, MultiDict, MultiDictProxy
from yarl import URL

from . import hdrs, multipart
from .helpers import HeadersMixin, reify, sentinel
from .protocol import WebResponse as ResponseImpl
from .protocol import HttpVersion10, HttpVersion11

__all__ = (
    'ContentCoding', 'Request', 'StreamResponse', 'Response',
    'json_response'
)

FileField = collections.namedtuple('Field', 'name filename file content_type')


class ContentCoding(enum.Enum):
    # The content codings that we have support for.
    #
    # Additional registered codings are listed at:
    # https://www.iana.org/assignments/http-parameters/http-parameters.xhtml#content-coding
    deflate = 'deflate'
    gzip = 'gzip'
    identity = 'identity'


############################################################
# HTTP Request
############################################################


class Request(collections.MutableMapping, HeadersMixin):

    POST_METHODS = {hdrs.METH_PATCH, hdrs.METH_POST, hdrs.METH_PUT,
                    hdrs.METH_TRACE, hdrs.METH_DELETE}

    def __init__(self, message, payload, transport, reader, writer,
                 time_service, *,
                 secure_proxy_ssl_header=None):
        self._message = message
        self._transport = transport
        self._reader = reader
        self._writer = writer
        self._post = None
        self._post_files_cache = None

        # matchdict, route_name, handler
        # or information about traversal lookup
        self._match_info = None  # initialized after route resolving

        self._payload = payload

        self._read_bytes = None
        self._has_body = not payload.at_eof()

        self._secure_proxy_ssl_header = secure_proxy_ssl_header
        self._time_service = time_service
        self._state = {}
        self._cache = {}

    def clone(self, *, method=sentinel, rel_url=sentinel,
              headers=sentinel):
        """Clone itself with replacement some attributes.

        Creates and returns a new instance of Request object. If no parameters
        are given, an exact copy is returned. If a parameter is not passed, it
        will reuse the one from the current request object.

        """

        if self._read_bytes:
            raise RuntimeError("Cannot clone request "
                               "after reading it's content")

        dct = {}
        if method is not sentinel:
            dct['method'] = method
        if rel_url is not sentinel:
            dct['path'] = str(URL(rel_url))
        if headers is not sentinel:
            dct['headers'] = CIMultiDict(headers)
            dct['raw_headers'] = [(k.encode('utf-8'), v.encode('utf-8'))
                                  for k, v in headers.items()]

        message = self._message._replace(**dct)

        return Request(
            message,
            self._payload,
            self._transport,
            self._reader,
            self._writer,
            self._time_service,
            secure_proxy_ssl_header=self._secure_proxy_ssl_header)

    # MutableMapping API

    def __getitem__(self, key):
        return self._state[key]

    def __setitem__(self, key, value):
        self._state[key] = value

    def __delitem__(self, key):
        del self._state[key]

    def __len__(self):
        return len(self._state)

    def __iter__(self):
        return iter(self._state)

    ########

    @reify
    def scheme(self):
        """A string representing the scheme of the request.

        'http' or 'https'.
        """
        warnings.warn("path_qs property is deprecated, "
                      "use .url.scheme instead",
                      DeprecationWarning)
        return self.url.scheme

    @reify
    def _scheme(self):
        if self._transport.get_extra_info('sslcontext'):
            return 'https'
        secure_proxy_ssl_header = self._secure_proxy_ssl_header
        if secure_proxy_ssl_header is not None:
            header, value = secure_proxy_ssl_header
            if self.headers.get(header) == value:
                return 'https'
        return 'http'

    @reify
    def method(self):
        """Read only property for getting HTTP method.

        The value is upper-cased str like 'GET', 'POST', 'PUT' etc.
        """
        return self._message.method

    @reify
    def version(self):
        """Read only property for getting HTTP version of request.

        Returns aiohttp.protocol.HttpVersion instance.
        """
        return self._message.version

    @reify
    def host(self):
        """Read only property for getting *HOST* header of request.

        Returns str or None if HTTP request has no HOST header.
        """
        warnings.warn("host property is deprecated, "
                      "use .url.host instead",
                      DeprecationWarning)
        return self._message.headers.get(hdrs.HOST)

    @reify
    def rel_url(self):
        return URL(self._message.path)

    @reify
    def path_qs(self):
        """The URL including PATH_INFO and the query string.

        E.g, /app/blog?id=10
        """
        warnings.warn("path_qs property is deprecated, "
                      "use str(request.rel_url) instead",
                      DeprecationWarning)
        return str(self.rel_url)

    @reify
    def url(self):
        return URL('{}://{}{}'.format(self._scheme,
                                      self._message.headers.get(hdrs.HOST),
                                      str(self.rel_url)))

    @reify
    def raw_path(self):
        """ The URL including raw *PATH INFO* without the host or scheme.
        Warning, the path is unquoted and may contains non valid URL characters

        E.g., ``/my%2Fpath%7Cwith%21some%25strange%24characters``
        """
        warnings.warn("raw_path property is deprecated, "
                      "use .rel_url.raw_path instead",
                      DeprecationWarning)
        return self.rel_url.raw_path

    @reify
    def path(self):
        """The URL including *PATH INFO* without the host or scheme.

        E.g., ``/app/blog``
        """
        warnings.warn("path property is deprecated, use .rel_url.path instead",
                      DeprecationWarning)
        return self.rel_url.path

    @reify
    def query_string(self):
        """The query string in the URL.

        E.g., id=10
        """
        warnings.warn("query_string property is deprecated, "
                      "use .rel_url.query_string instead",
                      DeprecationWarning)
        return self.rel_url.query_string

    @reify
    def GET(self):
        """A multidict with all the variables in the query string.

        Lazy property.
        """
        warnings.warn("GET property is deprecated, use .rel_url.query instead",
                      DeprecationWarning)
        return self.rel_url.query

    @reify
    def POST(self):
        """A multidict with all the variables in the POST parameters.

        post() methods has to be called before using this attribute.
        """
        warnings.warn("POST property is deprecated, use .post() instead",
                      DeprecationWarning)
        if self._post is None:
            raise RuntimeError("POST is not available before post()")
        return self._post

    @reify
    def headers(self):
        """A case-insensitive multidict proxy with all headers."""
        return CIMultiDictProxy(self._message.headers)

    @reify
    def raw_headers(self):
        """A sequence of pars for all headers."""
        return tuple(self._message.raw_headers)

    @reify
    def if_modified_since(self, _IF_MODIFIED_SINCE=hdrs.IF_MODIFIED_SINCE):
        """The value of If-Modified-Since HTTP header, or None.

        This header is represented as a `datetime` object.
        """
        httpdate = self.headers.get(_IF_MODIFIED_SINCE)
        if httpdate is not None:
            timetuple = parsedate(httpdate)
            if timetuple is not None:
                return datetime.datetime(*timetuple[:6],
                                         tzinfo=datetime.timezone.utc)
        return None

    @reify
    def keep_alive(self):
        """Is keepalive enabled by client?"""
        if self.version < HttpVersion10:
            return False
        else:
            return not self._message.should_close

    @property
    def match_info(self):
        """Result of route resolving."""
        return self._match_info

    @reify
    def app(self):
        """Application instance."""
        return self._match_info.apps[-1]

    @property
    def transport(self):
        """Transport used for request processing."""
        return self._transport

    @reify
    def cookies(self):
        """Return request cookies.

        A read-only dictionary-like object.
        """
        raw = self.headers.get(hdrs.COOKIE, '')
        parsed = http.cookies.SimpleCookie(raw)
        return MappingProxyType(
            {key: val.value for key, val in parsed.items()})

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
        while not self._payload.at_eof():
            yield from self._payload.readany()

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
                if not chunk:
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
    def json(self, *, loads=json.loads, loader=None):
        """Return BODY as JSON."""
        if loader is not None:
            warnings.warn(
                "Using loader argument is deprecated, use loads instead",
                DeprecationWarning)
            loads = loader
        body = yield from self.text()
        return loads(body)

    @asyncio.coroutine
    def multipart(self, *, reader=multipart.MultipartReader):
        """Return async iterator to process BODY as multipart."""
        return reader(self.headers, self.content)

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

        if self.content_type.startswith('multipart/'):
            warnings.warn('To process multipart requests use .multipart'
                          ' coroutine instead.', DeprecationWarning)

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
        _count = 1
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
                self._post_files_cache[field.name+str(_count)] = field
                _count += 1
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
        ascii_encodable_path = self.path.encode('ascii', 'backslashreplace') \
            .decode('ascii')
        return "<{} {} {} >".format(self.__class__.__name__,
                                    self.method, ascii_encodable_path)


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
        if hdrs.CONTENT_TYPE not in self._headers:
            self._headers[hdrs.CONTENT_TYPE] = 'application/octet-stream'

    def _copy_cookies(self):
        for cookie in self._cookies.values():
            value = cookie.output(header='')[1:]
            self.headers.add(hdrs.SET_COOKIE, value)

    @property
    def prepared(self):
        return self._resp_impl is not None

    @property
    def started(self):
        warnings.warn('use Response.prepared instead', DeprecationWarning)
        return self.prepared

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
            self.headers[hdrs.CONTENT_LENGTH] = str(value)
        else:
            self.headers.pop(hdrs.CONTENT_LENGTH, None)

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
        resp_impl = self._resp_impl
        if resp_impl is None:
            raise RuntimeError("Cannot get tcp_nodelay for "
                               "not prepared response")
        return resp_impl.transport.tcp_nodelay

    def set_tcp_nodelay(self, value):
        resp_impl = self._resp_impl
        if resp_impl is None:
            raise RuntimeError("Cannot set tcp_nodelay for "
                               "not prepared response")
        resp_impl.transport.set_tcp_nodelay(value)

    @property
    def tcp_cork(self):
        resp_impl = self._resp_impl
        if resp_impl is None:
            raise RuntimeError("Cannot get tcp_cork for "
                               "not prepared response")
        return resp_impl.transport.tcp_cork

    def set_tcp_cork(self, value):
        resp_impl = self._resp_impl
        if resp_impl is None:
            raise RuntimeError("Cannot set tcp_cork for "
                               "not prepared response")
        resp_impl.transport.set_tcp_cork(value)

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
                    "Response has been started with different request.")
            else:
                return self._resp_impl
        else:
            return None

    def _do_start_compression(self, coding):
        if coding != ContentCoding.identity:
            self.headers[hdrs.CONTENT_ENCODING] = coding.value
            self._resp_impl.add_compression_filter(coding.value)
            self.content_length = None

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

    def start(self, request):
        warnings.warn('use .prepare(request) instead', DeprecationWarning)
        resp_impl = self._start_pre_check(request)
        if resp_impl is not None:
            return resp_impl

        return self._start(request)

    @asyncio.coroutine
    def prepare(self, request):
        resp_impl = self._start_pre_check(request)
        if resp_impl is not None:
            return resp_impl
        for app in request.match_info.apps:
            yield from app.on_response_prepare.send(request, self)

        return self._start(request)

    def _start(self, request):
        self._req = request
        keep_alive = self._keep_alive
        if keep_alive is None:
            keep_alive = request.keep_alive
        self._keep_alive = keep_alive
        version = request.version

        resp_impl = self._resp_impl = ResponseImpl(
            request._writer,
            self._status,
            version,
            not keep_alive,
            self._reason)

        self._copy_cookies()

        headers = self.headers
        if self._compression:
            self._start_compression(request)

        if self._chunked:
            if request.version != HttpVersion11:
                raise RuntimeError("Using chunked encoding is forbidden "
                                   "for HTTP/{0.major}.{0.minor}".format(
                                       request.version))
            resp_impl.enable_chunked_encoding()
            if self._chunk_size:
                resp_impl.add_chunking_filter(self._chunk_size)
            headers[hdrs.TRANSFER_ENCODING] = 'chunked'
        else:
            resp_impl.length = self.content_length

        if hdrs.DATE not in headers:
            headers[hdrs.DATE] = request._time_service.strtime()
        headers.setdefault(hdrs.SERVER, resp_impl.SERVER_SOFTWARE)
        if hdrs.CONNECTION not in headers:
            if keep_alive:
                if version == HttpVersion10:
                    headers[hdrs.CONNECTION] = 'keep-alive'
            else:
                if version == HttpVersion11:
                    headers[hdrs.CONNECTION] = 'close'

        resp_impl.headers = headers

        self._send_headers(resp_impl)
        return resp_impl

    def _send_headers(self, resp_impl):
        # Durty hack required for
        # https://github.com/KeepSafe/aiohttp/issues/1093
        # File sender may override it
        resp_impl.send_headers()

    def write(self, data):
        assert isinstance(data, (bytes, bytearray, memoryview)), \
            "data argument must be byte-ish (%r)" % type(data)

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
            self.body = body

    @property
    def body(self):
        return self._body

    @body.setter
    def body(self, body):
        if body is not None and not isinstance(body, bytes):
            raise TypeError("body argument must be bytes (%r)" % type(body))
        self._body = body
        if body is not None:
            self.content_length = len(body)
        else:
            self.content_length = 0

    @property
    def text(self):
        if self._body is None:
            return None
        return self._body.decode(self.charset or 'utf-8')

    @text.setter
    def text(self, text):
        if text is not None and not isinstance(text, str):
            raise TypeError("text argument must be str (%r)" % type(text))

        if self.content_type == 'application/octet-stream':
            self.content_type = 'text/plain'
        if self.charset is None:
            self.charset = 'utf-8'

        self.body = text.encode(self.charset)

    @asyncio.coroutine
    def write_eof(self):
        body = self._body
        if (body is not None and
                self._req.method != hdrs.METH_HEAD and
                self._status not in [204, 304]):
            self.write(body)
        yield from super().write_eof()


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
