import abc
import asyncio
import binascii
import collections
import mimetypes
import cgi
import http.cookies
import io
import json
import re
import os

from urllib.parse import urlsplit, parse_qsl, unquote, urlencode

from .abc import AbstractRouter, AbstractMatchInfo
from .log import web_log
from .multidict import (CaseInsensitiveMultiDict,
                        CaseInsensitiveMutableMultiDict,
                        MultiDict,
                        MutableMultiDict)
from .protocol import Response as ResponseImpl, HttpVersion, HttpVersion11
from .server import ServerHttpProtocol
from .streams import EOF_MARKER


__all__ = [
    'Application',
    'HttpVersion',
    'Request',
    'StreamResponse',
    'Response',
    'UrlDispatcher',
    'UrlMappingMatchInfo',
    'HTTPException',
    'HTTPError',
    'HTTPRedirection',
    'HTTPSuccessful',
    'HTTPOk',
    'HTTPCreated',
    'HTTPAccepted',
    'HTTPNonAuthoritativeInformation',
    'HTTPNoContent',
    'HTTPResetContent',
    'HTTPPartialContent',
    'HTTPMultipleChoices',
    'HTTPMovedPermanently',
    'HTTPFound',
    'HTTPSeeOther',
    'HTTPNotModified',
    'HTTPUseProxy',
    'HTTPTemporaryRedirect',
    'HTTPClientError',
    'HTTPBadRequest',
    'HTTPUnauthorized',
    'HTTPPaymentRequired',
    'HTTPForbidden',
    'HTTPNotFound',
    'HTTPMethodNotAllowed',
    'HTTPNotAcceptable',
    'HTTPProxyAuthenticationRequired',
    'HTTPRequestTimeout',
    'HTTPConflict',
    'HTTPGone',
    'HTTPLengthRequired',
    'HTTPPreconditionFailed',
    'HTTPRequestEntityTooLarge',
    'HTTPRequestURITooLong',
    'HTTPUnsupportedMediaType',
    'HTTPRequestRangeNotSatisfiable',
    'HTTPExpectationFailed',
    'HTTPServerError',
    'HTTPInternalServerError',
    'HTTPNotImplemented',
    'HTTPBadGateway',
    'HTTPServiceUnavailable',
    'HTTPGatewayTimeout',
    'HTTPVersionNotSupported',
]


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
    def content_type(self):
        """The value of content part for Content-Type HTTP header."""
        raw = self.headers.get('Content-Type')
        if self._stored_content_type != raw:
            self._parse_content_type(raw)
        return self._content_type

    @property
    def charset(self):
        """The value of charset part for Content-Type HTTP header."""
        # Assumes that charset is UTF8 if not specified
        raw = self.headers.get('Content-Type')
        if self._stored_content_type != raw:
            self._parse_content_type(raw)
        return self._content_dict.get('charset')

    @property
    def content_length(self):
        """The value of Content-Length HTTP header."""
        l = self.headers.get('Content-Length')
        if l is None:
            return None
        else:
            return int(l)


FileField = collections.namedtuple('Field', 'name filename file content_type')


############################################################
# HTTP Request
############################################################


class Request(HeadersMixin):

    def __init__(self, app, message, payload, transport, writer,
                 keep_alive_timeout):
        self._app = app
        self._version = message.version
        self._transport = transport
        self._writer = writer
        self._method = message.method
        self._host = message.headers.get('HOST')
        path = unquote(message.path)
        self._path_qs = path
        res = urlsplit(path)
        self._path = res.path
        self._query_string = res.query
        self._get = None
        self._post = None
        self._post_files_cache = None
        self._headers = CaseInsensitiveMultiDict._from_uppercase_multidict(
            message.headers)

        if self._version < HttpVersion11:
            self._keep_alive = False
        elif message.should_close:
            self._keep_alive = False
        else:
            self._keep_alive = bool(keep_alive_timeout)

        # matchdict, route_name, handler
        # or information about traversal lookup
        self._match_info = None  # initialized after route resolving

        self._payload = payload
        self._cookies = None

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

    @property
    def GET(self):
        """A multidict with all the variables in the query string.

        Lazy property.
        """
        if self._get is None:
            self._get = MultiDict(parse_qsl(self._query_string))
        return self._get

    @property
    def headers(self):
        """A case-insensitive multidict with all headers.

        Lazy property.
        """
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
            raw = self.headers.get('COOKIE', '')
            parsed = http.cookies.SimpleCookie(raw)
            self._cookies = MultiDict({key: val.value
                                       for key, val in parsed.items()})
        return self._cookies

    @property
    def payload(self):
        """Return raw paiload stream."""
        return self._payload

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

        body = bytearray()
        while True:
            chunk = yield from self._payload.readany()
            body.extend(chunk)
            if chunk is EOF_MARKER:
                break
        return bytes(body)

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
        return loader(body)

    @asyncio.coroutine
    def POST(self):
        """Return POST parameters."""
        if self._post is not None:
            return self._post
        if self.method not in ('POST', 'PUT', 'PATCH'):
            self._post = MultiDict()
            return self._post
        content_type = self.content_type
        if (content_type not in ('',
                                 'application/x-www-form-urlencoded',
                                 'multipart/form-data')):
            self._post = MultiDict()
            return self._post

        body = yield from self.read()
        content_charset = self.charset or 'utf-8'

        environ = {'REQUEST_METHOD': self.method,
                   'CONTENT_LENGTH': str(len(body)),
                   'QUERY_STRING': '',
                   'CONTENT_TYPE': self.headers.get('CONTENT-TYPE')}

        fs = cgi.FieldStorage(fp=io.BytesIO(body),
                              environ=environ,
                              keep_blank_values=True,
                              encoding=content_charset)

        supported_tranfer_encoding = {
            'base64': binascii.a2b_base64,
            'quoted-printable': binascii.a2b_qp
        }
        out = MutableMultiDict()
        for field in fs.list or ():
            transfer_encoding = field.headers.get('Content-Transfer-Encoding',
                                                  None)
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
                if transfer_encoding in supported_tranfer_encoding:
                    # binascii accepts bytes
                    value = value.encode('utf-8')
                    value = supported_tranfer_encoding[
                        transfer_encoding](value)
                out.add(field.name, value)
        self._post = MultiDict(out.items(getall=True))
        return self._post

    # @asyncio.coroutine
    # def start_websocket(self):
    #     """Upgrade connection to websocket.

    #     Returns (reader, writer) pair.
    #     """

    #     upgrade = 'websocket' in message.headers.get('UPGRADE', '').lower()
    #     if not upgrade:
    #         pass


############################################################
# HTTP Response classes
############################################################


class StreamResponse(HeadersMixin):

    def __init__(self, request, *, status=200, reason=None):
        self._request = request
        self._headers = CaseInsensitiveMutableMultiDict()
        self.set_status(status, reason)
        self._cookies = http.cookies.SimpleCookie()
        self._keep_alive = request.keep_alive

        self._resp_impl = None
        self._eof_sent = False

    def _copy_cookies(self):
        for cookie in self._cookies.values():
            value = cookie.output(header='')[1:]
            self.headers.add('Set-Cookie', value)

    @property
    def request(self):
        return self._request

    @property
    def status(self):
        return self._status

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

    @property
    def headers(self):
        return self._headers

    @property
    def cookies(self):
        return self._cookies

    def set_cookie(self, name, value, *, expires=None,
                   domain=None, max_age=None, path=None,
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

    def del_cookie(self, name, *, domain=None, path=None):
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
            self.headers['Content-Length'] = str(value)
        elif 'Content-Length' in self.headers:
            del self.headers['Content-Length']

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
            self._content_dict['charset'] = str(value)
        self._generate_content_type_header()

    def _generate_content_type_header(self):
        params = '; '.join("%s=%s" % i for i in self._content_dict.items())
        if params:
            ctype = self._content_type + '; ' + params
        else:
            ctype = self._content_type
        self.headers['Content-Type'] = ctype

    @property
    def server_response(self):
        return self._resp_impl

    def send_headers(self):
        if self._resp_impl is not None:
            raise RuntimeError("HTTP headers are already sent")

        resp_impl = self._resp_impl = ResponseImpl(
            self._request._writer,
            self._status,
            self._request.version,
            not self._keep_alive,
            self._reason)

        self._copy_cookies()

        headers = self.headers.items(getall=True)
        for key, val in headers:
            resp_impl.add_header(key, val)

        resp_impl.send_headers()

    def write(self, data):
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError('data argument must be byte-ish (%r)',
                            type(data))

        if self._eof_sent:
            raise RuntimeError("Cannot call write() after write_eof()")
        if self._resp_impl is None:
            self.send_headers()

        if data:
            return self._resp_impl.write(data)
        else:
            return ()

    @asyncio.coroutine
    def write_eof(self):
        if self._eof_sent:
            return
        if self._resp_impl is None:
            raise RuntimeError("No headers has been sent")

        yield from self._resp_impl.write_eof()
        self._eof_sent = True


class Response(StreamResponse):

    def __init__(self, request, body=None, *,
                 status=200, reason=None, headers=None):
        super().__init__(request, status=status, reason=reason)
        self.body = body
        if headers is not None:
            self.headers.extend(headers)

    @property
    def body(self):
        return self._body

    @body.setter
    def body(self, body):
        if body is not None and not isinstance(body, bytes):
            raise TypeError('body argument must be bytes (%r)',
                            type(body))
        self._body = body
        if body is not None:
            self.content_length = len(body)
        else:
            self.content_length = 0

    @asyncio.coroutine
    def write_eof(self):
        body = self._body
        if self._resp_impl is None:
            self.send_headers()
        if body is not None:
            self.write(body)
        yield from super().write_eof()


############################################################
# HTTP Exceptions
############################################################

class HTTPException(Response, Exception):

    # You should set in subclasses:
    # status = 200

    status_code = None

    def __init__(self, request, *, headers=None, reason=None):
        Response.__init__(self, request, status=self.status_code,
                          headers=headers, reason=reason)
        Exception.__init__(self, self.reason)
        self.body = "{}: {}".format(self.status, self.reason).encode('utf-8')


class HTTPError(HTTPException):
    """Base class for exceptions with status codes in the 400s and 500s."""


class HTTPRedirection(HTTPException):
    """Base class for exceptions with status codes in the 300s."""


class HTTPSuccessful(HTTPException):
    """Base class for exceptions with status codes in the 200s."""


class HTTPOk(HTTPSuccessful):
    status_code = 200


class HTTPCreated(HTTPSuccessful):
    status_code = 201


class HTTPAccepted(HTTPSuccessful):
    status_code = 202


class HTTPNonAuthoritativeInformation(HTTPSuccessful):
    status_code = 203


class HTTPNoContent(HTTPSuccessful):
    status_code = 204


class HTTPResetContent(HTTPSuccessful):
    status_code = 205


class HTTPPartialContent(HTTPSuccessful):
    status_code = 206


############################################################
# 3xx redirection
############################################################


class _HTTPMove(HTTPRedirection):

    def __init__(self, request, location, *, headers=None, reason=None):
        if not location:
            raise ValueError("HTTP redirects need a location to redirect to.")
        super().__init__(request, headers=headers, reason=reason)
        self.headers['Location'] = location
        self.location = location


class HTTPMultipleChoices(_HTTPMove):
    status_code = 300


class HTTPMovedPermanently(_HTTPMove):
    status_code = 301


class HTTPFound(_HTTPMove):
    status_code = 302


# This one is safe after a POST (the redirected location will be
# retrieved with GET):
class HTTPSeeOther(_HTTPMove):
    status_code = 303


class HTTPNotModified(HTTPRedirection):
    # FIXME: this should include a date or etag header
    status_code = 304


class HTTPUseProxy(_HTTPMove):
    # Not a move, but looks a little like one
    status_code = 305


class HTTPTemporaryRedirect(_HTTPMove):
    status_code = 307


############################################################
# 4xx client error
############################################################


class HTTPClientError(HTTPError):
    pass


class HTTPBadRequest(HTTPClientError):
    status_code = 400


class HTTPUnauthorized(HTTPClientError):
    status_code = 401


class HTTPPaymentRequired(HTTPClientError):
    status_code = 402


class HTTPForbidden(HTTPClientError):
    status_code = 403


class HTTPNotFound(HTTPClientError):
    status_code = 404


class HTTPMethodNotAllowed(HTTPClientError):
    status_code = 405

    def __init__(self, request, method, allowed_methods, *,
                 headers=None, reason=None):
        allow = ','.join(sorted(allowed_methods))
        super().__init__(request, headers=headers, reason=reason)
        self.headers['Allow'] = allow
        self.allowed_methods = allowed_methods
        self.method = method.upper()


class HTTPNotAcceptable(HTTPClientError):
    status_code = 406


class HTTPProxyAuthenticationRequired(HTTPClientError):
    status_code = 407


class HTTPRequestTimeout(HTTPClientError):
    status_code = 408


class HTTPConflict(HTTPClientError):
    status_code = 409


class HTTPGone(HTTPClientError):
    status_code = 410


class HTTPLengthRequired(HTTPClientError):
    status_code = 411


class HTTPPreconditionFailed(HTTPClientError):
    status_code = 412


class HTTPRequestEntityTooLarge(HTTPClientError):
    status_code = 413


class HTTPRequestURITooLong(HTTPClientError):
    status_code = 414


class HTTPUnsupportedMediaType(HTTPClientError):
    status_code = 415


class HTTPRequestRangeNotSatisfiable(HTTPClientError):
    status_code = 416


class HTTPExpectationFailed(HTTPClientError):
    status_code = 417


############################################################
# 5xx Server Error
############################################################
#  Response status codes beginning with the digit "5" indicate cases in
#  which the server is aware that it has erred or is incapable of
#  performing the request. Except when responding to a HEAD request, the
#  server SHOULD include an entity containing an explanation of the error
#  situation, and whether it is a temporary or permanent condition. User
#  agents SHOULD display any included entity to the user. These response
#  codes are applicable to any request method.


class HTTPServerError(HTTPError):
    pass


class HTTPInternalServerError(HTTPServerError):
    status_code = 500


class HTTPNotImplemented(HTTPServerError):
    status_code = 501


class HTTPBadGateway(HTTPServerError):
    status_code = 502


class HTTPServiceUnavailable(HTTPServerError):
    status_code = 503


class HTTPGatewayTimeout(HTTPServerError):
    status_code = 504


class HTTPVersionNotSupported(HTTPServerError):
    status_code = 505


############################################################
# UrlDispatcher implementation
############################################################


class UrlMappingMatchInfo(dict, AbstractMatchInfo):

    def __init__(self, match_dict, route):
        super().__init__(match_dict)
        self._route = route

    @property
    def handler(self):
        return self._route.handler

    @property
    def route(self):
        return self._route


class Route(metaclass=abc.ABCMeta):

    def __init__(self, method, handler, name):
        self._method = method
        self._handler = handler
        self._name = name

    @property
    def method(self):
        return self._method

    @property
    def handler(self):
        return self._handler

    @property
    def name(self):
        return self._name

    @abc.abstractmethod
    def match(self, path):
        """Return dict with info for given path or
        None if route cannot process path."""

    @abc.abstractmethod
    def url(self, **kwargs):
        """Construct url for route with additional params."""

    @staticmethod
    def _append_query(url, query):
        if query is not None:
            return url + "?" + urlencode(query)
        else:
            return url


class PlainRoute(Route):
    def __init__(self, method, handler, name, path):
        super().__init__(method, handler, name)
        self._path = path

    def match(self, path):
        # string comparsion about 10 times faster than regexp matching
        if self._path == path:
            return {}
        else:
            return None

    def url(self, *, query=None):
        return self._append_query(self._path, query)

    def __repr__(self):
        name = "'" + self.name + "' " if self.name is not None else ""
        return "<PlainRoute {name}[{method}] {path} -> {handler!r}".format(
            name=name, method=self.method, path=self._path,
            handler=self.handler)


class DynamicRoute(Route):

    def __init__(self, method, handler, name, pattern, formatter):
        super().__init__(method, handler, name)
        self._pattern = pattern
        self._formatter = formatter

    def match(self, path):
        match = self._pattern.match(path)
        if match is None:
            return None
        else:
            return match.groupdict()

    def url(self, *, parts, query=None):
        url = self._formatter.format_map(parts)
        return self._append_query(url, query)

    def __repr__(self):
        name = "'" + self.name + "' " if self.name is not None else ""
        return ("<DynamicRoute {name}[{method}] {formatter} -> {handler!r}"
                .format(name=name, method=self.method,
                        formatter=self._formatter, handler=self.handler))


class StaticRoute(Route):

    def __init__(self, name, prefix, directory):
        assert prefix.startswith('/'), prefix
        assert prefix.endswith('/'), prefix
        super().__init__('GET', self.handle, name)
        self._prefix = prefix
        self._prefix_len = len(self._prefix)
        self._directory = directory

    def match(self, path):
        if not path.startswith(self._prefix):
            return None
        return {'filename': path[self._prefix_len:]}

    def url(self, *, filename, query=None):
        while filename.startswith('/'):
            filename = filename[1:]
        url = self._prefix + filename
        return self._append_query(url, query)

    @asyncio.coroutine
    def handle(self, request):
        resp = StreamResponse(request)
        filename = request.match_info['filename']
        filepath = os.path.join(self._directory, filename)
        if '..' in filename:
            raise HTTPNotFound(request)
        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            raise HTTPNotFound(request)

        ct = mimetypes.guess_type(filename)[0]
        if not ct:
            ct = 'application/octet-stream'
        resp.content_type = ct

        resp.headers['transfer-encoding'] = 'chunked'
        resp.send_headers()

        with open(filepath, 'rb') as f:
            chunk = f.read(1024)
            while chunk:
                resp.write(chunk)
                chunk = f.read(1024)

        yield from resp.write_eof()
        return resp

    def __repr__(self):
        name = "'" + self.name + "' " if self.name is not None else ""
        return "<StaticRoute {name}[{method}] {path} -> {directory!r}".format(
            name=name, method=self.method, path=self._prefix,
            directory=self._directory)


class UrlDispatcher(AbstractRouter, collections.abc.Mapping):

    DYN = re.compile(r'^\{[a-zA-Z][_a-zA-Z0-9]*\}$')
    GOOD = r'[^{}/]+'
    PLAIN = re.compile('^' + GOOD + '$')

    METHODS = {'POST', 'GET', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'}

    def __init__(self):
        super().__init__()
        self._urls = []
        self._routes = {}

    @asyncio.coroutine
    def resolve(self, request):
        path = request.path
        method = request.method
        allowed_methods = set()
        for route in self._urls:
            match_dict = route.match(path)
            if match_dict is None:
                continue
            route_method = route.method
            if route_method != method:
                allowed_methods.add(route_method)
            else:
                return UrlMappingMatchInfo(match_dict, route)
        else:
            if allowed_methods:
                raise HTTPMethodNotAllowed(request, method, allowed_methods)
            else:
                raise HTTPNotFound(request)

    def __iter__(self):
        return iter(self._routes)

    def __len__(self):
        return len(self._routes)

    def __contains__(self, name):
        return name in self._routes

    def __getitem__(self, name):
        return self._routes[name]

    def _register_endpoint(self, route):
        name = route.name
        if name is not None:
            if name in self._routes:
                raise ValueError('Duplicate {!r}, '
                                 'already handled by {!r}'
                                 .format(name, self._routes[name]))
            else:
                self._routes[name] = route
        self._urls.append(route)

    def add_route(self, method, path, handler, *, name=None):
        assert path.startswith('/')
        assert callable(handler), handler
        method = method.upper()
        assert method in self.METHODS, method
        parts = []
        factory = PlainRoute
        for part in path.split('/'):
            if not part:
                continue
            if self.DYN.match(part):
                parts.append('(?P<' + part[1:-1] + '>' + self.GOOD + ')')
                factory = DynamicRoute
            elif self.PLAIN.match(part):
                parts.append(re.escape(part))
            else:
                raise ValueError("Invalid path '{}'['{}']".format(path, part))
        if factory is PlainRoute:
            route = PlainRoute(method, handler, name, path)
        else:
            pattern = '/' + '/'.join(parts)
            if path.endswith('/') and pattern != '/':
                pattern += '/'
            compiled = re.compile('^' + pattern + '$')
            route = DynamicRoute(method, handler, name, compiled, path)
        self._register_endpoint(route)

    def add_static(self, prefix, path, *, name=None):
        """
        Adds static files view
        :param prefix - url prefix
        :param path - folder with files
        """
        assert prefix.startswith('/')
        assert os.path.isdir(path), 'Path does not directory %s' % path
        path = os.path.abspath(path)
        if not prefix.endswith('/'):
            prefix += '/'
        route = StaticRoute(name, prefix, path)
        self._register_endpoint(route)


############################################################
# Application implementation
############################################################


class RequestHandler(ServerHttpProtocol):

    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self._app = app

    def connection_made(self, transport):
        super().connection_made(transport)

        self._app.connection_made(self, transport)

    def connection_lost(self, exc):
        self._app.connection_lost(self, exc)

        super().connection_lost(exc)

    @asyncio.coroutine
    def handle_request(self, message, payload):
        now = self._loop.time()

        request = Request(self._app, message, payload,
                          self.transport, self.writer, self.keep_alive_timeout)
        try:
            match_info = yield from self._app.router.resolve(request)

            assert isinstance(match_info, AbstractMatchInfo), match_info

            request._match_info = match_info
            handler = match_info.handler

            resp = handler(request)
            if (asyncio.iscoroutine(resp) or
                    isinstance(resp, asyncio.Future)):
                resp = yield from resp
            if not isinstance(resp, StreamResponse):
                raise RuntimeError(("Handler should return response "
                                    "instance, got {!r}")
                                   .format(type(resp)))
        except HTTPException as exc:
            resp = exc

        yield from resp.write_eof()
        if resp.keep_alive:
            # Don't need to read request body if any on closing connection
            yield from request.release()
        self.keep_alive(resp.keep_alive)

        self.log_access(
            message, None, resp.server_response, self._loop.time() - now)


class Application(dict):

    def __init__(self, *, loop=None, router=None, **kwargs):
        # TODO: explicitly accept *debug* param
        if loop is None:
            loop = asyncio.get_event_loop()
        if router is None:
            router = UrlDispatcher()
        assert isinstance(router, AbstractRouter), router
        self._router = router
        self._loop = loop
        self._finish_callbacks = []
        self._connections = {}

    @property
    def router(self):
        return self._router

    @property
    def loop(self):
        return self._loop

    def make_handler(self, **kwargs):
        return RequestHandler(self, loop=self._loop, **kwargs)

    @property
    def connections(self):
        return list(self._connections.keys())

    def connection_made(self, handler, transport):
        self._connections[handler] = transport

    def connection_lost(self, handler, exc=None):
        if handler in self._connections:
            del self._connections[handler]

    @asyncio.coroutine
    def finish(self):
        callbacks = self._finish_callbacks
        self._finish_callbacks = []

        for (cb, args, kwargs) in callbacks:
            try:
                res = cb(*args, **kwargs)
                if (asyncio.iscoroutine(res) or
                        isinstance(res, asyncio.Future)):
                    yield from res
            except Exception as exc:
                self._loop.call_exception_handler({
                    'message': "Error in finish callback",
                    'exception': exc,
                    'application': self,
                })

    @asyncio.coroutine
    def finish_connections(self, timeout=None):
        for handler in self._connections.keys():
            handler.closing()

        def cleanup():
            while self._connections:
                yield from asyncio.sleep(0.5, loop=self._loop)

        if timeout:
            try:
                yield from asyncio.wait_for(
                    cleanup(), timeout, loop=self._loop)
            except asyncio.TimeoutError:
                web_log.warn(
                    "Not all connections closed (pending: %d)",
                    len(self._connections))

        for transport in self._connections.values():
            transport.close()

        self._connections.clear()

    def register_on_finish(self, func, *args, **kwargs):
        self._finish_callbacks.insert(0, (func, args, kwargs))
