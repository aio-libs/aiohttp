import asyncio
import binascii
import collections
import cgi
import http.cookies
import io
import json
import re
import weakref

from html import escape as _html_escape
from string import Template
from urllib.parse import urlsplit, parse_qsl, unquote

from .abc import AbstractRouter, AbstractMatchInfo
from .errors import HttpErrorException
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


class StreamResponse(HeadersMixin):

    def __init__(self, request, *, status=200, reason=None):
        self._request = request
        self._headers = CaseInsensitiveMutableMultiDict()
        self._status = int(status)
        if reason is None:
            reason = ResponseImpl.calc_reason(status)
        self._reason = reason
        self._cookies = http.cookies.SimpleCookie()
        self._deleted_cookies = set()
        self._keep_alive = request.keep_alive

        self._resp_impl = None
        self._eof_sent = False

    def _copy_cookies(self):
        for cookie in self._cookies.values():
            value = cookie.output(header='')[1:]
            self.headers.add('Set-Cookie', value)

    def _check_sending_started(self):
        resp = self._request._response
        if resp is not None:
            resp = resp()  # dereference weakref
        if resp is not None:
            raise RuntimeError(("Response {!r} already started to send"
                                " data").format(resp))

    @property
    def request(self):
        return self._request

    @property
    def status(self):
        return self._status

    @property
    def reason(self):
        return self._reason

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

        self._check_sending_started()
        if name in self._deleted_cookies:
            self._deleted_cookies.remove(name)
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
        self._check_sending_started()
        self._cookies.pop(name, None)
        self.set_cookie(name, '', max_age=0, domain=domain, path=path)
        self._deleted_cookies.add(name)

    @property
    def content_length(self):
        # Just a placeholder for adding setter
        return super().content_length

    @content_length.setter
    def content_length(self, value):
        self._check_sending_started()
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
        self._check_sending_started()
        self.content_type  # read header values if needed
        self._content_type = str(value)
        self._generate_content_type_header()

    @property
    def charset(self):
        # Just a placeholder for adding setter
        return super().charset

    @charset.setter
    def charset(self, value):
        self._check_sending_started()
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

    def set_chunked(self, chunk_size, buffered=True):
        if self.content_length is not None:
            raise RuntimeError(
                "Cannot use chunked encoding with Content-Length set up")

    def send_headers(self):
        if self._resp_impl is not None:
            raise RuntimeError("HTTP headers are already sent")

        self._check_sending_started()
        self._request._response = weakref.ref(self)

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
            raise RuntimeError("Cannot call write() after send_eof()")
        if self._resp_impl is None:
            self.send_headers()

        if data:
            self._resp_impl.write(data)

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
        self._check_sending_started()
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


class Request(HeadersMixin):

    def __init__(self, app, message, payload, writer):
        self._app = app
        self._version = message.version
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
        self._headers = CaseInsensitiveMultiDict._from_uppercase_multidict(
            message.headers)

        if self._version < HttpVersion11:
            self._keep_alive = False
        elif message.should_close:
            self._keep_alive = False
        else:
            self._keep_alive = True

        # matchdict, route_name, handler
        # or information about traversal lookup
        self._match_info = None  # initialized after route resolving

        self._payload = payload
        self._response = None
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
        fs = cgi.FieldStorage(fp=io.BytesIO(body),
                              environ={'REQUEST_METHOD': self.method},
                              headers=self._headers,
                              keep_blank_values=True,
                              encoding=content_charset)

        supported_tranfer_encoding = {
            'base64': binascii.a2b_base64,
            'quoted-printable': binascii.a2b_qp
        }
        out = MutableMultiDict()
        for field in fs.list or ():
            charset = field.type_options.get('charset', 'utf-8')
            transfer_encoding = field.headers.get('Content-Transfer-Encoding',
                                                  None)
            if charset == 'utf-8':
                decode = lambda b: b
            else:
                decode = lambda b: b.encode('utf-8').decode(charset)
            if field.filename:
                field.filename = decode(field.filename)
                out.add(field.name, field)
            else:
                value = field.value
                if transfer_encoding in supported_tranfer_encoding:
                    # binascii accepts bytes
                    value = value.encode('utf-8')
                    value = supported_tranfer_encoding[
                        transfer_encoding](value)
                    # binascii returns bytes
                    value = value.decode('utf-8')
                out.add(field.name, decode(value))
        self._post = MultiDict(out)
        return self._post

    @asyncio.coroutine
    def start_websocket(self):
        """Upgrade connection to websocket.

        Returns (reader, writer) pair.
        """


def _no_escape(value):
    if value is None:
        return ''
    if not isinstance(value, str):
        if isinstance(value, bytes):
            value = value.decode('utf-8')
        else:
            value = str(value)
    return value


class HTTPException(Response, Exception):

    # You should set in subclasses:
    # status = 200
    # title = 'OK'
    # explanation = 'why this happens'
    # body_template_obj = Template('response template')

    status_code = None
    explanation = ''
    body_template_obj = Template('''\
${explanation}${br}${br}
${detail}
${html_comment}
''')

    plain_template_obj = Template('''\
${status}

${body}''')

    html_template_obj = Template('''\
<html>
 <head>
  <title>${status}</title>
 </head>
 <body>
  <h1>${status}</h1>
  ${body}
 </body>
</html>''')

    # Set this to True for responses that should have no request body
    empty_body = False

    def __init__(self, request, detail=None, headers=None, comment=None,
                 body_template=None, **kw):
        Response.__init__(self, status=self.status_code, **kw)
        Exception.__init__(self, detail)
        self.detail = self.message = detail
        if headers:
            self.headers.extend(headers)
        self.comment = comment
        if body_template is not None:
            self.body_template = body_template
            self.body_template_obj = Template(body_template)

        if self.empty_body:
            del self.content_type
            del self.content_length

    def __str__(self):
        return self.detail or self.explanation

    @asyncio.coroutine
    def write_eof(self):
        if not self.body and not self.empty_body:
            html_comment = ''
            comment = self.comment or ''
            accept = self.request.headers.get('HTTP_ACCEPT', '')
            if accept and 'html' in accept or '*/*' in accept:
                self.content_type = 'text/html'
                escape = _html_escape
                page_template = self.html_template_obj
                br = '<br/>'
                if comment:
                    html_comment = '<!-- %s -->' % escape(comment)
            else:
                self.content_type = 'text/plain'
                escape = _no_escape
                page_template = self.plain_template_obj
                br = '\n'
                if comment:
                    html_comment = escape(comment)
            args = {
                'br': br,
                'explanation': escape(self.explanation),
                'detail': escape(self.detail or ''),
                'comment': escape(comment),
                'html_comment': html_comment,
                }
            body_tmpl = self.body_template_obj
            body = body_tmpl.substitute(args)
            status = "{} {}".format(self.status, self.reason)
            page = page_template.substitute(status=status, body=body)
            page = page.encode(self.charset)
            self.body = page


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
    explanation = 'The request is accepted for processing.'


class HTTPNonAuthoritativeInformation(HTTPSuccessful):
    status_code = 203


class HTTPNoContent(HTTPSuccessful):
    status_code = 204
    empty_body = True


class HTTPResetContent(HTTPSuccessful):
    status_code = 205
    empty_body = True


class HTTPPartialContent(HTTPSuccessful):
    status_code = 206


############################################################
# 3xx redirection
############################################################


class _HTTPMove(HTTPRedirection):

    explanation = 'The resource has been moved to'
    body_template_obj = Template('''\
${explanation} ${location}; you should be redirected automatically.
${detail}
${html_comment}''')

    def __init__(self, location='', detail=None, headers=None, comment=None,
                 body_template=None, **kw):
        if location is None:
            raise ValueError("HTTP redirects need a location to redirect to.")
        super(_HTTPMove, self).__init__(
            detail=detail, headers=headers, comment=comment,
            body_template=body_template, location=location, **kw)


class HTTPMultipleChoices(_HTTPMove):
    status_code = 300


class HTTPMovedPermanently(_HTTPMove):
    status_code = 301


class HTTPFound(_HTTPMove):
    status_code = 302
    explanation = 'The resource was found at'


# This one is safe after a POST (the redirected location will be
# retrieved with GET):
class HTTPSeeOther(_HTTPMove):
    status_code = 303


class HTTPNotModified(HTTPRedirection):
    # FIXME: this should include a date or etag header
    status_code = 304
    empty_body = True


class HTTPUseProxy(_HTTPMove):
    # Not a move, but looks a little like one
    status_code = 305
    explanation = (
        'The resource must be accessed through a proxy located at')


class HTTPTemporaryRedirect(_HTTPMove):
    status_code = 307

############################################################
# 4xx client error
############################################################


class HTTPClientError(HTTPError):
    status_code = 400
    explanation = ('The server could not comply with the request since '
                   'it is either malformed or otherwise incorrect.')


class HTTPBadRequest(HTTPClientError):
    pass


class HTTPUnauthorized(HTTPClientError):
    status_code = 401
    explanation = (
        'This server could not verify that you are authorized to '
        'access the document you requested.  Either you supplied the '
        'wrong credentials (e.g., bad password), or your browser '
        'does not understand how to supply the credentials required.')


class HTTPPaymentRequired(HTTPClientError):
    status_code = 402
    explanation = ('Access was denied for financial reasons.')


class HTTPForbidden(HTTPClientError):
    status_code = 403
    explanation = ('Access was denied to this resource.')

    def __init__(self, detail=None, headers=None, comment=None,
                 body_template=None, result=None, **kw):
        HTTPClientError.__init__(self, detail=detail, headers=headers,
                                 comment=comment, body_template=body_template,
                                 **kw)
        self.result = result


class HTTPNotFound(HTTPClientError):
    status_code = 404
    explanation = ('The resource could not be found.')


class HTTPMethodNotAllowed(HTTPClientError):
    status_code = 405
    body_template_obj = Template('''\
The method ${REQUEST_METHOD} is not allowed for this resource. ${br}${br}
${detail}''')


class HTTPNotAcceptable(HTTPClientError):
    status_code = 406


class HTTPProxyAuthenticationRequired(HTTPClientError):
    status_code = 407
    explanation = ('Authentication with a local proxy is needed.')


class HTTPRequestTimeout(HTTPClientError):
    status_code = 408
    explanation = ('The server has waited too long for the request to '
                   'be sent by the client.')


class HTTPConflict(HTTPClientError):
    status_code = 409
    explanation = ('There was a conflict when trying to complete '
                   'your request.')


class HTTPGone(HTTPClientError):
    status_code = 410
    explanation = ('This resource is no longer available.  No forwarding '
                   'address is given.')


class HTTPLengthRequired(HTTPClientError):
    status_code = 411
    explanation = ('Content-Length header required.')


class HTTPPreconditionFailed(HTTPClientError):
    status_code = 412
    explanation = ('Request precondition failed.')


class HTTPRequestEntityTooLarge(HTTPClientError):
    status_code = 413
    explanation = ('The body of your request was too large for this server.')


class HTTPRequestURITooLong(HTTPClientError):
    status_code = 414
    explanation = ('The request URI was too long for this server.')


class HTTPUnsupportedMediaType(HTTPClientError):
    status_code = 415


class HTTPRequestRangeNotSatisfiable(HTTPClientError):
    status_code = 416
    explanation = ('The Range requested is not available.')


class HTTPExpectationFailed(HTTPClientError):
    status_code = 417
    explanation = ('Expectation failed.')

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
    status_code = 500
    explanation = (
        'The server has either erred or is incapable of performing '
        'the requested operation.')


class HTTPInternalServerError(HTTPServerError):
    pass


class HTTPNotImplemented(HTTPServerError):
    status_code = 501


class HTTPBadGateway(HTTPServerError):
    status_code = 502
    explanation = ('Bad gateway.')


class HTTPServiceUnavailable(HTTPServerError):
    status_code = 503
    explanation = ('The server is currently unavailable. '
                   'Please try again at a later time.')


class HTTPGatewayTimeout(HTTPServerError):
    status_code = 504
    explanation = ('The gateway has timed out.')


class HTTPVersionNotSupported(HTTPServerError):
    status_code = 505
    explanation = ('The HTTP version is not supported.')


############################################################
# UrlDispatcher implementation
############################################################

class UrlMappingMatchInfo(dict, AbstractMatchInfo):

    def __init__(self, match_dict, entry):
        super().__init__(match_dict)
        self._entry = entry

    @property
    def handler(self):
        return self._entry.handler


Entry = collections.namedtuple('Entry', 'regex method handler')


class UrlDispatcher(AbstractRouter):

    DYN = re.compile(r'^\{[_a-zA-Z][_a-zA-Z0-9]*\}$')
    GOOD = r'[^{}/]+'
    PLAIN = re.compile('^'+GOOD+'$')

    METHODS = {'POST', 'GET', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'}

    def __init__(self):
        super().__init__()
        self._urls = []

    @asyncio.coroutine
    def resolve(self, request):
        path = request.path
        method = request.method
        allowed_methods = set()
        for entry in self._urls:
            match = entry.regex.match(path)
            if match is None:
                continue
            if entry.method != method:
                allowed_methods.add(entry.method)
            else:
                break
        else:
            if allowed_methods:
                allow = ', '.join(sorted(allowed_methods))
                # add log
                raise HTTPMethodNotAllowed(
                    headers={'ALLOW', allow})
            else:
                # add log
                raise HttpErrorException(404, "Not Found")

        matchdict = match.groupdict()
        return UrlMappingMatchInfo(matchdict, entry)

    def add_route(self, method, path, handler):
        assert path.startswith('/')
        assert callable(handler), handler
        method = method.upper()
        assert method in self.METHODS, method
        regexp = []
        for part in path.split('/'):
            if not part:
                continue
            if self.DYN.match(part):
                regexp.append('(?P<'+part[1:-1]+'>'+self.GOOD+')')
            elif self.PLAIN.match(part):
                regexp.append(part)
            else:
                raise ValueError("Invalid path '{}'['{}']".format(path, part))
        pattern = '/' + '/'.join(regexp)
        if path.endswith('/') and pattern != '/':
            pattern += '/'
        try:
            compiled = re.compile('^' + pattern + '$')
        except re.error:
            raise ValueError("Invalid path '{}'".format(path))
        self._urls.append(Entry(compiled, method, handler))


############################################################
# Application implementation
############################################################

class RequestHandler(ServerHttpProtocol):

    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self._app = app

    @asyncio.coroutine
    def handle_request(self, message, payload):
        request = Request(self._app, message, payload, self.writer)
        try:
            match_info = yield from self._app.router.resolve(request)

            request._match_info = match_info
            handler = match_info.handler

            resp = handler(request)
            if (asyncio.iscoroutine(resp) or
                    isinstance(resp, asyncio.Future)):
                resp = yield from resp
            if not isinstance(resp, StreamResponse):
                raise RuntimeError(("Handler should return Response "
                                    "instance, got {!r}")
                                   .format(type(resp)))

            yield from resp.write_eof()
            if resp.keep_alive:
                # Don't need to read request body if any on closing connection
                yield from request.release()
            self.keep_alive(resp.keep_alive)

        except HTTPException as exc:
            yield from exc.write_eof()
            if exc.keep_alive:
                # Don't need to read request body if any on closing connection
                yield from request.release()
            self.keep_alive(exc.keep_alive)


class Application(dict):

    def __init__(self, loop=None, *, router=None, **kwargs):
        # TODO: explicitly accept *debug* param
        if loop is None:
            loop = asyncio.get_event_loop()
        self._kwargs = kwargs
        if router is None:
            router = UrlDispatcher()
        self._router = router
        self._loop = loop
        self._finish_callbacks = []

    @property
    def router(self):
        return self._router

    @property
    def loop(self):
        return self._loop

    def make_handler(self):
        return RequestHandler(self, loop=self._loop, **self._kwargs)

    @asyncio.coroutine
    def finish(self):
        for (cb, args, kwargs) in self._finish_callbacks:
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

    def register_on_finish(self, cb, *args, **kwargs):
        self._finish_callbacks.append((cb, args, kwargs))
