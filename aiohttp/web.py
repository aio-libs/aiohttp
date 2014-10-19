import asyncio
import binascii
import collections
import cgi
import http.cookies
import io
import json
import re
import weakref

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
    'UrlDispatch',
    'UrlMappingMatchInfo',
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
        raw = self.headers.get('Content-Type')
        if self._stored_content_type != raw:
            self._parse_content_type(raw)
        return self._content_type

    @property
    def charset(self):
        # Assumes that charset is UTF8 if not specified
        raw = self.headers.get('Content-Type')
        if self._stored_content_type != raw:
            self._parse_content_type(raw)
        return self._content_dict.get('charset')

    @property
    def content_length(self):
        l = self.headers.get('Content-Length')
        if l is None:
            return None
        else:
            return int(l)


class StreamResponse(HeadersMixin):

    def __init__(self, request):
        self._request = request
        self.headers = CaseInsensitiveMutableMultiDict()
        self._status = 200
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
    def status(self):
        return self._status

    @status.setter
    def status(self, value):
        self._check_sending_started()
        if not isinstance(value, int):
            raise TypeError("Status code must be int")
        self._status = value

    @property
    def keep_alive(self):
        return self._keep_alive

    def force_close(self):
        self._keep_alive = False

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
            self._request.version)

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

    def __init__(self, request, body=None, *, status=200, headers=None):
        super().__init__(request)
        self.status = status
        self.body = body
        if headers is not None:
            self.headers.extend(headers)

    @property
    def body(self):
        return self._body

    @body.setter
    def body(self, body):
        if body is not None and not isinstance(body,
                                               (bytes, bytearray, memoryview)):
            raise TypeError('body argument must be byte-ish (%r)',
                            type(body))
        self._check_sending_started()
        self._body = body
        if body is not None:
            self.content_length = len(body)
        else:
            self.content_length = 0

    @asyncio.coroutine
    def render(self):
        body = self._body
        self.send_headers()
        if body is not None:
            self.write(body)
        yield from self.write_eof()


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
        return self._method

    @property
    def version(self):
        return self._version

    @property
    def host(self):
        return self._host

    @property
    def path_qs(self):
        return self._path_qs

    @property
    def path(self):
        return self._path

    @property
    def query_string(self):
        return self._query_string

    @property
    def GET(self):
        if self._get is None:
            self._get = MultiDict(parse_qsl(self._query_string))
        return self._get

    @property
    def headers(self):
        return self._headers

    @property
    def keep_alive(self):
        """Is keepalive enabled by client?"""
        return self._keep_alive

    @property
    def match_info(self):
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

        Returns bytes object with full request content or None if
        request has no BODY.
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
        bytes_body = yield from self.read()
        encoding = self.charset or 'utf-8'
        return bytes_body.decode(encoding)

    @asyncio.coroutine
    def json(self, *, loader=json.loads):
        body = yield from self.text()
        return loader(body)

    @asyncio.coroutine
    def POST(self):
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


class UrlMappingMatchInfo(AbstractMatchInfo):

    def __init__(self, matchdict, entry):
        self._matchdict = matchdict
        self._entry = entry

    @property
    def handler(self):
        return self._entry.handler

    @property
    def matchdict(self):
        return self._matchdict


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
                raise HttpErrorException(405, "Method Not Allowed",
                                         headers=(('Allow', allow),))
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


class RequestHandler(ServerHttpProtocol):

    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self._app = app

    @asyncio.coroutine
    def handle_request(self, message, payload):
        request = Request(self._app, message, payload, self.writer)
        match_info = yield from self._app.router.resolve(request)
        if match_info is not None:
            request._match_info = match_info
            handler = match_info.handler

            resp = handler(request)
            if (asyncio.iscoroutine(resp) or
                    isinstance(resp, asyncio.Future)):
                resp = yield from resp

            if isinstance(resp, Response):
                yield from resp.render()
            else:
                raise RuntimeError(("Handler should return Response "
                                    "instance, got {!r}")
                                   .format(type(resp)))

            yield from resp.write_eof()
            if resp.keep_alive:
                # Don't need to read request body if any on closing connection
                yield from request.release()
            self.keep_alive(resp.keep_alive)
        else:
            raise HttpErrorException(404, "Not Found")


class Application(dict, asyncio.AbstractServer):

    def __init__(self, *, loop=None, router=None, **kwargs):
        # TODO: explicitly accept *debug* param
        self._kwargs = kwargs
        if loop is None:
            loop = asyncio.get_event_loop()
        if router is None:
            router = UrlDispatcher()
        self._router = router
        self._loop = loop

    @property
    def router(self):
        return self._router

    def make_handler(self):
        return RequestHandler(self, loop=self._loop, **self._kwargs)

    def close(self):
        pass

    def register_on_close(self, cb):
        pass

    @asyncio.coroutine
    def wait_closed(self):
        pass
