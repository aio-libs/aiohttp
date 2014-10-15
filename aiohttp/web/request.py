import asyncio
import http.cookies
import json

from urllib.parse import urlsplit, parse_qsl, unquote

from ..helpers import parse_mimetype
from ..multidict import MultiDict, MutableMultiDict
from ..protocol import Response
from ..streams import EOF_MARKER


__all__ = [
    'ServerRequest',
    'ServerStreamResponse',
    'ServerResponse',
    ]


class ServerStreamResponse:

    def __init__(self, request):
        self._request = request
        self.headers = MutableMultiDict({'Host': request.host})
        self._status_code = 200
        self._cookies = http.cookies.SimpleCookie()
        self._deleted_cookies = set()
        self._keep_alive = True

        self._resp_impl = None
        self._eof_sent = False

    def _copy_cookies(self):
        for cookie in self._cookies.values():
            value = cookie.output(header='')[1:]
            self.headers.add('Set-Cookie', value)

    def _check_sending_started(self):
        if self._request._response is not None:
            raise RuntimeError(("Response {!r} already started to send"
                                " data").format(self._request._response))

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
    def status_code(self):
        return self._status_code

    @status_code.setter
    def status_code(self, value):
        self._check_sending_started()
        assert isinstance(value, int), "Status code must be int"
        self._status_code = value

    @property
    def version(self):
        return self._version

    @version.setter
    def version(self, value):
        self._check_sending_started()
        assert isinstance(value, str), "HTTP version must be str"
        self._version = value

    @property
    def keep_alive(self):
        return self._keep_alive

    @keep_alive.setter
    def keep_alive(self, value):
        self._check_sending_started()
        self._keep_alive = bool(value)

    @property
    def content_length(self):
        l = self.headers.get('Content-Length')
        if l is None:
            return None
        else:
            return int(l)

    @content_length.setter
    def content_length(self, value):
        self._check_sending_started()
        value = int(value)
        # raise error if chunked enabled
        self.headers['Content-Length'] = str(value)

    @property
    def content_type(self):
        ctype = self.headers.get('Content-Type')
        mtype, stype, _, params = parse_mimetype(ctype)

    def set_chunked(self, chunk_size, buffered=True):
        if self.content_length is not None:
            raise RuntimeError(
                "Cannot use chunked encoding with Content-Length set up")

    def send_headers(self):
        if self._resp_impl is not None:
            raise RuntimeError("HTTP headers are already sent")
        if self._eof_sent:
            raise RuntimeError("Cannot call send_header() after write_eof()")

        self._check_sending_started()
        self._request._response = self

        resp_impl = self._resp_impl = Response(
            self._request._server_http_protocol.writer,
            self._status_code,
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
        if self._resp_impl is None:
            raise RuntimeError("No data has been sent")
        if self._eof_sent:
            return

        yield from self._resp_impl.write_eof()
        if self._resp_impl.keep_alive():
            self._request._server_http_protocol.keep_alive(self._keep_alive)
        self._eof_sent = True


class ServerResponse(ServerStreamResponse):

    def __init__(self, request, *, status_code=200, body=b'', headers=None):
        super().__init__(request)
        self.status_code = status_code
        self.body = body
        if headers is not None:
            self.headers.extend(headers)

    @property
    def body(self):
        return self._body

    @body.setter
    def body(self, body):
        if not isinstance(body, (bytes, bytearray, memoryview)):
            raise TypeError('body argument must be byte-ish (%r)',
                            type(body))
        self._check_sending_started()
        self._body = body

    @asyncio.coroutine
    def render(self):
        body = self._body
        self.content_length = len(body)
        self.write(body)


class ServerRequest:

    def __init__(self, application, message, payload, protocol, *,
                 loop=None):
        if loop is None:
            loop = asyncio.get_event_loop()
        path = unquote(message.path)
        res = urlsplit(path)
        self._application = application
        self._loop = loop
        self.version = message.version
        self._server_http_protocol = protocol
        self.method = message.method.upper()
        self.host = message.headers.get('HOST', application.host)
        self.host_url = 'http://' + self.host
        self.path_qs = path
        self.path = res.path
        self.path_url = self.host_url + self.path
        self.url = self.host_url + self.path_qs
        self.query_string = res.query
        self.args = MultiDict(parse_qsl(res.query))
        self.headers = message.headers

        # matchdict, route_name, handler
        # or information about traversal lookup
        self._match_info = None  # initialized after route resolving

        self._payload = payload
        self._response = None
        self._cookies = None

    @property
    def match_info(self):
        return self._match_info

    @property
    def application(self):
        """Application instance."""
        return self._application

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

        if self._payload is None:
            return None
        body = bytearray()
        while True:
            chunk = yield from self._payload.readany()
            body.extend(chunk)
            if chunk is EOF_MARKER:
                break
        return bytes(body)

    @asyncio.coroutine
    def text(self, *, encoding='utf-8'):
        bytes_body = yield from self.read()
        if bytes_body is None:
            return None
        return bytes_body.encode(encoding)

    @asyncio.coroutine
    def json(self, *, encoding='utf-8', loader=json.loads):
        body = yield from self.text(encoding=encoding)
        if body is None:
            return None
        return loader(body)

    @asyncio.coroutine
    def POST(self, *, encoding='utf-8'):
        body = yield from self.text(encoding=encoding)
        return parse_x_www_form_encoding(body)

    @asyncio.coroutine
    def start_websocket(self):
        """Upgrade connection to websocket.

        Returns (reader, writer) pair.
        """
