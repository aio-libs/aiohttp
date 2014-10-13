import asyncio
import http.cookies
import json

from urllib.parse import urlsplit, parse_qsl

from aiohttp.multidict import MultiDict, MutableMultiDict
from aiohttp.protocol import Response
from aiohttp.streams import EOF_MARKER


__all__ = [
    'ServerRequest',
    'ServerResponse',
    ]


class ServerResponse:

    def __init__(self, host, writer, version):
        self.headers = MutableMultiDict({'Host': host})
        self._status_code = 200
        self._cookies = http.cookies.SimpleCookie()
        self._deleted_cookies = set()
        self._headers_sent = False
        self._writer = writer
        self._version = version
        self._resp_impl = None

    def _copy_cookies(self):
        for cookie in self._cookies.values():
            value = cookie.output(header='')[1:]
            self.headers.add('Set-Cookie', value)

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

        if self._headers_sent:
            raise RuntimeError("Cannot change cookie "
                               "after sending response headers")
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
        if self._headers_sent:
            raise RuntimeError("Cannot delete cookie "
                               "after sending response headers")
        self._cookies.pop(name, None)
        self.set_cookie(name, '', max_age=0, domain=domain, path=path)
        self._deleted_cookies.add(name)

    @property
    def status_code(self):
        return self._status_code

    @status_code.setter
    def status_code(self, value):
        if self._headers_sent:
            raise RuntimeError("Cannot change HTTP status code "
                               "after sending response headers")
        assert isinstance(value, int), "Status code must be int"
        self._status_code = value

    @property
    def version(self):
        return self._version

    @version.setter
    def version(self, value):
        if self._headers_sent:
            raise RuntimeError("Cannot change HTTP version "
                               "after sending response headers")
        assert isinstance(value, ), "HTTP version must be str"
        self._version = value

    def send_headers(self):
        if self._headers_sent:
            raise RuntimeError("HTTP headers are already sent")
        self._headers_sent = True
        resp_impl = self._resp_impl = Response(self._writer,
                                               self._status_code,
                                               self._version)

        self._copy_cookies()
        resp_impl.send_headers()

    def write(self, binary):
        pass

    def write_eof(self):
        pass


class ServerRequest:

    def __init__(self, registry, match, host, message, payload, writer, *,
                 loop=None):
        if loop is None:
            loop = asyncio.get_event_loop()
        res = urlsplit(message.path)
        self._registry = registry
        self._loop = loop
        self.version = message.version
        self.method = message.method.upper()
        self.host = message.headers.get('HOST', host)
        self.host_url = 'http://' + self.host
        self.path_qs = message.path
        self.path = res.path
        self.path_url = self.host_url + self.path
        self.url = self.host_url + self.path_qs
        self.query_string = res.query
        self.args = MultiDict(parse_qsl(res.query))
        self.headers = message.headers

        # TODO: Do we need this? What is matchdict for traversal?
        # self.matchdict = {}
        self.match = match  # matchdict, route_name, handler

        self._payload = payload
        self._response = ServerResponse(host, writer, self.version)
        self._cookies = None

    @property
    def response(self):
        """Response object."""
        return self._response

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
        return self._payload

    @asyncio.coroutine
    def release(self):
        chunk = yield from self.content.readany()
        while chunk is not EOF_MARKER or chunk:
            chunk = yield from self.content.readany()

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


class UrlMatchRequest(ServerRequest):
    pass
