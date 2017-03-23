import asyncio
import collections
import datetime
import json
import re
import tempfile
import warnings
from email.utils import parsedate
from types import MappingProxyType
from urllib.parse import parse_qsl

from multidict import CIMultiDict, MultiDict, MultiDictProxy
from yarl import URL

from . import hdrs, multipart
from .helpers import HeadersMixin, SimpleCookie, reify, sentinel
from .web_exceptions import HTTPRequestEntityTooLarge

__all__ = ('BaseRequest', 'FileField', 'Request')

FileField = collections.namedtuple(
    'Field', 'name filename file content_type headers')


############################################################
# HTTP Request
############################################################


class BaseRequest(collections.MutableMapping, HeadersMixin):

    POST_METHODS = {hdrs.METH_PATCH, hdrs.METH_POST, hdrs.METH_PUT,
                    hdrs.METH_TRACE, hdrs.METH_DELETE}

    def __init__(self, message, payload, protocol, writer, time_service, task,
                 *, secure_proxy_ssl_header=None, client_max_size=1024**2):
        self._message = message
        self._protocol = protocol
        self._transport = protocol.transport
        self._writer = writer

        self._payload = payload
        self._headers = message.headers
        self._method = message.method
        self._version = message.version
        self._rel_url = message.url
        self._post = None
        self._read_bytes = None

        self._secure_proxy_ssl_header = secure_proxy_ssl_header
        self._time_service = time_service
        self._state = {}
        self._cache = {}
        self._task = task
        self._client_max_size = client_max_size

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
            rel_url = URL(rel_url)
            dct['url'] = rel_url
            dct['path'] = str(rel_url)
        if headers is not sentinel:
            dct['headers'] = CIMultiDict(headers)
            dct['raw_headers'] = tuple((k.encode('utf-8'), v.encode('utf-8'))
                                       for k, v in headers.items())

        message = self._message._replace(**dct)

        return self.__class__(
            message,
            self._payload,
            self._protocol,
            self._writer,
            self._time_service,
            self._task,
            secure_proxy_ssl_header=self._secure_proxy_ssl_header)

    @property
    def task(self):
        return self._task

    @property
    def protocol(self):
        return self._protocol

    @property
    def transport(self):
        return self._protocol.transport

    @property
    def writer(self):
        return self._writer

    @property
    def message(self):
        return self._message

    @property
    def rel_url(self):
        return self._rel_url

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

    @property
    def scheme(self):
        """A string representing the scheme of the request.

        'http' or 'https'.
        """
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

    @reify
    def host(self):
        """Read only property for getting *HOST* header of request.

        Returns str or None if HTTP request has no HOST header.
        """
        return self._message.headers.get(hdrs.HOST)

    @reify
    def url(self):
        return URL('{}://{}{}'.format(self._scheme,
                                      self._message.headers.get(hdrs.HOST),
                                      str(self._rel_url)))

    @property
    def path(self):
        """The URL including *PATH INFO* without the host or scheme.

        E.g., ``/app/blog``
        """
        return self._rel_url.path

    @reify
    def path_qs(self):
        """The URL including PATH_INFO and the query string.

        E.g, /app/blog?id=10
        """
        return str(self._rel_url)

    @property
    def raw_path(self):
        """ The URL including raw *PATH INFO* without the host or scheme.
        Warning, the path is unquoted and may contains non valid URL characters

        E.g., ``/my%2Fpath%7Cwith%21some%25strange%24characters``
        """
        return self._message.path

    @property
    def query(self):
        """A multidict with all the variables in the query string."""
        return self._rel_url.query

    @property
    def GET(self):
        """A multidict with all the variables in the query string."""
        warnings.warn("GET property is deprecated, use .query instead",
                      DeprecationWarning)
        return self._rel_url.query

    @property
    def query_string(self):
        """The query string in the URL.

        E.g., id=10
        """
        return self._rel_url.query_string

    @property
    def headers(self):
        """A case-insensitive multidict proxy with all headers."""
        return self._headers

    @property
    def raw_headers(self):
        """A sequence of pars for all headers."""
        return self._message.raw_headers

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

    @property
    def keep_alive(self):
        """Is keepalive enabled by client?"""
        return not self._message.should_close

    @property
    def time_service(self):
        """Time service"""
        return self._time_service

    @reify
    def cookies(self):
        """Return request cookies.

        A read-only dictionary-like object.
        """
        raw = self.headers.get(hdrs.COOKIE, '')
        parsed = SimpleCookie(raw)
        return MappingProxyType(
            {key: val.value for key, val in parsed.items()})

    @property
    def http_range(self, *, _RANGE=hdrs.RANGE):
        """The content of Range HTTP header.

        Return a slice instance.

        """
        rng = self._headers.get(_RANGE)
        start, end = None, None
        if rng is not None:
            try:
                pattern = r'^bytes=(\d*)-(\d*)$'
                start, end = re.findall(pattern, rng)[0]
            except IndexError:  # pattern was not found in header
                raise ValueError("range not in acceptible format")

            end = int(end) if end else None
            start = int(start) if start else None

            if start is None and end is not None:
                # end with no start is to return tail of content
                end = -end

            if start is not None and end is not None:
                # end is inclusive in range header, exclusive for slice
                end += 1

                if start >= end:
                    raise ValueError('start cannot be after end')

            if start is end is None:  # No valid range supplied
                raise ValueError('No start or end of range specified')
        return slice(start, end, 1)

    @property
    def content(self):
        """Return raw payload stream."""
        return self._payload

    @property
    def has_body(self):
        """Return True if request has HTTP BODY, False otherwise."""
        return not self._payload.at_eof()

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
                if self._client_max_size \
                        and len(body) >= self._client_max_size:
                    raise HTTPRequestEntityTooLarge
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
    def json(self, *, loads=json.loads):
        """Return BODY as JSON."""
        body = yield from self.text()
        return loads(body)

    @asyncio.coroutine
    def multipart(self, *, reader=multipart.MultipartReader):
        """Return async iterator to process BODY as multipart."""
        return reader(self._headers, self._payload)

    @asyncio.coroutine
    def post(self):
        """Return POST parameters."""
        if self._post is not None:
            return self._post
        if self._method not in self.POST_METHODS:
            self._post = MultiDictProxy(MultiDict())
            return self._post

        content_type = self.content_type
        if (content_type not in ('',
                                 'application/x-www-form-urlencoded',
                                 'multipart/form-data')):
            self._post = MultiDictProxy(MultiDict())
            return self._post

        out = MultiDict()

        if content_type == 'multipart/form-data':
            multipart = yield from self.multipart()

            field = yield from multipart.next()
            while field is not None:
                size = 0
                max_size = self._client_max_size
                content_type = field.headers.get(hdrs.CONTENT_TYPE)

                if field.filename:
                    # store file in temp file
                    tmp = tempfile.TemporaryFile()
                    chunk = yield from field.read_chunk(size=2**16)
                    while chunk:
                        chunk = field.decode(chunk)
                        tmp.write(chunk)
                        size += len(chunk)
                        if max_size > 0 and size > max_size:
                            raise ValueError(
                                'Maximum request body size exceeded')
                        chunk = yield from field.read_chunk(size=2**16)
                    tmp.seek(0)

                    ff = FileField(field.name, field.filename,
                                   tmp, content_type, field.headers)
                    out.add(field.name, ff)
                else:
                    value = yield from field.read(decode=True)
                    if content_type is None or \
                            content_type.startswith('text/'):
                        charset = field.get_charset(default='utf-8')
                        value = value.decode(charset)
                    out.add(field.name, value)
                    size += len(value)
                    if max_size > 0 and size > max_size:
                        raise ValueError(
                            'Maximum request body size exceeded')

                field = yield from multipart.next()
        else:
            data = yield from self.read()
            if data:
                charset = self.charset or 'utf-8'
                out.extend(
                    parse_qsl(
                        data.rstrip().decode(charset),
                        encoding=charset))

        self._post = MultiDictProxy(out)
        return self._post

    def __repr__(self):
        ascii_encodable_path = self.path.encode('ascii', 'backslashreplace') \
            .decode('ascii')
        return "<{} {} {} >".format(self.__class__.__name__,
                                    self._method, ascii_encodable_path)

    @asyncio.coroutine
    def _prepare_hook(self, response):
        return
        yield  # pragma: no cover


class Request(BaseRequest):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # matchdict, route_name, handler
        # or information about traversal lookup
        self._match_info = None  # initialized after route resolving

    @property
    def match_info(self):
        """Result of route resolving."""
        return self._match_info

    @reify
    def app(self):
        """Application instance."""
        return self._match_info.apps[-1]

    @asyncio.coroutine
    def _prepare_hook(self, response):
        match_info = self._match_info
        if match_info is None:
            return
        for app in match_info.apps:
            yield from app.on_response_prepare.send(self, response)
