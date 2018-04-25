import asyncio
import collections
import datetime
import io
import json
import re
import socket
import string
import tempfile
import types
import warnings
from email.utils import parsedate
from http.cookies import SimpleCookie
from types import MappingProxyType
from urllib.parse import parse_qsl

import attr
from multidict import CIMultiDict, CIMultiDictProxy, MultiDict, MultiDictProxy
from yarl import URL

from . import hdrs, multipart
from .helpers import DEBUG, ChainMapProxy, HeadersMixin, reify, sentinel
from .streams import EmptyStreamReader
from .web_exceptions import HTTPRequestEntityTooLarge


__all__ = ('BaseRequest', 'FileField', 'Request')


@attr.s(frozen=True, slots=True)
class FileField:
    name = attr.ib(type=str)
    filename = attr.ib(type=str)
    file = attr.ib(type=io.BufferedReader)
    content_type = attr.ib(type=str)
    headers = attr.ib(type=CIMultiDictProxy)


_TCHAR = string.digits + string.ascii_letters + r"!#$%&'*+.^_`|~-"
# '-' at the end to prevent interpretation as range in a char class

_TOKEN = r'[{tchar}]+'.format(tchar=_TCHAR)

_QDTEXT = r'[{}]'.format(
    r''.join(chr(c) for c in (0x09, 0x20, 0x21) + tuple(range(0x23, 0x7F))))
# qdtext includes 0x5C to escape 0x5D ('\]')
# qdtext excludes obs-text (because obsoleted, and encoding not specified)

_QUOTED_PAIR = r'\\[\t !-~]'

_QUOTED_STRING = r'"(?:{quoted_pair}|{qdtext})*"'.format(
    qdtext=_QDTEXT, quoted_pair=_QUOTED_PAIR)

_FORWARDED_PAIR = (
    r'({token})=({token}|{quoted_string})'.format(
        token=_TOKEN,
        quoted_string=_QUOTED_STRING))

_QUOTED_PAIR_REPLACE_RE = re.compile(r'\\([\t !-~])')
# same pattern as _QUOTED_PAIR but contains a capture group

_FORWARDED_PAIR_RE = re.compile(_FORWARDED_PAIR)

############################################################
# HTTP Request
############################################################


class BaseRequest(collections.MutableMapping, HeadersMixin):

    POST_METHODS = {hdrs.METH_PATCH, hdrs.METH_POST, hdrs.METH_PUT,
                    hdrs.METH_TRACE, hdrs.METH_DELETE}

    ATTRS = HeadersMixin.ATTRS | frozenset([
        '_message', '_protocol', '_payload_writer', '_payload', '_headers',
        '_method', '_version', '_rel_url', '_post', '_read_bytes',
        '_state', '_cache', '_task', '_client_max_size', '_loop'])

    def __init__(self, message, payload, protocol, payload_writer, task,
                 loop,
                 *, client_max_size=1024**2,
                 state=None,
                 scheme=None, host=None, remote=None):
        if state is None:
            state = {}
        self._message = message
        self._protocol = protocol
        self._payload_writer = payload_writer

        self._payload = payload
        self._headers = message.headers
        self._method = message.method
        self._version = message.version
        self._rel_url = message.url
        self._post = None
        self._read_bytes = None

        self._state = state
        self._cache = {}
        self._task = task
        self._client_max_size = client_max_size
        self._loop = loop

        if scheme is not None:
            self._cache['scheme'] = scheme
        if host is not None:
            self._cache['host'] = host
        if remote is not None:
            self._cache['remote'] = remote

    def clone(self, *, method=sentinel, rel_url=sentinel,
              headers=sentinel, scheme=sentinel, host=sentinel,
              remote=sentinel):
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

        kwargs = {}
        if scheme is not sentinel:
            kwargs['scheme'] = scheme
        if host is not sentinel:
            kwargs['host'] = host
        if remote is not sentinel:
            kwargs['remote'] = remote

        return self.__class__(
            message,
            self._payload,
            self._protocol,
            self._payload_writer,
            self._task,
            self._loop,
            client_max_size=self._client_max_size,
            state=self._state.copy(),
            **kwargs)

    @property
    def task(self):
        return self._task

    @property
    def protocol(self):
        return self._protocol

    @property
    def transport(self):
        if self._protocol is None:
            return None
        return self._protocol.transport

    @property
    def writer(self):
        return self._payload_writer

    @property
    def message(self):
        return self._message

    @property
    def rel_url(self):
        return self._rel_url

    @property
    def loop(self):
        return self._loop

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
    def secure(self):
        """A bool indicating if the request is handled with SSL."""
        return self.scheme == 'https'

    @reify
    def forwarded(self):
        """A tuple containing all parsed Forwarded header(s).

        Makes an effort to parse Forwarded headers as specified by RFC 7239:

        - It adds one (immutable) dictionary per Forwarded 'field-value', ie
          per proxy. The element corresponds to the data in the Forwarded
          field-value added by the first proxy encountered by the client. Each
          subsequent item corresponds to those added by later proxies.
        - It checks that every value has valid syntax in general as specified
          in section 4: either a 'token' or a 'quoted-string'.
        - It un-escapes found escape sequences.
        - It does NOT validate 'by' and 'for' contents as specified in section
          6.
        - It does NOT validate 'host' contents (Host ABNF).
        - It does NOT validate 'proto' contents for valid URI scheme names.

        Returns a tuple containing one or more immutable dicts
        """
        elems = []
        for field_value in self._message.headers.getall(hdrs.FORWARDED, ()):
            length = len(field_value)
            pos = 0
            need_separator = False
            elem = {}
            elems.append(types.MappingProxyType(elem))
            while 0 <= pos < length:
                match = _FORWARDED_PAIR_RE.match(field_value, pos)
                if match is not None:           # got a valid forwarded-pair
                    if need_separator:
                        # bad syntax here, skip to next comma
                        pos = field_value.find(',', pos)
                    else:
                        (name, value) = match.groups()
                        if value[0] == '"':
                            # quoted string: remove quotes and unescape
                            value = _QUOTED_PAIR_REPLACE_RE.sub(r'\1',
                                                                value[1:-1])
                        elem[name.lower()] = value
                        pos += len(match.group(0))
                        need_separator = True
                elif field_value[pos] == ',':      # next forwarded-element
                    need_separator = False
                    elem = {}
                    elems.append(types.MappingProxyType(elem))
                    pos += 1
                elif field_value[pos] == ';':      # next forwarded-pair
                    need_separator = False
                    pos += 1
                elif field_value[pos] in ' \t':
                    # Allow whitespace even between forwarded-pairs, though
                    # RFC 7239 doesn't. This simplifies code and is in line
                    # with Postel's law.
                    pos += 1
                else:
                    # bad syntax here, skip to next comma
                    pos = field_value.find(',', pos)
        return tuple(elems)

    @reify
    def scheme(self):
        """A string representing the scheme of the request.

        Hostname is resolved in this order:

        - overridden value by .clone(scheme=new_scheme) call.
        - type of connection to peer: HTTPS if socket is SSL, HTTP otherwise.

        'http' or 'https'.
        """
        if self.transport.get_extra_info('sslcontext'):
            return 'https'
        else:
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
        """Hostname of the request.

        Hostname is resolved in this order:

        - overridden value by .clone(host=new_host) call.
        - HOST HTTP header
        - socket.getfqdn() value
        """
        host = self._message.headers.get(hdrs.HOST)
        if host is not None:
            return host
        else:
            return socket.getfqdn()

    @reify
    def remote(self):
        """Remote IP of client initiated HTTP request.

        The IP is resolved in this order:

        - overridden value by .clone(remote=new_remote) call.
        - peername of opened socket
        """
        if self.transport is None:
            return None
        peername = self.transport.get_extra_info('peername')
        if isinstance(peername, (list, tuple)):
            return peername[0]
        else:
            return peername

    @reify
    def url(self):
        url = URL.build(scheme=self.scheme, host=self.host)
        return url.join(self._rel_url)

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

    @staticmethod
    def _http_date(_date_str):
        """Process a date string, return a datetime object
        """
        if _date_str is not None:
            timetuple = parsedate(_date_str)
            if timetuple is not None:
                return datetime.datetime(*timetuple[:6],
                                         tzinfo=datetime.timezone.utc)
        return None

    @reify
    def if_modified_since(self, _IF_MODIFIED_SINCE=hdrs.IF_MODIFIED_SINCE):
        """The value of If-Modified-Since HTTP header, or None.

        This header is represented as a `datetime` object.
        """
        return self._http_date(self.headers.get(_IF_MODIFIED_SINCE))

    @reify
    def if_unmodified_since(self,
                            _IF_UNMODIFIED_SINCE=hdrs.IF_UNMODIFIED_SINCE):
        """The value of If-Unmodified-Since HTTP header, or None.

        This header is represented as a `datetime` object.
        """
        return self._http_date(self.headers.get(_IF_UNMODIFIED_SINCE))

    @reify
    def if_range(self, _IF_RANGE=hdrs.IF_RANGE):
        """The value of If-Range HTTP header, or None.

        This header is represented as a `datetime` object.
        """
        return self._http_date(self.headers.get(_IF_RANGE))

    @property
    def keep_alive(self):
        """Is keepalive enabled by client?"""
        return not self._message.should_close

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
                raise ValueError("range not in acceptable format")

            end = int(end) if end else None
            start = int(start) if start else None

            if start is None and end is not None:
                # end with no start is to return tail of content
                start = -end
                end = None

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
        """Return True if request's HTTP BODY can be read, False otherwise."""
        warnings.warn(
            "Deprecated, use .can_read_body #2005",
            DeprecationWarning, stacklevel=2)
        return not self._payload.at_eof()

    @property
    def can_read_body(self):
        """Return True if request's HTTP BODY can be read, False otherwise."""
        return not self._payload.at_eof()

    @property
    def body_exists(self):
        """Return True if request has HTTP BODY, False otherwise."""
        return type(self._payload) is not EmptyStreamReader

    async def release(self):
        """Release request.

        Eat unread part of HTTP BODY if present.
        """
        while not self._payload.at_eof():
            await self._payload.readany()

    async def read(self):
        """Read request body if present.

        Returns bytes object with full request content.
        """
        if self._read_bytes is None:
            body = bytearray()
            while True:
                chunk = await self._payload.readany()
                body.extend(chunk)
                if self._client_max_size \
                        and len(body) >= self._client_max_size:
                    raise HTTPRequestEntityTooLarge
                if not chunk:
                    break
            self._read_bytes = bytes(body)
        return self._read_bytes

    async def text(self):
        """Return BODY as text using encoding from .charset."""
        bytes_body = await self.read()
        encoding = self.charset or 'utf-8'
        return bytes_body.decode(encoding)

    async def json(self, *, loads=json.loads):
        """Return BODY as JSON."""
        body = await self.text()
        return loads(body)

    async def multipart(self, *, reader=multipart.MultipartReader):
        """Return async iterator to process BODY as multipart."""
        return reader(self._headers, self._payload)

    async def post(self):
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
            multipart = await self.multipart()

            field = await multipart.next()
            while field is not None:
                size = 0
                max_size = self._client_max_size
                content_type = field.headers.get(hdrs.CONTENT_TYPE)

                if field.filename:
                    # store file in temp file
                    tmp = tempfile.TemporaryFile()
                    chunk = await field.read_chunk(size=2**16)
                    while chunk:
                        chunk = field.decode(chunk)
                        tmp.write(chunk)
                        size += len(chunk)
                        if 0 < max_size < size:
                            raise ValueError(
                                'Maximum request body size exceeded')
                        chunk = await field.read_chunk(size=2**16)
                    tmp.seek(0)

                    ff = FileField(field.name, field.filename,
                                   tmp, content_type, field.headers)
                    out.add(field.name, ff)
                else:
                    value = await field.read(decode=True)
                    if content_type is None or \
                            content_type.startswith('text/'):
                        charset = field.get_charset(default='utf-8')
                        value = value.decode(charset)
                    out.add(field.name, value)
                    size += len(value)
                    if 0 < max_size < size:
                        raise ValueError(
                            'Maximum request body size exceeded')

                field = await multipart.next()
        else:
            data = await self.read()
            if data:
                charset = self.charset or 'utf-8'
                out.extend(
                    parse_qsl(
                        data.rstrip().decode(charset),
                        keep_blank_values=True,
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

    ATTRS = BaseRequest.ATTRS | frozenset(['_match_info'])

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # matchdict, route_name, handler
        # or information about traversal lookup
        self._match_info = None  # initialized after route resolving

    if DEBUG:
        def __setattr__(self, name, val):
            if name not in self.ATTRS:
                warnings.warn("Setting custom {}.{} attribute "
                              "is discouraged".format(self.__class__.__name__,
                                                      name),
                              DeprecationWarning,
                              stacklevel=2)
            super().__setattr__(name, val)

    def clone(self, *, method=sentinel, rel_url=sentinel,
              headers=sentinel, scheme=sentinel, host=sentinel,
              remote=sentinel):
        ret = super().clone(method=method,
                            rel_url=rel_url,
                            headers=headers,
                            scheme=scheme,
                            host=host,
                            remote=remote)
        ret._match_info = self._match_info
        return ret

    @property
    def match_info(self):
        """Result of route resolving."""
        return self._match_info

    @property
    def app(self):
        """Application instance."""
        return self._match_info.current_app

    @property
    def config_dict(self):
        lst = self._match_info.apps
        app = self.app
        idx = lst.index(app)
        sublist = list(reversed(lst[:idx + 1]))
        return ChainMapProxy(sublist)

    async def _prepare_hook(self, response):
        match_info = self._match_info
        if match_info is None:
            return
        for app in match_info.apps:
            await app.on_response_prepare.send(self, response)
