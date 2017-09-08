import asyncio
import collections
import datetime
import json
import re
import string
import tempfile
import types
import warnings
from email.utils import parsedate
from types import MappingProxyType
from urllib.parse import parse_qsl

from multidict import CIMultiDict, MultiDict, MultiDictProxy
from yarl import URL

from . import hdrs, multipart
from .helpers import (HeadersMixin, SimpleCookie, parse_mimetype, reify,
                      sentinel)
from .streams import EmptyStreamReader
from .web_exceptions import HTTPNotAcceptable, HTTPRequestEntityTooLarge


__all__ = ('BaseRequest', 'FileField', 'Request')

FileField = collections.namedtuple(
    'Field', 'name filename file content_type headers')

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

    def __init__(self, message, payload, protocol, writer, time_service, task,
                 loop,
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
        self._loop = loop

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
            self._loop,
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
    def scheme(self):
        """A string representing the scheme of the request.

        'http' or 'https'.
        """
        return self.url.scheme

    @property
    def secure(self):
        """A bool indicating if the request is handled with SSL or
        'secure_proxy_ssl_header' is matching

        """
        return self.url.scheme == 'https'

    @reify
    def forwarded(self):
        """ A tuple containing all parsed Forwarded header(s).

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
    def _scheme(self):
        proto = None
        if self._transport.get_extra_info('sslcontext'):
            proto = 'https'
        elif self._secure_proxy_ssl_header is not None:
            header, value = self._secure_proxy_ssl_header
            if self.headers.get(header) == value:
                proto = 'https'
        else:
            proto = next(
                (f['proto'] for f in self.forwarded if 'proto' in f), None
            )
            if not proto and hdrs.X_FORWARDED_PROTO in self._message.headers:
                proto = self._message.headers[hdrs.X_FORWARDED_PROTO]
        return proto or 'http'

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

        Hostname is resolved through the following headers, in this order:

        - Forwarded
        - X-Forwarded-Host
        - Host

        Returns str, or None if no hostname is found in the headers.
        """
        host = next(
            (f['host'] for f in self.forwarded if 'host' in f), None
        )
        if host is None:
            host = self._message.headers.get(hdrs.X_FORWARDED_HOST)
        if host is None:
            host = self._message.headers.get(hdrs.HOST)
        return host

    @reify
    def remote(self):
        """Remote IP of client initiated HTTP request.

        The IP is resolved through the following headers, in this order:

        - Forwarded
        - X-Forwarded-For
        - peername of opened socket
        """
        ip = next(
            (f['for'] for f in self.forwarded if 'for' in f), None
        )
        if ip is None:
            ips = self._message.headers.get(hdrs.X_FORWARDED_FOR)
            if ips is not None:
                ip = ips.split(',')[0].strip()
        if ip is None:
            transport = self._transport
            peername = transport.get_extra_info('peername')
            if isinstance(peername, (list, tuple)):
                ip = peername[0]
            else:
                ip = peername
        return ip

    @reify
    def url(self):
        return URL('{}://{}{}'.format(self._scheme,
                                      self.host,
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
    def json(self, *, loads=json.loads, allowed_type=None):
        """ Return BODY as JSON. If the `Content-Type` does not equal
        allowed_type, then the request is rejected.
        """

        if allowed_type is None:  # do not check the content_type
            pass
        elif isinstance(allowed_type, str):
            # parse the content_type
            content_type = self.content_type
            (mime_type, subtype, suffix, _) = parse_mimetype(content_type)
            content_type = mime_type + '/' + subtype
            if suffix != '':
                content_type += '+' + suffix

            if allowed_type != content_type:
                raise HTTPNotAcceptable()
        else:  # for other types
            raise TypeError("Unsupported type for allowed `Content-Type`")

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
