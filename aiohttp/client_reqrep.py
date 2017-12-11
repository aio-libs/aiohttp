import asyncio
import codecs
import collections
import io
import json
import ssl
import sys
import traceback
import warnings
from collections import namedtuple
from hashlib import md5, sha1, sha256
from http.cookies import CookieError, Morsel, SimpleCookie
from types import MappingProxyType

from multidict import CIMultiDict, CIMultiDictProxy, MultiDict, MultiDictProxy
from yarl import URL

from . import hdrs, helpers, http, multipart, payload
from .client_exceptions import (ClientConnectionError, ClientOSError,
                                ClientResponseError, ContentTypeError,
                                InvalidURL)
from .formdata import FormData
from .helpers import HeadersMixin, TimerNoop, noop, reify, set_result
from .http import SERVER_SOFTWARE, HttpVersion10, HttpVersion11, PayloadWriter
from .log import client_logger
from .streams import StreamReader


try:
    import cchardet as chardet
except ImportError:  # pragma: no cover
    import chardet

try:
    import aiosocks
except ImportError:  # pragma: no cover
    aiosocks = None


__all__ = ('ClientRequest', 'ClientResponse', 'RequestInfo')


ContentDisposition = collections.namedtuple(
    'ContentDisposition', ('type', 'parameters', 'filename'))


RequestInfo = collections.namedtuple(
    'RequestInfo', ('url', 'method', 'headers'))


HASHFUNC_BY_DIGESTLEN = {
    16: md5,
    20: sha1,
    32: sha256,
}


_SSL_OP_NO_COMPRESSION = getattr(ssl, "OP_NO_COMPRESSION", 0)


ConnectionKey = namedtuple('ConnectionKey', ['host', 'port', 'ssl'])


class ClientRequest:
    GET_METHODS = {
        hdrs.METH_GET,
        hdrs.METH_HEAD,
        hdrs.METH_OPTIONS,
        hdrs.METH_TRACE,
    }
    POST_METHODS = {hdrs.METH_PATCH, hdrs.METH_POST, hdrs.METH_PUT}
    ALL_METHODS = GET_METHODS.union(POST_METHODS).union({hdrs.METH_DELETE})

    DEFAULT_HEADERS = {
        hdrs.ACCEPT: '*/*',
        hdrs.ACCEPT_ENCODING: 'gzip, deflate',
    }

    body = b''
    auth = None
    response = None
    response_class = None

    _writer = None  # async task for streaming data
    _continue = None  # waiter future for '100 Continue' response

    # N.B.
    # Adding __del__ method with self._writer closing doesn't make sense
    # because _writer is instance method, thus it keeps a reference to self.
    # Until writer has finished finalizer will not be called.

    def __init__(self, method, url, *,
                 params=None, headers=None, skip_auto_headers=frozenset(),
                 data=None, cookies=None,
                 auth=None, version=http.HttpVersion11, compress=None,
                 chunked=None, expect100=False,
                 loop=None, response_class=None,
                 proxy=None, proxy_auth=None,
                 timer=None, session=None, auto_decompress=True,
                 verify_ssl=None, fingerprint=None, ssl_context=None,
                 proxy_headers=None, socks_remote_resolve=True):

        if verify_ssl is False and ssl_context is not None:
            raise ValueError(
                "Either disable ssl certificate validation by "
                "verify_ssl=False or specify ssl_context, not both.")

        if loop is None:
            loop = asyncio.get_event_loop()

        assert isinstance(url, URL), url
        assert isinstance(proxy, (URL, type(None))), proxy
        self._session = session
        if params:
            q = MultiDict(url.query)
            url2 = url.with_query(params)
            q.extend(url2.query)
            url = url.with_query(q)
        self.url = url.with_fragment(None)
        self.original_url = url
        self.method = method.upper()
        self.chunked = chunked
        self.compress = compress
        self.loop = loop
        self.length = None
        self.response_class = response_class or ClientResponse
        self._timer = timer if timer is not None else TimerNoop()
        self._auto_decompress = auto_decompress
        self._verify_ssl = verify_ssl
        self._ssl_context = ssl_context

        if loop.get_debug():
            self._source_traceback = traceback.extract_stack(sys._getframe(1))

        self.update_version(version)
        self.update_host(url)
        self.update_headers(headers)
        self.update_auto_headers(skip_auto_headers)
        self.update_cookies(cookies)
        self.update_content_encoding(data)
        self.update_auth(auth)
        self.update_proxy(
            proxy, proxy_auth, proxy_headers, socks_remote_resolve)
        self.update_fingerprint(fingerprint)

        self.update_body_from_data(data)
        if data or self.method not in self.GET_METHODS:
            self.update_transfer_encoding()
        self.update_expect_continue(expect100)

    @property
    def connection_key(self):
        return ConnectionKey(self.host, self.port, self.ssl)

    @property
    def host(self):
        return self.url.host

    @property
    def port(self):
        return self.url.port

    @property
    def request_info(self):
        return RequestInfo(self.url, self.method, self.headers)

    def update_host(self, url):
        """Update destination host, port and connection type (ssl)."""
        # get host/port
        if not url.host:
            raise InvalidURL(url)

        # basic auth info
        username, password = url.user, url.password
        if username:
            self.auth = helpers.BasicAuth(username, password or '')

        # Record entire netloc for usage in host header

        scheme = url.scheme
        self.ssl = scheme in ('https', 'wss')

    def update_version(self, version):
        """Convert request version to two elements tuple.

        parser HTTP version '1.1' => (1, 1)
        """
        if isinstance(version, str):
            v = [l.strip() for l in version.split('.', 1)]
            try:
                version = int(v[0]), int(v[1])
            except ValueError:
                raise ValueError(
                    'Can not parse http version number: {}'
                    .format(version)) from None
        self.version = version

    def update_headers(self, headers):
        """Update request headers."""
        self.headers = CIMultiDict()
        if headers:
            if isinstance(headers, (dict, MultiDictProxy, MultiDict)):
                headers = headers.items()

            for key, value in headers:
                self.headers.add(key, value)

    def update_auto_headers(self, skip_auto_headers):
        self.skip_auto_headers = CIMultiDict(
            (hdr, None) for hdr in sorted(skip_auto_headers))
        used_headers = self.headers.copy()
        used_headers.extend(self.skip_auto_headers)

        for hdr, val in self.DEFAULT_HEADERS.items():
            if hdr not in used_headers:
                self.headers.add(hdr, val)

        # add host
        if hdrs.HOST not in used_headers:
            netloc = self.url.raw_host
            if not self.url.is_default_port():
                netloc += ':' + str(self.url.port)
            self.headers[hdrs.HOST] = netloc

        if hdrs.USER_AGENT not in used_headers:
            self.headers[hdrs.USER_AGENT] = SERVER_SOFTWARE

    def update_cookies(self, cookies):
        """Update request cookies header."""
        if not cookies:
            return

        c = SimpleCookie()
        if hdrs.COOKIE in self.headers:
            c.load(self.headers.get(hdrs.COOKIE, ''))
            del self.headers[hdrs.COOKIE]

        for name, value in cookies.items():
            if isinstance(value, Morsel):
                # Preserve coded_value
                mrsl_val = value.get(value.key, Morsel())
                mrsl_val.set(value.key, value.value, value.coded_value)
                c[name] = mrsl_val
            else:
                c[name] = value

        self.headers[hdrs.COOKIE] = c.output(header='', sep=';').strip()

    def update_content_encoding(self, data):
        """Set request content encoding."""
        if not data:
            return

        enc = self.headers.get(hdrs.CONTENT_ENCODING, '').lower()
        if enc:
            if self.compress:
                raise ValueError(
                    'compress can not be set '
                    'if Content-Encoding header is set')
        elif self.compress:
            if not isinstance(self.compress, str):
                self.compress = 'deflate'
            self.headers[hdrs.CONTENT_ENCODING] = self.compress
            self.chunked = True  # enable chunked, no need to deal with length

    def update_transfer_encoding(self):
        """Analyze transfer-encoding header."""
        te = self.headers.get(hdrs.TRANSFER_ENCODING, '').lower()

        if 'chunked' in te:
            if self.chunked:
                raise ValueError(
                    'chunked can not be set '
                    'if "Transfer-Encoding: chunked" header is set')

        elif self.chunked:
            if hdrs.CONTENT_LENGTH in self.headers:
                raise ValueError(
                    'chunked can not be set '
                    'if Content-Length header is set')

            self.headers[hdrs.TRANSFER_ENCODING] = 'chunked'
        else:
            if hdrs.CONTENT_LENGTH not in self.headers:
                self.headers[hdrs.CONTENT_LENGTH] = str(len(self.body))

    def update_auth(self, auth):
        """Set basic auth."""
        if auth is None:
            auth = self.auth
        if auth is None:
            return

        if not isinstance(auth, helpers.BasicAuth):
            raise TypeError('BasicAuth() tuple is required instead')

        self.headers[hdrs.AUTHORIZATION] = auth.encode()

    def update_body_from_data(self, body):
        if not body:
            return

        # FormData
        if isinstance(body, FormData):
            body = body()

        try:
            body = payload.PAYLOAD_REGISTRY.get(body, disposition=None)
        except payload.LookupError:
            body = FormData(body)()

        self.body = body

        # enable chunked encoding if needed
        if not self.chunked:
            if hdrs.CONTENT_LENGTH not in self.headers:
                size = body.size
                if size is None:
                    self.chunked = True
                else:
                    if hdrs.CONTENT_LENGTH not in self.headers:
                        self.headers[hdrs.CONTENT_LENGTH] = str(size)

        # set content-type
        if (hdrs.CONTENT_TYPE not in self.headers and
                hdrs.CONTENT_TYPE not in self.skip_auto_headers):
            self.headers[hdrs.CONTENT_TYPE] = body.content_type

        # copy payload headers
        if body.headers:
            for (key, value) in body.headers.items():
                if key not in self.headers:
                    self.headers[key] = value

    def update_expect_continue(self, expect=False):
        if expect:
            self.headers[hdrs.EXPECT] = '100-continue'
        elif self.headers.get(hdrs.EXPECT, '').lower() == '100-continue':
            expect = True

        if expect:
            self._continue = self.loop.create_future()

    def update_proxy(self, proxy, proxy_auth, proxy_headers,
                     socks_remote_resolve=True):
        if proxy and proxy.scheme not in ['http', 'socks4', 'socks5']:
            raise ValueError(
                "Only http, socks4 and socks5 proxies are supported")
        if proxy and proxy.scheme in ['socks4', 'socks5'] and aiosocks is None:
            raise RuntimeError(
                "{} requires aiosocks library".format(proxy.scheme))

        if proxy and proxy_auth:
            if proxy.scheme == 'http' and \
                    not isinstance(proxy_auth, helpers.BasicAuth):
                raise ValueError("proxy_auth must be None or "
                                 "BasicAuth() tuple for http proxy")
            if proxy.scheme == 'socks4' and \
                    not isinstance(proxy_auth, aiosocks.Socks4Auth):
                raise ValueError("proxy_auth must be None or Socks4Auth() "
                                 "tuple for socks4 proxy")
            if proxy.scheme == 'socks5' and \
                    not isinstance(proxy_auth, aiosocks.Socks5Auth):
                raise ValueError("proxy_auth must be None or Socks5Auth() "
                                 "tuple for socks5 proxy")
        self.proxy = proxy
        self.proxy_auth = proxy_auth
        self.proxy_headers = proxy_headers
        self.socks_remote_resolve = socks_remote_resolve

    def update_fingerprint(self, fingerprint):
        if fingerprint:
            digestlen = len(fingerprint)
            hashfunc = HASHFUNC_BY_DIGESTLEN.get(digestlen)
            if not hashfunc:
                raise ValueError('fingerprint has invalid length')
            elif hashfunc is md5 or hashfunc is sha1:
                raise ValueError('md5 and sha1 are insecure and '
                                 'not supported. Use sha256.')
            self._hashfunc = hashfunc
        self._fingerprint = fingerprint

    @property
    def verify_ssl(self):
        """Do check for ssl certifications?"""
        return self._verify_ssl

    @property
    def fingerprint(self):
        """Expected ssl certificate fingerprint."""
        return self._fingerprint

    @property
    def ssl_context(self):
        """SSLContext instance for https requests."""
        return self._ssl_context

    def keep_alive(self):
        if self.version < HttpVersion10:
            # keep alive not supported at all
            return False
        if self.version == HttpVersion10:
            if self.headers.get(hdrs.CONNECTION) == 'keep-alive':
                return True
            else:  # no headers means we close for Http 1.0
                return False
        elif self.headers.get(hdrs.CONNECTION) == 'close':
            return False

        return True

    async def write_bytes(self, writer, conn):
        """Support coroutines that yields bytes objects."""
        # 100 response
        if self._continue is not None:
            await writer.drain()
            await self._continue

        try:
            if isinstance(self.body, payload.Payload):
                await self.body.write(writer)
            else:
                if isinstance(self.body, (bytes, bytearray)):
                    self.body = (self.body,)

                for chunk in self.body:
                    writer.write(chunk)

            await writer.write_eof()
        except OSError as exc:
            new_exc = ClientOSError(
                exc.errno,
                'Can not write request body for %s' % self.url)
            new_exc.__context__ = exc
            new_exc.__cause__ = exc
            conn.protocol.set_exception(new_exc)
        except asyncio.CancelledError as exc:
            if not conn.closed:
                conn.protocol.set_exception(exc)
        except Exception as exc:
            conn.protocol.set_exception(exc)
        finally:
            self._writer = None

    def send(self, conn):
        # Specify request target:
        # - CONNECT request must send authority form URI
        # - not CONNECT proxy must send absolute form URI
        # - most common is origin form URI
        if self.method == hdrs.METH_CONNECT:
            path = '{}:{}'.format(self.url.raw_host, self.url.port)
        elif self.proxy and not self.ssl:
            path = str(self.url)
        else:
            path = self.url.raw_path
            if self.url.raw_query_string:
                path += '?' + self.url.raw_query_string

        writer = PayloadWriter(conn.writer, self.loop)

        if self.compress:
            writer.enable_compression(self.compress)

        if self.chunked is not None:
            writer.enable_chunking()

        # set default content-type
        if (self.method in self.POST_METHODS and
                hdrs.CONTENT_TYPE not in self.skip_auto_headers and
                hdrs.CONTENT_TYPE not in self.headers):
            self.headers[hdrs.CONTENT_TYPE] = 'application/octet-stream'

        # set the connection header
        connection = self.headers.get(hdrs.CONNECTION)
        if not connection:
            if self.keep_alive():
                if self.version == HttpVersion10:
                    connection = 'keep-alive'
            else:
                if self.version == HttpVersion11:
                    connection = 'close'

        if connection is not None:
            self.headers[hdrs.CONNECTION] = connection

        # status + headers
        status_line = '{0} {1} HTTP/{2[0]}.{2[1]}\r\n'.format(
            self.method, path, self.version)
        writer.write_headers(status_line, self.headers)

        self._writer = self.loop.create_task(self.write_bytes(writer, conn))

        self.response = self.response_class(
            self.method, self.original_url,
            writer=self._writer, continue100=self._continue, timer=self._timer,
            request_info=self.request_info,
            auto_decompress=self._auto_decompress)

        self.response._post_init(self.loop, self._session)
        return self.response

    async def close(self):
        if self._writer is not None:
            try:
                await self._writer
            finally:
                self._writer = None

    def terminate(self):
        if self._writer is not None:
            if not self.loop.is_closed():
                self._writer.cancel()
            self._writer = None


class ClientResponse(HeadersMixin):

    # from the Status-Line of the response
    version = None  # HTTP-Version
    status = None   # Status-Code
    reason = None   # Reason-Phrase

    content = None  # Payload stream
    headers = None  # Response headers, CIMultiDictProxy
    raw_headers = None  # Response raw headers, a sequence of pairs

    _connection = None  # current connection
    flow_control_class = StreamReader  # reader flow control
    _reader = None     # input stream
    _source_traceback = None
    # setted up by ClientRequest after ClientResponse object creation
    # post-init stage allows to not change ctor signature
    _loop = None
    _closed = True  # to allow __del__ for non-initialized properly response
    _session = None

    def __init__(self, method, url, *,
                 writer=None, continue100=None, timer=None,
                 request_info=None, auto_decompress=True):
        assert isinstance(url, URL)

        self.method = method
        self.headers = None
        self.cookies = SimpleCookie()

        self._url = url
        self._content = None
        self._writer = writer
        self._continue = continue100
        self._closed = True
        self._history = ()
        self._request_info = request_info
        self._timer = timer if timer is not None else TimerNoop()
        self._auto_decompress = auto_decompress
        self._cache = {}  # reqired for @reify method decorator

    @property
    def url(self):
        return self._url

    @property
    def url_obj(self):
        warnings.warn(
            "Deprecated, use .url #1654", DeprecationWarning, stacklevel=2)
        return self._url

    @property
    def host(self):
        return self._url.host

    @property
    def _headers(self):
        return self.headers

    @property
    def request_info(self):
        return self._request_info

    @reify
    def content_disposition(self):
        raw = self._headers.get(hdrs.CONTENT_DISPOSITION)
        if raw is None:
            return None
        disposition_type, params = multipart.parse_content_disposition(raw)
        params = MappingProxyType(params)
        filename = multipart.content_disposition_filename(params)
        return ContentDisposition(disposition_type, params, filename)

    def _post_init(self, loop, session):
        self._loop = loop
        self._session = session  # store a reference to session #1985
        if loop.get_debug():
            self._source_traceback = traceback.extract_stack(sys._getframe(1))

    def __del__(self, _warnings=warnings):
        if self._loop is None:
            return  # not started
        if self._closed:
            return

        if self._connection is not None:
            self._connection.release()
            self._cleanup_writer()

            # warn
            if __debug__:
                if self._loop.get_debug():
                    _warnings.warn("Unclosed response {!r}".format(self),
                                   ResourceWarning)
                    context = {'client_response': self,
                               'message': 'Unclosed response'}
                    if self._source_traceback:
                        context['source_traceback'] = self._source_traceback
                    self._loop.call_exception_handler(context)

    def __repr__(self):
        out = io.StringIO()
        ascii_encodable_url = str(self.url)
        if self.reason:
            ascii_encodable_reason = self.reason.encode('ascii',
                                                        'backslashreplace') \
                .decode('ascii')
        else:
            ascii_encodable_reason = self.reason
        print('<ClientResponse({}) [{} {}]>'.format(
            ascii_encodable_url, self.status, ascii_encodable_reason),
            file=out)
        print(self.headers, file=out)
        return out.getvalue()

    @property
    def connection(self):
        return self._connection

    @property
    def history(self):
        """A sequence of of responses, if redirects occurred."""
        return self._history

    async def start(self, connection, read_until_eof=False):
        """Start response processing."""
        self._closed = False
        self._protocol = connection.protocol
        self._connection = connection

        connection.protocol.set_response_params(
            timer=self._timer,
            skip_payload=self.method.lower() == 'head',
            skip_status_codes=(204, 304),
            read_until_eof=read_until_eof,
            auto_decompress=self._auto_decompress)

        with self._timer:
            while True:
                # read response
                try:
                    (message, payload) = await self._protocol.read()
                except http.HttpProcessingError as exc:
                    raise ClientResponseError(
                        self.request_info, self.history,
                        code=exc.code,
                        message=exc.message, headers=exc.headers) from exc

                if (message.code < 100 or
                        message.code > 199 or message.code == 101):
                    break

                if self._continue is not None:
                    set_result(self._continue, True)
                    self._continue = None

        # payload eof handler
        payload.on_eof(self._response_eof)

        # response status
        self.version = message.version
        self.status = message.code
        self.reason = message.reason

        # headers
        self.headers = CIMultiDictProxy(message.headers)
        self.raw_headers = tuple(message.raw_headers)

        # payload
        self.content = payload

        # cookies
        for hdr in self.headers.getall(hdrs.SET_COOKIE, ()):
            try:
                self.cookies.load(hdr)
            except CookieError as exc:
                client_logger.warning(
                    'Can not load response cookies: %s', exc)
        return self

    def _response_eof(self):
        if self._closed:
            return

        if self._connection is not None:
            # websocket, protocol could be None because
            # connection could be detached
            if (self._connection.protocol is not None and
                    self._connection.protocol.upgraded):
                return

            self._connection.release()
            self._connection = None

        self._closed = True
        self._cleanup_writer()

    @property
    def closed(self):
        return self._closed

    def close(self):
        if self._closed:
            return

        self._closed = True
        if self._loop is None or self._loop.is_closed():
            return

        if self._connection is not None:
            self._connection.close()
            self._connection = None
        self._cleanup_writer()
        self._notify_content()

    def release(self):
        if self._closed:
            return noop()

        self._closed = True
        if self._connection is not None:
            self._connection.release()
            self._connection = None

        self._cleanup_writer()
        self._notify_content()
        return noop()

    def raise_for_status(self):
        if 400 <= self.status:
            raise ClientResponseError(
                self.request_info,
                self.history,
                code=self.status,
                message=self.reason,
                headers=self.headers)

    def _cleanup_writer(self):
        if self._writer is not None:
            self._writer.cancel()
        self._writer = None
        self._session = None

    def _notify_content(self):
        content = self.content
        if content and content.exception() is None and not content.is_eof():
            content.set_exception(
                ClientConnectionError('Connection closed'))

    async def wait_for_close(self):
        if self._writer is not None:
            try:
                await self._writer
            finally:
                self._writer = None
        self.release()

    async def read(self):
        """Read response payload."""
        if self._content is None:
            try:
                self._content = await self.content.read()
            except Exception:
                self.close()
                raise

        return self._content

    def get_encoding(self):
        ctype = self.headers.get(hdrs.CONTENT_TYPE, '').lower()
        mimetype = helpers.parse_mimetype(ctype)

        encoding = mimetype.parameters.get('charset')
        if encoding:
            try:
                codecs.lookup(encoding)
            except LookupError:
                encoding = None
        if not encoding:
            if mimetype.type == 'application' and mimetype.subtype == 'json':
                # RFC 7159 states that the default encoding is UTF-8.
                encoding = 'utf-8'
            else:
                encoding = chardet.detect(self._content)['encoding']
        if not encoding:
            encoding = 'utf-8'

        return encoding

    async def text(self, encoding=None, errors='strict'):
        """Read response payload and decode."""
        if self._content is None:
            await self.read()

        if encoding is None:
            encoding = self.get_encoding()

        return self._content.decode(encoding, errors=errors)

    async def json(self, *, encoding=None, loads=json.loads,
                   content_type='application/json'):
        """Read and decodes JSON response."""
        if self._content is None:
            await self.read()

        if content_type:
            ctype = self.headers.get(hdrs.CONTENT_TYPE, '').lower()
            if content_type not in ctype:
                raise ContentTypeError(
                    self.request_info,
                    self.history,
                    message=('Attempt to decode JSON with '
                             'unexpected mimetype: %s' % ctype),
                    headers=self.headers)

        stripped = self._content.strip()
        if not stripped:
            return None

        if encoding is None:
            encoding = self.get_encoding()

        return loads(stripped.decode(encoding))

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        # similar to _RequestContextManager, we do not need to check
        # for exceptions, response object can closes connection
        # is state is broken
        self.release()
