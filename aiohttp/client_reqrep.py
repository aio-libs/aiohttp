import asyncio
import io
import json
import mimetypes
import os
import sys
import traceback
import warnings
from http.cookies import CookieError, Morsel

from multidict import CIMultiDict, CIMultiDictProxy, MultiDict, MultiDictProxy
from yarl import URL

import aiohttp

from . import hdrs, helpers, streams
from .helpers import HeadersMixin, SimpleCookie, TimerNoop
from .log import client_logger
from .multipart import MultipartWriter
from .protocol import HttpMessage
from .streams import FlowControlStreamReader

try:
    import cchardet as chardet
except ImportError:  # pragma: no cover
    import chardet


__all__ = ('ClientRequest', 'ClientResponse')

PY_35 = sys.version_info >= (3, 5)


class ClientRequest:

    GET_METHODS = {hdrs.METH_GET, hdrs.METH_HEAD, hdrs.METH_OPTIONS}
    POST_METHODS = {hdrs.METH_PATCH, hdrs.METH_POST, hdrs.METH_PUT}
    ALL_METHODS = GET_METHODS.union(POST_METHODS).union(
        {hdrs.METH_DELETE, hdrs.METH_TRACE})

    DEFAULT_HEADERS = {
        hdrs.ACCEPT: '*/*',
        hdrs.ACCEPT_ENCODING: 'gzip, deflate',
    }

    SERVER_SOFTWARE = HttpMessage.SERVER_SOFTWARE

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
                 auth=None, encoding='utf-8',
                 version=aiohttp.HttpVersion11, compress=None,
                 chunked=None, expect100=False,
                 loop=None, response_class=None,
                 proxy=None, proxy_auth=None, timer=None):

        if loop is None:
            loop = asyncio.get_event_loop()

        assert isinstance(url, URL), url
        assert isinstance(proxy, (URL, type(None))), proxy

        if params:
            q = MultiDict(url.query)
            url2 = url.with_query(params)
            q.extend(url2.query)
            url = url.with_query(q)
        self.url = url.with_fragment(None)
        self.original_url = url
        self.method = method.upper()
        self.encoding = encoding
        self.chunked = chunked
        self.compress = compress
        self.loop = loop
        self.response_class = response_class or ClientResponse
        self._timer = timer if timer is not None else TimerNoop()

        if loop.get_debug():
            self._source_traceback = traceback.extract_stack(sys._getframe(1))

        self.update_version(version)
        self.update_host(url)
        self.update_headers(headers)
        self.update_auto_headers(skip_auto_headers)
        self.update_cookies(cookies)
        self.update_content_encoding(data)
        self.update_auth(auth)
        self.update_proxy(proxy, proxy_auth)

        self.update_body_from_data(data, skip_auto_headers)
        self.update_transfer_encoding()
        self.update_expect_continue(expect100)

    @property
    def host(self):
        return self.url.host

    @property
    def port(self):
        return self.url.port

    def update_host(self, url):
        """Update destination host, port and connection type (ssl)."""
        # get host/port
        if not url.host:
            raise ValueError('Host could not be detected.')

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
            if isinstance(headers, dict):
                headers = headers.items()
            elif isinstance(headers, (MultiDictProxy, MultiDict)):
                headers = headers.items()

            for key, value in headers:
                self.headers.add(key, value)

    def update_auto_headers(self, skip_auto_headers):
        self.skip_auto_headers = skip_auto_headers
        used_headers = set(self.headers) | skip_auto_headers

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
            self.headers[hdrs.USER_AGENT] = self.SERVER_SOFTWARE

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
            if self.compress is not False:
                self.compress = enc
                # enable chunked, no need to deal with length
                self.chunked = True
        elif self.compress:
            if not isinstance(self.compress, str):
                self.compress = 'deflate'
            self.headers[hdrs.CONTENT_ENCODING] = self.compress
            self.chunked = True  # enable chunked, no need to deal with length

    def update_auth(self, auth):
        """Set basic auth."""
        if auth is None:
            auth = self.auth
        if auth is None:
            return

        if not isinstance(auth, helpers.BasicAuth):
            raise TypeError('BasicAuth() tuple is required instead')

        self.headers[hdrs.AUTHORIZATION] = auth.encode()

    def update_body_from_data(self, data, skip_auto_headers):
        if not data:
            return

        if isinstance(data, str):
            data = data.encode(self.encoding)

        if isinstance(data, (bytes, bytearray)):
            self.body = data
            if (hdrs.CONTENT_TYPE not in self.headers and
                    hdrs.CONTENT_TYPE not in skip_auto_headers):
                self.headers[hdrs.CONTENT_TYPE] = 'application/octet-stream'
            if hdrs.CONTENT_LENGTH not in self.headers and not self.chunked:
                self.headers[hdrs.CONTENT_LENGTH] = str(len(self.body))

        elif isinstance(data, (asyncio.StreamReader, streams.StreamReader,
                               streams.DataQueue)):
            self.body = data

        elif asyncio.iscoroutine(data):
            self.body = data
            if (hdrs.CONTENT_LENGTH not in self.headers and
                    self.chunked is None):
                self.chunked = True

        elif isinstance(data, io.IOBase):
            assert not isinstance(data, io.StringIO), \
                'attempt to send text data instead of binary'
            self.body = data
            if not self.chunked and isinstance(data, io.BytesIO):
                # Not chunking if content-length can be determined
                size = len(data.getbuffer())
                self.headers[hdrs.CONTENT_LENGTH] = str(size)
                self.chunked = False
            elif (not self.chunked and
                  isinstance(data, (io.BufferedReader, io.BufferedRandom))):
                # Not chunking if content-length can be determined
                try:
                    size = os.fstat(data.fileno()).st_size - data.tell()
                    self.headers[hdrs.CONTENT_LENGTH] = str(size)
                    self.chunked = False
                except OSError:
                    # data.fileno() is not supported, e.g.
                    # io.BufferedReader(io.BytesIO(b'data'))
                    self.chunked = True
            else:
                self.chunked = True

            if hasattr(data, 'mode'):
                if data.mode == 'r':
                    raise ValueError('file {!r} should be open in binary mode'
                                     ''.format(data))
            if (hdrs.CONTENT_TYPE not in self.headers and
                hdrs.CONTENT_TYPE not in skip_auto_headers and
                    hasattr(data, 'name')):
                mime = mimetypes.guess_type(data.name)[0]
                mime = 'application/octet-stream' if mime is None else mime
                self.headers[hdrs.CONTENT_TYPE] = mime

        elif isinstance(data, MultipartWriter):
            self.body = data.serialize()
            self.headers.update(data.headers)
            self.chunked = self.chunked or 8192

        else:
            if not isinstance(data, helpers.FormData):
                data = helpers.FormData(data)

            self.body = data(self.encoding)

            if (hdrs.CONTENT_TYPE not in self.headers and
                    hdrs.CONTENT_TYPE not in skip_auto_headers):
                self.headers[hdrs.CONTENT_TYPE] = data.content_type

            if data.is_multipart:
                self.chunked = self.chunked or 8192
            else:
                if (hdrs.CONTENT_LENGTH not in self.headers and
                        not self.chunked):
                    self.headers[hdrs.CONTENT_LENGTH] = str(len(self.body))

    def update_transfer_encoding(self):
        """Analyze transfer-encoding header."""
        te = self.headers.get(hdrs.TRANSFER_ENCODING, '').lower()

        if self.chunked:
            if hdrs.CONTENT_LENGTH in self.headers:
                del self.headers[hdrs.CONTENT_LENGTH]
            if 'chunked' not in te:
                self.headers[hdrs.TRANSFER_ENCODING] = 'chunked'

            self.chunked = self.chunked if type(self.chunked) is int else 8192
        else:
            if 'chunked' in te:
                self.chunked = 8192
            else:
                self.chunked = None
                if hdrs.CONTENT_LENGTH not in self.headers:
                    self.headers[hdrs.CONTENT_LENGTH] = str(len(self.body))

    def update_expect_continue(self, expect=False):
        if expect:
            self.headers[hdrs.EXPECT] = '100-continue'
        elif self.headers.get(hdrs.EXPECT, '').lower() == '100-continue':
            expect = True

        if expect:
            self._continue = helpers.create_future(self.loop)

    def update_proxy(self, proxy, proxy_auth):
        if proxy and not proxy.scheme == 'http':
            raise ValueError("Only http proxies are supported")
        if proxy_auth and not isinstance(proxy_auth, helpers.BasicAuth):
            raise ValueError("proxy_auth must be None or BasicAuth() tuple")
        self.proxy = proxy
        self.proxy_auth = proxy_auth

    @asyncio.coroutine
    def write_bytes(self, request, reader):
        """Support coroutines that yields bytes objects."""
        # 100 response
        if self._continue is not None:
            yield from self._continue

        try:
            if asyncio.iscoroutine(self.body):
                exc = None
                value = None
                stream = self.body

                while True:
                    try:
                        if exc is not None:
                            result = stream.throw(exc)
                        else:
                            result = stream.send(value)
                    except StopIteration as exc:
                        if isinstance(exc.value, bytes):
                            yield from request.write(exc.value, drain=True)
                        break
                    except:
                        self.response.close()
                        raise

                    if isinstance(result, asyncio.Future):
                        exc = None
                        value = None
                        try:
                            value = yield result
                        except Exception as err:
                            exc = err
                    elif isinstance(result, (bytes, bytearray)):
                        yield from request.write(result, drain=True)
                        value = None
                    else:
                        raise ValueError(
                            'Bytes object is expected, got: %s.' %
                            type(result))

            elif isinstance(self.body, (asyncio.StreamReader,
                                        streams.StreamReader)):
                chunk = yield from self.body.read(streams.DEFAULT_LIMIT)
                while chunk:
                    yield from request.write(chunk, drain=True)
                    chunk = yield from self.body.read(streams.DEFAULT_LIMIT)

            elif isinstance(self.body, streams.DataQueue):
                while True:
                    try:
                        chunk = yield from self.body.read()
                        if not chunk:
                            break
                        yield from request.write(chunk, drain=True)
                    except streams.EofStream:
                        break

            elif isinstance(self.body, io.IOBase):
                chunk = self.body.read(self.chunked)
                while chunk:
                    request.write(chunk)
                    chunk = self.body.read(self.chunked)
            else:
                if isinstance(self.body, (bytes, bytearray)):
                    self.body = (self.body,)

                for chunk in self.body:
                    request.write(chunk)

        except Exception as exc:
            new_exc = aiohttp.ClientRequestError(
                'Can not write request body for %s' % self.url)
            new_exc.__context__ = exc
            new_exc.__cause__ = exc
            reader.set_exception(new_exc)
        else:
            try:
                ret = request.write_eof()
                # NB: in asyncio 3.4.1+ StreamWriter.drain() is coroutine
                # see bug #170
                if (asyncio.iscoroutine(ret) or
                        isinstance(ret, asyncio.Future)):
                    yield from ret
            except Exception as exc:
                new_exc = aiohttp.ClientRequestError(
                    'Can not write request body for %s' % self.url)
                new_exc.__context__ = exc
                new_exc.__cause__ = exc
                reader.set_exception(new_exc)

        self._writer = None

    def send(self, writer, reader):
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

        request = aiohttp.Request(writer, self.method, path,
                                  self.version)

        if self.compress:
            request.add_compression_filter(self.compress)

        if self.chunked is not None:
            request.enable_chunked_encoding()
            request.add_chunking_filter(self.chunked)

        # set default content-type
        if (self.method in self.POST_METHODS and
                hdrs.CONTENT_TYPE not in self.skip_auto_headers and
                hdrs.CONTENT_TYPE not in self.headers):
            self.headers[hdrs.CONTENT_TYPE] = 'application/octet-stream'

        for k, value in self.headers.items():
            request.add_header(k, value)
        request.send_headers()

        self._writer = helpers.ensure_future(
            self.write_bytes(request, reader), loop=self.loop)

        self.response = self.response_class(
            self.method, self.original_url,
            writer=self._writer, continue100=self._continue, timer=self._timer)

        self.response._post_init(self.loop)
        return self.response

    @asyncio.coroutine
    def close(self):
        if self._writer is not None:
            try:
                yield from self._writer
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
    flow_control_class = FlowControlStreamReader  # reader flow control
    _reader = None     # input stream
    _response_parser = aiohttp.HttpResponseParser()
    _source_traceback = None
    # setted up by ClientRequest after ClientResponse object creation
    # post-init stage allows to not change ctor signature
    _loop = None
    _closed = True  # to allow __del__ for non-initialized properly response

    def __init__(self, method, url, *,
                 writer=None, continue100=None, timer=None):
        assert isinstance(url, URL)

        self.method = method
        self._url_obj = url
        self._content = None
        self._writer = writer
        self._continue = continue100
        self._closed = False
        self._should_close = True  # override by message.should_close later
        self._history = ()
        self._timer = timer if timer is not None else TimerNoop()
        self.cookies = SimpleCookie()

    @property
    def url_obj(self):
        return self._url_obj

    @property
    def url(self):
        warnings.warn("Deprecated, use .url_obj",
                      DeprecationWarning,
                      stacklevel=2)
        return str(self._url_obj)

    @property
    def host(self):
        warnings.warn("Deprecated, use .url_obj.host",
                      DeprecationWarning,
                      stacklevel=2)
        return self._url_obj.host

    def _post_init(self, loop):
        self._loop = loop
        if loop.get_debug():
            self._source_traceback = traceback.extract_stack(sys._getframe(1))

    def __del__(self, _warnings=warnings):
        if self._loop is None:
            return  # not started
        if self._closed:
            return
        self.close()

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

    def _setup_connection(self, connection):
        self._reader = connection.reader
        self._connection = connection
        self.content = self.flow_control_class(
            connection.reader, loop=connection.loop, timer=self._timer)

    def _need_parse_response_body(self):
        return (self.method.lower() != 'head' and
                self.status not in [204, 304])

    @asyncio.coroutine
    def start(self, connection, read_until_eof=False):
        """Start response processing."""
        self._setup_connection(connection)

        with self._timer:
            while True:
                httpstream = self._reader.set_parser(self._response_parser)

                # read response
                message = yield from httpstream.read()
                if (message.code < 100 or
                        message.code > 199 or message.code == 101):
                    break

                if self._continue is not None and not self._continue.done():
                    self._continue.set_result(True)
                    self._continue = None

        # response status
        self.version = message.version
        self.status = message.code
        self.reason = message.reason
        self._should_close = message.should_close

        # headers
        self.headers = CIMultiDictProxy(message.headers)
        self.raw_headers = tuple(message.raw_headers)

        # payload
        rwb = self._need_parse_response_body()
        self._reader.set_parser(
            aiohttp.HttpPayloadParser(message,
                                      readall=read_until_eof,
                                      response_with_body=rwb),
            self.content)

        # cookies
        for hdr in self.headers.getall(hdrs.SET_COOKIE, ()):
            try:
                self.cookies.load(hdr)
            except CookieError as exc:
                client_logger.warning(
                    'Can not load response cookies: %s', exc)
        return self

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

    @asyncio.coroutine
    def release(self, *, consume=False):
        if self._closed:
            return
        try:
            content = self.content
            if content is not None:
                if consume:
                    while not content.at_eof():
                        yield from content.readany()
                else:
                    close = False
                    if content.exception() is not None:
                        close = True
                    else:
                        content.read_nowait()
                        if not content.at_eof():
                            close = True
                    if close:
                        self.close()
        except Exception:
            self._connection.close()
            self._connection = None
            raise
        finally:
            self._closed = True
            if self._connection is not None:
                self._connection.release()
                if self._reader is not None:
                    self._reader.unset_parser()
                self._connection = None
            self._cleanup_writer()
            self._notify_content()

    def raise_for_status(self):
        if 400 <= self.status:
            raise aiohttp.HttpProcessingError(
                code=self.status,
                message=self.reason)

    def _cleanup_writer(self):
        if self._writer is not None and not self._writer.done():
            self._writer.cancel()
        self._writer = None

    def _notify_content(self):
        content = self.content
        if content and content.exception() is None and not content.is_eof():
            content.set_exception(
                aiohttp.ClientDisconnectedError('Connection closed'))

    @asyncio.coroutine
    def wait_for_close(self):
        if self._writer is not None:
            try:
                yield from self._writer
            finally:
                self._writer = None
        yield from self.release()

    @asyncio.coroutine
    def read(self):
        """Read response payload."""
        if self._content is None:
            try:
                self._content = yield from self.content.read()
            except:
                self.close()
                raise
            else:
                yield from self.release()

        return self._content

    def _get_encoding(self):
        ctype = self.headers.get(hdrs.CONTENT_TYPE, '').lower()
        mtype, stype, _, params = helpers.parse_mimetype(ctype)

        encoding = params.get('charset')
        if not encoding:
            if mtype == 'application' and stype == 'json':
                # RFC 7159 states that the default encoding is UTF-8.
                encoding = 'utf-8'
            else:
                encoding = chardet.detect(self._content)['encoding']
        if not encoding:
            encoding = 'utf-8'

        return encoding

    @asyncio.coroutine
    def text(self, encoding=None, errors='strict'):
        """Read response payload and decode."""
        if self._content is None:
            yield from self.read()

        if encoding is None:
            encoding = self._get_encoding()

        return self._content.decode(encoding, errors=errors)

    @asyncio.coroutine
    def json(self, *, encoding=None, loads=json.loads):
        """Read and decodes JSON response."""
        if self._content is None:
            yield from self.read()

        ctype = self.headers.get(hdrs.CONTENT_TYPE, '').lower()
        if 'json' not in ctype:
            client_logger.warning(
                'Attempt to decode JSON with unexpected mimetype: %s', ctype)

        stripped = self._content.strip()
        if not stripped:
            return None

        if encoding is None:
            encoding = self._get_encoding()

        return loads(stripped.decode(encoding))

    if PY_35:
        @asyncio.coroutine
        def __aenter__(self):
            return self

        @asyncio.coroutine
        def __aexit__(self, exc_type, exc_val, exc_tb):
            # similar to _RequestContextManager, we do not need to check
            # for exceptions, response object can closes connection
            # is state is broken
            yield from self.release()
