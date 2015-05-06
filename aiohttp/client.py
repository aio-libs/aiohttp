"""HTTP Client for asyncio."""

import asyncio
import http.cookies
import io
import json
import mimetypes
import os
import urllib.parse
import weakref
import warnings
import chardet

import aiohttp
from . import hdrs, helpers, streams
from .log import client_logger
from .streams import EOF_MARKER, FlowControlStreamReader
from .multidict import CIMultiDictProxy, MultiDictProxy, MultiDict, CIMultiDict
from .multipart import MultipartWriter

__all__ = ('request', 'ClientSession')

HTTP_PORT = 80
HTTPS_PORT = 443


class ClientSession:

    def __init__(self, *, connector=None, loop=None, request_class=None,
                 response_class=None, cookies=None, headers=None, auth=None):
        if loop is None:
            loop = asyncio.get_event_loop()
        self._loop = loop
        self._cookies = http.cookies.SimpleCookie()

        if connector is None:
            connector = aiohttp.TCPConnector(force_close=True, loop=loop)
        elif connector._loop is not loop:
            raise ValueError("loop argument must agree with connector")

        # For Backward compatability with `share_cookie` connectors
        elif connector._share_cookies:
            self._update_cookies(connector.cookies)
        if cookies is not None:
            self._update_cookies(cookies)
        self._connector = connector
        self._default_auth = auth

        # Convert to list of tuples
        if headers:
            if isinstance(headers, dict):
                headers = list(headers.items())
            elif isinstance(headers, (MultiDictProxy, MultiDict)):
                headers = list(headers.items())
        self._default_headers = headers

        if request_class is None:
            request_class = ClientRequest
        self._request_class = request_class
        self._response_class = response_class

    @asyncio.coroutine
    def request(self, method, url, *,
                params=None,
                data=None,
                headers=None,
                files=None,
                auth=None,
                allow_redirects=True,
                max_redirects=10,
                encoding='utf-8',
                version=aiohttp.HttpVersion11,
                compress=None,
                chunked=None,
                expect100=False,
                read_until_eof=True):

        if self.closed:
            raise RuntimeError('Session is closed')

        redirects = 0
        method = method.upper()

        # Merge with default headers and transform to CIMultiDict
        headers = self._prepare_headers(headers)
        if auth is None:
            auth = self._default_auth
        # It would be confusing if we support explicit Authorization header
        # with `auth` argument
        if (headers is not None and
                auth is not None and
                hdrs.AUTHORIZATION in headers):
            raise ValueError("Can't combine `Authorization` header with "
                             "`auth` argument")

        while True:
            req = self._request_class(
                method, url, params=params, headers=headers, data=data,
                cookies=self.cookies, files=files, encoding=encoding,
                auth=auth, version=version, compress=compress, chunked=chunked,
                expect100=expect100,
                loop=self._loop, response_class=self._response_class)

            conn = yield from self._connector.connect(req)
            try:
                resp = req.send(conn.writer, conn.reader)
                try:
                    yield from resp.start(conn, read_until_eof)
                except:
                    resp.close()
                    conn.close()
                    raise
            except (aiohttp.HttpProcessingError,
                    aiohttp.ServerDisconnectedError) as exc:
                raise aiohttp.ClientResponseError() from exc
            except OSError as exc:
                raise aiohttp.ClientOSError() from exc

            self._update_cookies(resp.cookies)
            # For Backward compatability with `share_cookie` connectors
            if self._connector._share_cookies:
                self._connector.update_cookies(resp.cookies)

            # redirects
            if resp.status in (301, 302, 303, 307) and allow_redirects:
                redirects += 1
                if max_redirects and redirects >= max_redirects:
                    resp.close(force=True)
                    break

                # For 301 and 302, mimic IE behaviour, now changed in RFC.
                # Details: https://github.com/kennethreitz/requests/pull/269
                if resp.status != 307:
                    method = hdrs.METH_GET
                    data = None

                r_url = (resp.headers.get(hdrs.LOCATION) or
                         resp.headers.get(hdrs.URI))

                scheme = urllib.parse.urlsplit(r_url)[0]
                if scheme not in ('http', 'https', ''):
                    resp.close(force=True)
                    raise ValueError('Can redirect only to http or https')
                elif not scheme:
                    r_url = urllib.parse.urljoin(url, r_url)

                url = urllib.parse.urldefrag(r_url)[0]
                if url:
                    yield from asyncio.async(resp.release(), loop=self._loop)
                    continue

            break

        return resp

    def _update_cookies(self, cookies):
        """Update shared cookies."""
        if isinstance(cookies, dict):
            cookies = cookies.items()

        for name, value in cookies:
            if isinstance(value, http.cookies.Morsel):
                # use dict method because SimpleCookie class modifies value
                # before Python3.4
                dict.__setitem__(self.cookies, name, value)
            else:
                self.cookies[name] = value

    def _prepare_headers(self, headers):
        """ Add default headers and transform it to CIMultiDict
        """
        # Convert headers to MultiDict
        result = CIMultiDict()
        if headers:
            if isinstance(headers, dict):
                headers = headers.items()
            elif isinstance(headers, (MultiDictProxy, MultiDict)):
                headers = headers.items()
            for key, value in headers:
                result.add(key, value)
        # Add defaults only if those are not overridden
        if self._default_headers:
            for key, value in self._default_headers:
                if key not in result:
                    result.add(key, value)
        return result

    @asyncio.coroutine
    def get(self, url, *, allow_redirects=True, **kwargs):
        resp = yield from self.request(hdrs.METH_GET, url,
                                       allow_redirects=allow_redirects,
                                       **kwargs)
        return resp

    @asyncio.coroutine
    def options(self, url, *, allow_redirects=True, **kwargs):
        resp = yield from self.request(hdrs.METH_OPTIONS, url,
                                       allow_redirects=allow_redirects,
                                       **kwargs)
        return resp

    @asyncio.coroutine
    def head(self, url, *, allow_redirects=False, **kwargs):
        resp = yield from self.request(hdrs.METH_HEAD, url,
                                       allow_redirects=allow_redirects,
                                       **kwargs)
        return resp

    @asyncio.coroutine
    def post(self, url, *, data=None, **kwargs):
        resp = yield from self.request(hdrs.METH_POST, url,
                                       data=data,
                                       **kwargs)
        return resp

    @asyncio.coroutine
    def put(self, url, *, data=None, **kwargs):
        resp = yield from self.request(hdrs.METH_PUT, url,
                                       data=data,
                                       **kwargs)
        return resp

    @asyncio.coroutine
    def patch(self, url, *, data=None, **kwargs):
        resp = yield from self.request(hdrs.METH_PATCH, url,
                                       data=data,
                                       **kwargs)
        return resp

    @asyncio.coroutine
    def delete(self, url, **kwargs):
        resp = yield from self.request(hdrs.METH_DELETE, url,
                                       **kwargs)
        return resp

    def close(self):
        """Close underlying connector.

        Release all acquired resources.
        """
        if not self.closed:
            self._connector.close()
            self._connector = None

    @property
    def closed(self):
        """Is client session closed.

        A readonly property.
        """
        return self._connector is None or self._connector.closed

    @property
    def connector(self):
        """Connector instance used for the session."""
        return self._connector

    @property
    def cookies(self):
        """The session cookies."""
        return self._cookies

    def detach(self):
        """Detach connector from session without closing the former.

        Session is switched to closed state anyway.
        """
        self._connector = None


@asyncio.coroutine
def request(method, url, *,
            params=None,
            data=None,
            headers=None,
            cookies=None,
            files=None,
            auth=None,
            allow_redirects=True,
            max_redirects=10,
            encoding='utf-8',
            version=aiohttp.HttpVersion11,
            compress=None,
            chunked=None,
            expect100=False,
            connector=None,
            loop=None,
            read_until_eof=True,
            request_class=None,
            response_class=None):
    """Constructs and sends a request. Returns response object.

    :param str method: http method
    :param str url: request url
    :param params: (optional) Dictionary or bytes to be sent in the query
      string of the new request
    :param data: (optional) Dictionary, bytes, or file-like object to
      send in the body of the request
    :param dict headers: (optional) Dictionary of HTTP Headers to send with
      the request
    :param dict cookies: (optional) Dict object to send with the request
    :param auth: (optional) BasicAuth named tuple represent HTTP Basic Auth
    :type auth: aiohttp.helpers.BasicAuth
    :param bool allow_redirects: (optional) If set to False, do not follow
      redirects
    :param version: Request http version.
    :type version: aiohttp.protocol.HttpVersion
    :param bool compress: Set to True if request has to be compressed
       with deflate encoding.
    :param chunked: Set to chunk size for chunked transfer encoding.
    :type chunked: bool or int
    :param bool expect100: Expect 100-continue response from server.
    :param connector: BaseConnector sub-class instance to support
       connection pooling.
    :type connector: aiohttp.connector.BaseConnector
    :param bool read_until_eof: Read response until eof if response
       does not have Content-Length header.
    :param request_class: (optional) Custom Request class implementation.
    :param response_class: (optional) Custom Response class implementation.
    :param loop: Optional event loop.

    Usage::

      >>> import aiohttp
      >>> resp = yield from aiohttp.request('GET', 'http://python.org/')
      >>> resp
      <ClientResponse(python.org/) [200]>
      >>> data = yield from resp.read()

    """
    session = ClientSession(connector=connector, loop=loop,
                            request_class=request_class,
                            response_class=response_class,
                            cookies=cookies)
    resp = yield from session.request(method, url,
                                      params=params,
                                      data=data,
                                      headers=headers,
                                      files=files,
                                      auth=auth,
                                      allow_redirects=allow_redirects,
                                      max_redirects=max_redirects,
                                      encoding=encoding,
                                      version=version,
                                      compress=compress,
                                      chunked=chunked,
                                      expect100=expect100,
                                      read_until_eof=read_until_eof)
    if connector is not None:
        session.detach()
    else:
        session.close()
    return resp


class ClientRequest:

    GET_METHODS = {hdrs.METH_GET, hdrs.METH_HEAD, hdrs.METH_OPTIONS}
    POST_METHODS = {hdrs.METH_PATCH, hdrs.METH_POST, hdrs.METH_PUT}
    ALL_METHODS = GET_METHODS.union(POST_METHODS).union(
        {hdrs.METH_DELETE, hdrs.METH_TRACE})

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

    # Adding weakref to self for _writer cancelling doesn't make sense:
    # _writer exists until .write_bytes coro is finished,
    # .write_bytes generator has strong reference to self and `del request`
    # doesn't produce request finalization.
    # After .write_bytes is done _writer has set to None and we have nothing
    # to cancel.
    # Maybe we need to add .cancel() method to ClientRequest through for
    # forced closing request sending.

    def __init__(self, method, url, *,
                 params=None, headers=None, data=None, cookies=None,
                 files=None, auth=None, encoding='utf-8',
                 version=aiohttp.HttpVersion11, compress=None,
                 chunked=None, expect100=False,
                 loop=None, response_class=None):
        self.url = url
        self.method = method.upper()
        self.encoding = encoding
        self.chunked = chunked
        self.compress = compress
        self.loop = loop
        self.response_class = response_class or ClientResponse

        self.update_version(version)
        self.update_host(url)
        self.update_path(params)
        self.update_headers(headers)
        self.update_cookies(cookies)
        self.update_content_encoding()
        self.update_auth(auth)

        if files:
            warnings.warn(
                'files parameter is deprecated. use data instead',
                DeprecationWarning)
            if data:
                raise ValueError(
                    'data and files parameters are '
                    'not supported at the same time.')
            data = files

        self.update_body_from_data(data)
        self.update_transfer_encoding()
        self.update_expect_continue(expect100)

    def update_host(self, url):
        """Update destination host, port and connection type (ssl)."""
        scheme, netloc, path, query, fragment = urllib.parse.urlsplit(url)
        if not netloc:
            raise ValueError('Host could not be detected.')

        # check domain idna encoding
        try:
            netloc = netloc.encode('idna').decode('utf-8')
        except UnicodeError:
            raise ValueError('URL has an invalid label.')

        # basic auth info
        if '@' in netloc:
            authinfo, netloc = netloc.split('@', 1)
            self.auth = helpers.BasicAuth(*authinfo.split(':', 1))

        # Record entire netloc for usage in host header
        self.netloc = netloc

        # extract host and port
        self.ssl = scheme == 'https'
        if ':' in netloc:
            netloc, port_s = netloc.split(':', 1)
            try:
                self.port = int(port_s)
            except ValueError:
                raise ValueError(
                    'Port number could not be converted.') from None
        else:
            if self.ssl:
                self.port = HTTPS_PORT
            else:
                self.port = HTTP_PORT

        self.scheme = scheme
        self.host = netloc

    def update_version(self, version):
        """Convert request version to two elements tuple.

        parser http version '1.1' => (1, 1)
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

    def update_path(self, params):
        """Build path."""
        # extract path
        scheme, netloc, path, query, fragment = urllib.parse.urlsplit(self.url)
        if not path:
            path = '/'

        if isinstance(params, dict):
            params = list(params.items())
        elif isinstance(params, (MultiDictProxy, MultiDict)):
            params = list(params.items())

        if params:
            params = urllib.parse.urlencode(params)
            if query:
                query = '%s&%s' % (query, params)
            else:
                query = params

        if query:
            # Separately unquoting key/value,
            # so as to not mix querystring separators
            # included in query values.
            query_parts = [
                (urllib.parse.unquote(q[0]), urllib.parse.unquote(q[1]))
                for q in urllib.parse.parse_qsl(query, keep_blank_values=True)]
            # urlencode will take care of quoting
            query = urllib.parse.urlencode(query_parts)
        path = helpers.unquote_quote(path)
        fragment = helpers.unquote_quote(fragment)

        self.path = urllib.parse.urlunsplit(('', '', path, query, fragment))

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

        for hdr, val in self.DEFAULT_HEADERS.items():
            if hdr not in self.headers:
                self.headers[hdr] = val

        # add host
        if hdrs.HOST not in self.headers:
            self.headers[hdrs.HOST] = self.netloc

    def update_cookies(self, cookies):
        """Update request cookies header."""
        if not cookies:
            return

        c = http.cookies.SimpleCookie()
        if hdrs.COOKIE in self.headers:
            c.load(self.headers.get(hdrs.COOKIE, ''))
            del self.headers[hdrs.COOKIE]

        if isinstance(cookies, dict):
            cookies = cookies.items()

        for name, value in cookies:
            if isinstance(value, http.cookies.Morsel):
                # use dict method because SimpleCookie class modifies value
                dict.__setitem__(c, name, value)
            else:
                c[name] = value

        self.headers[hdrs.COOKIE] = c.output(header='', sep=';').strip()

    def update_content_encoding(self):
        """Set request content encoding."""
        enc = self.headers.get(hdrs.CONTENT_ENCODING, '').lower()
        if enc:
            self.compress = enc
            self.chunked = True  # enable chunked, no need to deal with length
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
            warnings.warn(
                'BasicAuth() tuple is required instead ', DeprecationWarning)
            auth = helpers.BasicAuth(*auth)

        self.headers[hdrs.AUTHORIZATION] = auth.encode()

    def update_body_from_data(self, data):
        if not data:
            return

        if isinstance(data, str):
            data = data.encode(self.encoding)

        if isinstance(data, (bytes, bytearray)):
            self.body = data
            if hdrs.CONTENT_TYPE not in self.headers:
                self.headers[hdrs.CONTENT_TYPE] = 'application/octet-stream'
            if hdrs.CONTENT_LENGTH not in self.headers and not self.chunked:
                self.headers[hdrs.CONTENT_LENGTH] = str(len(self.body))

        elif isinstance(data, (asyncio.StreamReader, streams.DataQueue)):
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
            if not self.chunked and isinstance(data, io.BufferedReader):
                # Not chunking if content-length can be determined
                size = os.fstat(data.fileno()).st_size - data.tell()
                self.headers[hdrs.CONTENT_LENGTH] = str(size)
                self.chunked = False
            else:
                self.chunked = True
            if hasattr(data, 'mode'):
                if data.mode == 'r':
                    raise ValueError('file {!r} should be open in binary mode'
                                     ''.format(data))
            if (hdrs.CONTENT_TYPE not in self.headers and
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

            if hdrs.CONTENT_TYPE not in self.headers:
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
            self._continue = asyncio.Future(loop=self.loop)

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
                        self.response.close(True)
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

            elif isinstance(self.body, asyncio.StreamReader):
                chunk = yield from self.body.read(streams.DEFAULT_LIMIT)
                while chunk:
                    yield from request.write(chunk, drain=True)
                    chunk = yield from self.body.read(streams.DEFAULT_LIMIT)

            elif isinstance(self.body, streams.DataQueue):
                while True:
                    try:
                        chunk = yield from self.body.read()
                        if chunk is EOF_MARKER:
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
        request = aiohttp.Request(writer, self.method, self.path, self.version)

        if self.compress:
            request.add_compression_filter(self.compress)

        if self.chunked is not None:
            request.enable_chunked_encoding()
            request.add_chunking_filter(self.chunked)

        # set default content-type
        if (self.method in self.POST_METHODS and
                hdrs.CONTENT_TYPE not in self.headers):
            self.headers[hdrs.CONTENT_TYPE] = 'application/octet-stream'

        request.add_headers(
            *((k, v)
              for k, v in ((k, value)
                           for k, value in self.headers.items())))
        request.send_headers()

        self._writer = asyncio.async(
            self.write_bytes(request, reader), loop=self.loop)

        self.response = self.response_class(
            self.method, self.url, self.host,
            writer=self._writer, continue100=self._continue)
        return self.response

    @asyncio.coroutine
    def close(self):
        if self._writer is not None:
            try:
                yield from self._writer
            finally:
                self._writer = None


class ClientResponse:

    message = None  # RawResponseMessage object

    # from the Status-Line of the response
    version = None  # HTTP-Version
    status = None   # Status-Code
    reason = None   # Reason-Phrase

    cookies = None  # Response cookies (Set-Cookie)
    content = None  # Payload stream

    connection = None  # current connection
    flow_control_class = FlowControlStreamReader  # reader flow control
    _reader = None     # input stream
    _response_parser = aiohttp.HttpResponseParser()
    _connection_wr = None  # weakref to self for releasing connection on del
    _writer_wr = None  # weakref to self for cancelling writer on del

    def __init__(self, method, url, host='', *, writer=None, continue100=None):
        super().__init__()

        self.method = method
        self.url = url
        self.host = host
        self.headers = None
        self._content = None
        self._writer = writer
        if writer is not None:
            self._writer_wr = weakref.ref(self, lambda wr: writer.cancel())
        self._continue = continue100

    def __repr__(self):
        out = io.StringIO()
        print('<ClientResponse({}) [{} {}]>'.format(
            self.url, self.status, self.reason), file=out)
        print(self.headers, file=out)
        return out.getvalue()

    def waiting_for_continue(self):
        return self._continue is not None

    def _setup_connection(self, connection):
        self._reader = connection.reader
        self.connection = connection
        self.content = self.flow_control_class(
            connection.reader, loop=connection.loop)

        msg = ('ClientResponse has to be closed explicitly! {}:{}:{}'
               .format(self.method, self.host, self.url))

        def _do_close_connection(wr, connection=connection, msg=msg):
            warnings.warn(msg, ResourceWarning)
            connection.close()

        self._connection_wr = weakref.ref(self, _do_close_connection)

    @asyncio.coroutine
    def start(self, connection, read_until_eof=False):
        """Start response processing."""
        self._setup_connection(connection)

        while True:
            httpstream = self._reader.set_parser(self._response_parser)

            # read response
            self.message = yield from httpstream.read()
            if self.message.code != 100:
                break

            if self._continue is not None and not self._continue.done():
                self._continue.set_result(True)
                self._continue = None

        # response status
        self.version = self.message.version
        self.status = self.message.code
        self.reason = self.message.reason

        # headers
        self.headers = CIMultiDictProxy(self.message.headers)

        # payload
        response_with_body = self.method.lower() != 'head'
        self._reader.set_parser(
            aiohttp.HttpPayloadParser(self.message,
                                      readall=read_until_eof,
                                      response_with_body=response_with_body),
            self.content)

        # cookies
        self.cookies = http.cookies.SimpleCookie()
        if hdrs.SET_COOKIE in self.headers:
            for hdr in self.headers.getall(hdrs.SET_COOKIE):
                try:
                    self.cookies.load(hdr)
                except http.cookies.CookieError as exc:
                    client_logger.warning(
                        'Can not load response cookies: %s', exc)
        return self

    def close(self, force=False):
        if self.connection is not None:
            if self.content and not self.content.at_eof():
                force = True

            if force:
                self.connection.close()
            else:
                self.connection.release()
                if self._reader is not None:
                    self._reader.unset_parser()

            self.connection = None
            self._connection_wr = None
        if self._writer is not None and not self._writer.done():
            self._writer.cancel()
            self._writer = None
            self._writer_wr = None

    @asyncio.coroutine
    def release(self):
        try:
            chunk = yield from self.content.readany()
            while chunk is not EOF_MARKER or chunk:
                chunk = yield from self.content.readany()
        finally:
            self.close()

    @asyncio.coroutine
    def wait_for_close(self):
        if self._writer is not None:
            try:
                yield from self._writer
            finally:
                self._writer = None
                self._writer_wr = None
        self.close()

    @asyncio.coroutine
    def read(self, decode=False):
        """Read response payload."""
        if self._content is None:
            try:
                self._content = yield from self.content.read()
            except:
                self.close(True)
                raise
            else:
                self.close()

        data = self._content

        if decode:
            warnings.warn(
                '.read(True) is deprecated. use .json() instead',
                DeprecationWarning)
            return (yield from self.json())

        return data

    @asyncio.coroutine
    def read_and_close(self, decode=False):
        """Read response payload and then close response."""
        warnings.warn(
            'read_and_close is deprecated, use .read() instead',
            DeprecationWarning)
        return (yield from self.read(decode))

    def _get_encoding(self, encoding):
        ctype = self.headers.get(hdrs.CONTENT_TYPE, '').lower()
        mtype, stype, _, params = helpers.parse_mimetype(ctype)

        if not encoding:
            encoding = params.get('charset')
            if not encoding:
                encoding = chardet.detect(self._content)['encoding']
            if not encoding:
                encoding = 'utf-8'

        return encoding

    @asyncio.coroutine
    def text(self, encoding=None):
        """Read response payload and decode."""
        if self._content is None:
            yield from self.read()

        if encoding is None:
            encoding = self._get_encoding(encoding)

        return self._content.decode(encoding)

    @asyncio.coroutine
    def json(self, *, encoding=None, loads=json.loads):
        """Reads and decodes JSON response."""
        if self._content is None:
            yield from self.read()

        ctype = self.headers.get(hdrs.CONTENT_TYPE, '').lower()
        if 'json' not in ctype:
            client_logger.warning(
                'Attempt to decode JSON with unexpected mimetype: %s', ctype)

        if not self._content.strip():
            return None

        if encoding is None:
            encoding = self._get_encoding(encoding)

        return loads(self._content.decode(encoding))
