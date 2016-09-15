"""HTTP Client for asyncio."""

import asyncio
import base64
import hashlib
import os
import sys
import traceback
import urllib.parse
import warnings

from multidict import CIMultiDict, MultiDict, MultiDictProxy, istr

import aiohttp

from . import hdrs, helpers
from ._ws_impl import WS_KEY, WebSocketParser, WebSocketWriter
from .client_reqrep import ClientRequest, ClientResponse
from .client_ws import ClientWebSocketResponse
from .cookiejar import CookieJar
from .errors import WSServerHandshakeError
from .helpers import Timeout

__all__ = ('ClientSession', 'request', 'get', 'options', 'head',
           'delete', 'post', 'put', 'patch', 'ws_connect')

PY_35 = sys.version_info >= (3, 5)


class ClientSession:
    """First-class interface for making HTTP requests."""

    _source_traceback = None
    _connector = None

    def __init__(self, *, connector=None, loop=None, cookies=None,
                 headers=None, skip_auto_headers=None,
                 auth=None, request_class=ClientRequest,
                 response_class=ClientResponse,
                 ws_response_class=ClientWebSocketResponse,
                 version=aiohttp.HttpVersion11,
                 cookie_jar=None):

        if connector is None:
            connector = aiohttp.TCPConnector(loop=loop)
            loop = connector._loop  # never None
        else:
            if loop is None:
                loop = connector._loop  # never None
            elif connector._loop is not loop:
                raise ValueError("loop argument must agree with connector")

        self._loop = loop
        if loop.get_debug():
            self._source_traceback = traceback.extract_stack(sys._getframe(1))

        if cookie_jar is None:
            cookie_jar = CookieJar(loop=loop)
        self._cookie_jar = cookie_jar

        if cookies is not None:
            self._cookie_jar.update_cookies(cookies)
        self._connector = connector
        self._default_auth = auth
        self._version = version

        # Convert to list of tuples
        if headers:
            headers = CIMultiDict(headers)
        else:
            headers = CIMultiDict()
        self._default_headers = headers
        if skip_auto_headers is not None:
            self._skip_auto_headers = frozenset([istr(i)
                                                 for i in skip_auto_headers])
        else:
            self._skip_auto_headers = frozenset()

        self._request_class = request_class
        self._response_class = response_class
        self._ws_response_class = ws_response_class

    def __del__(self, _warnings=warnings):
        if not self.closed:
            self.close()

            _warnings.warn("Unclosed client session {!r}".format(self),
                           ResourceWarning)
            context = {'client_session': self,
                       'message': 'Unclosed client session'}
            if self._source_traceback is not None:
                context['source_traceback'] = self._source_traceback
            self._loop.call_exception_handler(context)

    def request(self, method, url, *,
                params=None,
                data=None,
                headers=None,
                skip_auto_headers=None,
                auth=None,
                allow_redirects=True,
                max_redirects=10,
                encoding='utf-8',
                version=None,
                compress=None,
                chunked=None,
                expect100=False,
                read_until_eof=True,
                proxy=None,
                proxy_auth=None,
                timeout=5*60):
        """Perform HTTP request."""

        return _RequestContextManager(
            self._request(
                method,
                url,
                params=params,
                data=data,
                headers=headers,
                skip_auto_headers=skip_auto_headers,
                auth=auth,
                allow_redirects=allow_redirects,
                max_redirects=max_redirects,
                encoding=encoding,
                version=version,
                compress=compress,
                chunked=chunked,
                expect100=expect100,
                read_until_eof=read_until_eof,
                proxy=proxy,
                proxy_auth=proxy_auth,
                timeout=timeout))

    @asyncio.coroutine
    def _request(self, method, url, *,
                 params=None,
                 data=None,
                 headers=None,
                 skip_auto_headers=None,
                 auth=None,
                 allow_redirects=True,
                 max_redirects=10,
                 encoding='utf-8',
                 version=None,
                 compress=None,
                 chunked=None,
                 expect100=False,
                 read_until_eof=True,
                 proxy=None,
                 proxy_auth=None,
                 timeout=5*60):

        if version is not None:
            warnings.warn("HTTP version should be specified "
                          "by ClientSession constructor", DeprecationWarning)
        else:
            version = self._version

        if self.closed:
            raise RuntimeError('Session is closed')

        redirects = 0
        history = []

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

        skip_headers = set(self._skip_auto_headers)
        if skip_auto_headers is not None:
            for i in skip_auto_headers:
                skip_headers.add(istr(i))

        while True:
            url, _ = urllib.parse.urldefrag(url)

            cookies = self._cookie_jar.filter_cookies(url)

            req = self._request_class(
                method, url, params=params, headers=headers,
                skip_auto_headers=skip_headers, data=data,
                cookies=cookies, encoding=encoding,
                auth=auth, version=version, compress=compress, chunked=chunked,
                expect100=expect100,
                loop=self._loop, response_class=self._response_class,
                proxy=proxy, proxy_auth=proxy_auth, timeout=timeout)

            with Timeout(timeout, loop=self._loop):
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
                raise aiohttp.ClientOSError(*exc.args) from exc

            self._cookie_jar.update_cookies(resp.cookies, resp.url)

            # redirects
            if resp.status in (301, 302, 303, 307) and allow_redirects:
                redirects += 1
                history.append(resp)
                if max_redirects and redirects >= max_redirects:
                    resp.close()
                    break
                else:
                    # TODO: close the connection if BODY is large enough
                    # Redirect with big BODY is forbidden by HTTP protocol
                    # but malformed server may send illegal response.
                    # Small BODIES with text like "Not Found" are still
                    # perfectly fine and should be accepted.
                    yield from resp.release()

                # For 301 and 302, mimic IE behaviour, now changed in RFC.
                # Details: https://github.com/kennethreitz/requests/pull/269
                if (resp.status == 303 and resp.method != hdrs.METH_HEAD) \
                   or (resp.status in (301, 302) and
                       resp.method == hdrs.METH_POST):
                    method = hdrs.METH_GET
                    data = None
                    if headers.get(hdrs.CONTENT_LENGTH):
                        headers.pop(hdrs.CONTENT_LENGTH)

                r_url = (resp.headers.get(hdrs.LOCATION) or
                         resp.headers.get(hdrs.URI))

                scheme = urllib.parse.urlsplit(r_url)[0]
                if scheme not in ('http', 'https', ''):
                    resp.close()
                    raise ValueError('Can redirect only to http or https')
                elif not scheme:
                    r_url = urllib.parse.urljoin(url, r_url)

                url = r_url
                params = None
                yield from resp.release()
                continue

            break

        resp._history = tuple(history)
        return resp

    def ws_connect(self, url, *,
                   protocols=(),
                   timeout=10.0,
                   autoclose=True,
                   autoping=True,
                   auth=None,
                   origin=None,
                   headers=None,
                   proxy=None,
                   proxy_auth=None):
        """Initiate websocket connection."""
        return _WSRequestContextManager(
            self._ws_connect(url,
                             protocols=protocols,
                             timeout=timeout,
                             autoclose=autoclose,
                             autoping=autoping,
                             auth=auth,
                             origin=origin,
                             headers=headers,
                             proxy=proxy,
                             proxy_auth=proxy_auth))

    @asyncio.coroutine
    def _ws_connect(self, url, *,
                    protocols=(),
                    timeout=10.0,
                    autoclose=True,
                    autoping=True,
                    auth=None,
                    origin=None,
                    headers=None,
                    proxy=None,
                    proxy_auth=None):

        sec_key = base64.b64encode(os.urandom(16))

        if headers is None:
            headers = CIMultiDict()

        default_headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_VERSION: '13',
            hdrs.SEC_WEBSOCKET_KEY: sec_key.decode(),
        }

        for key, value in default_headers.items():
            if key not in headers:
                headers[key] = value

        if protocols:
            headers[hdrs.SEC_WEBSOCKET_PROTOCOL] = ','.join(protocols)
        if origin is not None:
            headers[hdrs.ORIGIN] = origin

        # send request
        resp = yield from self.get(url, headers=headers,
                                   read_until_eof=False,
                                   auth=auth,
                                   proxy=proxy,
                                   proxy_auth=proxy_auth)

        try:
            # check handshake
            if resp.status != 101:
                raise WSServerHandshakeError(
                    message='Invalid response status',
                    code=resp.status,
                    headers=resp.headers)

            if resp.headers.get(hdrs.UPGRADE, '').lower() != 'websocket':
                raise WSServerHandshakeError(
                    message='Invalid upgrade header',
                    code=resp.status,
                    headers=resp.headers)

            if resp.headers.get(hdrs.CONNECTION, '').lower() != 'upgrade':
                raise WSServerHandshakeError(
                    message='Invalid connection header',
                    code=resp.status,
                    headers=resp.headers)

            # key calculation
            key = resp.headers.get(hdrs.SEC_WEBSOCKET_ACCEPT, '')
            match = base64.b64encode(
                hashlib.sha1(sec_key + WS_KEY).digest()).decode()
            if key != match:
                raise WSServerHandshakeError(
                    message='Invalid challenge response',
                    code=resp.status,
                    headers=resp.headers)

            # websocket protocol
            protocol = None
            if protocols and hdrs.SEC_WEBSOCKET_PROTOCOL in resp.headers:
                resp_protocols = [
                    proto.strip() for proto in
                    resp.headers[hdrs.SEC_WEBSOCKET_PROTOCOL].split(',')]

                for proto in resp_protocols:
                    if proto in protocols:
                        protocol = proto
                        break

            reader = resp.connection.reader.set_parser(WebSocketParser)
            resp.connection.writer.set_tcp_nodelay(True)
            writer = WebSocketWriter(resp.connection.writer, use_mask=True)
        except Exception:
            resp.close()
            raise
        else:
            return self._ws_response_class(reader,
                                           writer,
                                           protocol,
                                           resp,
                                           timeout,
                                           autoclose,
                                           autoping,
                                           self._loop)

    def _prepare_headers(self, headers):
        """ Add default headers and transform it to CIMultiDict
        """
        # Convert headers to MultiDict
        result = CIMultiDict(self._default_headers)
        if headers:
            if not isinstance(headers, (MultiDictProxy, MultiDict)):
                headers = CIMultiDict(headers)
            added_names = set()
            for key, value in headers.items():
                if key in added_names:
                    result.add(key, value)
                else:
                    result[key] = value
                    added_names.add(key)
        return result

    def get(self, url, *, allow_redirects=True, **kwargs):
        """Perform HTTP GET request."""
        return _RequestContextManager(
            self._request(hdrs.METH_GET, url,
                          allow_redirects=allow_redirects,
                          **kwargs))

    def options(self, url, *, allow_redirects=True, **kwargs):
        """Perform HTTP OPTIONS request."""
        return _RequestContextManager(
            self._request(hdrs.METH_OPTIONS, url,
                          allow_redirects=allow_redirects,
                          **kwargs))

    def head(self, url, *, allow_redirects=False, **kwargs):
        """Perform HTTP HEAD request."""
        return _RequestContextManager(
            self._request(hdrs.METH_HEAD, url,
                          allow_redirects=allow_redirects,
                          **kwargs))

    def post(self, url, *, data=None, **kwargs):
        """Perform HTTP POST request."""
        return _RequestContextManager(
            self._request(hdrs.METH_POST, url,
                          data=data,
                          **kwargs))

    def put(self, url, *, data=None, **kwargs):
        """Perform HTTP PUT request."""
        return _RequestContextManager(
            self._request(hdrs.METH_PUT, url,
                          data=data,
                          **kwargs))

    def patch(self, url, *, data=None, **kwargs):
        """Perform HTTP PATCH request."""
        return _RequestContextManager(
            self._request(hdrs.METH_PATCH, url,
                          data=data,
                          **kwargs))

    def delete(self, url, **kwargs):
        """Perform HTTP DELETE request."""
        return _RequestContextManager(
            self._request(hdrs.METH_DELETE, url,
                          **kwargs))

    def close(self):
        """Close underlying connector.

        Release all acquired resources.
        """
        if not self.closed:
            self._connector.close()
            self._connector = None
        ret = helpers.create_future(self._loop)
        ret.set_result(None)
        return ret

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
    def cookie_jar(self):
        """The session cookies."""
        return self._cookie_jar

    @property
    def version(self):
        """The session HTTP protocol version."""
        return self._version

    @property
    def loop(self):
        """Session's loop."""
        return self._loop

    def detach(self):
        """Detach connector from session without closing the former.

        Session is switched to closed state anyway.
        """
        self._connector = None

    def __enter__(self):
        warnings.warn("Use async with instead", DeprecationWarning)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    if PY_35:
        @asyncio.coroutine
        def __aenter__(self):
            return self

        @asyncio.coroutine
        def __aexit__(self, exc_type, exc_val, exc_tb):
            yield from self.close()

if PY_35:
    from collections.abc import Coroutine
    base = Coroutine
else:
    base = object


class _BaseRequestContextManager(base):

    __slots__ = ('_coro', '_resp')

    def __init__(self, coro):
        self._coro = coro
        self._resp = None

    def send(self, value):
        return self._coro.send(value)

    def throw(self, typ, val=None, tb=None):
        if val is None:
            return self._coro.throw(typ)
        elif tb is None:
            return self._coro.throw(typ, val)
        else:
            return self._coro.throw(typ, val, tb)

    def close(self):
        return self._coro.close()

    @property
    def gi_frame(self):
        return self._coro.gi_frame

    @property
    def gi_running(self):
        return self._coro.gi_running

    @property
    def gi_code(self):
        return self._coro.gi_code

    def __next__(self):
        return self.send(None)

    @asyncio.coroutine
    def __iter__(self):
        resp = yield from self._coro
        return resp

    if PY_35:
        def __await__(self):
            resp = yield from self._coro
            return resp

        @asyncio.coroutine
        def __aenter__(self):
            self._resp = yield from self._coro
            return self._resp


if not PY_35:
    try:
        from asyncio import coroutines
        coroutines._COROUTINE_TYPES += (_BaseRequestContextManager,)
    except:  # pragma: no cover
        pass  # Python 3.4.2 and 3.4.3 has no coroutines._COROUTINE_TYPES


class _RequestContextManager(_BaseRequestContextManager):
    if PY_35:
        @asyncio.coroutine
        def __aexit__(self, exc_type, exc, tb):
            if exc_type is not None:
                self._resp.close()
            else:
                yield from self._resp.release()


class _WSRequestContextManager(_BaseRequestContextManager):
    if PY_35:
        @asyncio.coroutine
        def __aexit__(self, exc_type, exc, tb):
            yield from self._resp.close()


class _DetachedRequestContextManager(_RequestContextManager):

    __slots__ = _RequestContextManager.__slots__ + ('_session', )

    def __init__(self, coro, session):
        super().__init__(coro)
        self._session = session

    @asyncio.coroutine
    def __iter__(self):
        try:
            return (yield from self._coro)
        except:
            yield from self._session.close()
            raise

    if PY_35:
        def __await__(self):
            try:
                return (yield from self._coro)
            except:
                yield from self._session.close()
                raise

    def __del__(self):
        self._session.detach()


class _DetachedWSRequestContextManager(_WSRequestContextManager):

    __slots__ = _WSRequestContextManager.__slots__ + ('_session', )

    def __init__(self, coro, session):
        super().__init__(coro)
        self._session = session

    def __del__(self):
        self._session.detach()


def request(method, url, *,
            params=None,
            data=None,
            headers=None,
            skip_auto_headers=None,
            cookies=None,
            auth=None,
            allow_redirects=True,
            max_redirects=10,
            encoding='utf-8',
            version=None,
            compress=None,
            chunked=None,
            expect100=False,
            connector=None,
            loop=None,
            read_until_eof=True,
            request_class=None,
            response_class=None,
            proxy=None,
            proxy_auth=None):
    """Constructs and sends a request. Returns response object.

    method - HTTP method
    url - request url
    params - (optional) Dictionary or bytes to be sent in the query
      string of the new request
    data - (optional) Dictionary, bytes, or file-like object to
      send in the body of the request
    headers - (optional) Dictionary of HTTP Headers to send with
      the request
    cookies - (optional) Dict object to send with the request
    auth - (optional) BasicAuth named tuple represent HTTP Basic Auth
    auth - aiohttp.helpers.BasicAuth
    allow_redirects - (optional) If set to False, do not follow
      redirects
    version - Request HTTP version.
    compress - Set to True if request has to be compressed
       with deflate encoding.
    chunked - Set to chunk size for chunked transfer encoding.
    expect100 - Expect 100-continue response from server.
    connector - BaseConnector sub-class instance to support
       connection pooling.
    read_until_eof - Read response until eof if response
       does not have Content-Length header.
    request_class - (optional) Custom Request class implementation.
    response_class - (optional) Custom Response class implementation.
    loop - Optional event loop.

    Usage::

      >>> import aiohttp
      >>> resp = yield from aiohttp.request('GET', 'http://python.org/')
      >>> resp
      <ClientResponse(python.org/) [200]>
      >>> data = yield from resp.read()

    """
    warnings.warn("Use ClientSession().request() instead", DeprecationWarning)
    if connector is None:
        connector = aiohttp.TCPConnector(loop=loop, force_close=True)

    kwargs = {}

    if request_class is not None:
        kwargs['request_class'] = request_class

    if response_class is not None:
        kwargs['response_class'] = response_class

    session = ClientSession(loop=loop,
                            cookies=cookies,
                            connector=connector,
                            **kwargs)
    return _DetachedRequestContextManager(
        session._request(method, url,
                         params=params,
                         data=data,
                         headers=headers,
                         skip_auto_headers=skip_auto_headers,
                         auth=auth,
                         allow_redirects=allow_redirects,
                         max_redirects=max_redirects,
                         encoding=encoding,
                         version=version,
                         compress=compress,
                         chunked=chunked,
                         expect100=expect100,
                         read_until_eof=read_until_eof,
                         proxy=proxy,
                         proxy_auth=proxy_auth,),
        session=session)


def get(url, **kwargs):
    warnings.warn("Use ClientSession().get() instead", DeprecationWarning)
    return request(hdrs.METH_GET, url, **kwargs)


def options(url, **kwargs):
    warnings.warn("Use ClientSession().options() instead", DeprecationWarning)
    return request(hdrs.METH_OPTIONS, url, **kwargs)


def head(url, **kwargs):
    warnings.warn("Use ClientSession().head() instead", DeprecationWarning)
    return request(hdrs.METH_HEAD, url, **kwargs)


def post(url, **kwargs):
    warnings.warn("Use ClientSession().post() instead", DeprecationWarning)
    return request(hdrs.METH_POST, url, **kwargs)


def put(url, **kwargs):
    warnings.warn("Use ClientSession().put() instead", DeprecationWarning)
    return request(hdrs.METH_PUT, url, **kwargs)


def patch(url, **kwargs):
    warnings.warn("Use ClientSession().patch() instead", DeprecationWarning)
    return request(hdrs.METH_PATCH, url, **kwargs)


def delete(url, **kwargs):
    warnings.warn("Use ClientSession().delete() instead", DeprecationWarning)
    return request(hdrs.METH_DELETE, url, **kwargs)


def ws_connect(url, *, protocols=(), timeout=10.0, connector=None, auth=None,
               ws_response_class=ClientWebSocketResponse, autoclose=True,
               autoping=True, loop=None, origin=None, headers=None):

    warnings.warn("Use ClientSession().ws_connect() instead",
                  DeprecationWarning)
    if loop is None:
        loop = asyncio.get_event_loop()

    if connector is None:
        connector = aiohttp.TCPConnector(loop=loop, force_close=True)

    session = aiohttp.ClientSession(loop=loop, connector=connector, auth=auth,
                                    ws_response_class=ws_response_class,
                                    headers=headers)

    return _DetachedWSRequestContextManager(
        session._ws_connect(url,
                            protocols=protocols,
                            timeout=timeout,
                            autoclose=autoclose,
                            autoping=autoping,
                            origin=origin),
        session=session)
