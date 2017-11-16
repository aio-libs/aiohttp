"""HTTP Client for asyncio."""

import asyncio
import base64
import hashlib
import json
import os
import sys
import traceback
import warnings

from multidict import CIMultiDict, MultiDict, MultiDictProxy, istr
from yarl import URL

from . import connector as connector_mod
from . import client_exceptions, client_reqrep, hdrs, http, payload
from .client_exceptions import *  # noqa
from .client_exceptions import (ClientError, ClientOSError, InvalidURL,
                                ServerTimeoutError, WSServerHandshakeError)
from .client_reqrep import *  # noqa
from .client_reqrep import ClientRequest, ClientResponse
from .client_ws import ClientWebSocketResponse
from .connector import *  # noqa
from .connector import TCPConnector
from .cookiejar import CookieJar
from .helpers import (PY_35, CeilTimeout, TimeoutHandle, _BaseCoroMixin,
                      deprecated_noop, proxies_from_env, sentinel,
                      strip_auth_from_url)
from .http import WS_KEY, WebSocketReader, WebSocketWriter
from .http_websocket import WSHandshakeError, ws_ext_gen, ws_ext_parse
from .streams import FlowControlDataQueue


__all__ = (client_exceptions.__all__ +  # noqa
           client_reqrep.__all__ +  # noqa
           connector_mod.__all__ +  # noqa
           ('ClientSession', 'ClientWebSocketResponse', 'request'))


# 5 Minute default read and connect timeout
DEFAULT_TIMEOUT = 5 * 60


class ClientSession:
    """First-class interface for making HTTP requests."""

    _source_traceback = None
    _connector = None

    requote_redirect_url = True

    def __init__(self, *, connector=None, loop=None, cookies=None,
                 headers=None, skip_auto_headers=None,
                 auth=None, json_serialize=json.dumps,
                 request_class=ClientRequest, response_class=ClientResponse,
                 ws_response_class=ClientWebSocketResponse,
                 version=http.HttpVersion11,
                 cookie_jar=None, connector_owner=True, raise_for_status=False,
                 read_timeout=sentinel, conn_timeout=None,
                 auto_decompress=True, trust_env=False):

        implicit_loop = False
        if loop is None:
            if connector is not None:
                loop = connector._loop
            else:
                implicit_loop = True
                loop = asyncio.get_event_loop()

        if connector is None:
            connector = TCPConnector(loop=loop)

        if connector._loop is not loop:
            raise RuntimeError(
                "Session and connector has to use same event loop")

        self._loop = loop

        if loop.get_debug():
            self._source_traceback = traceback.extract_stack(sys._getframe(1))

        if implicit_loop and not loop.is_running():
            warnings.warn("Creating a client session outside of coroutine is "
                          "a very dangerous idea", ResourceWarning,
                          stacklevel=2)
            context = {'client_session': self,
                       'message': 'Creating a client session outside '
                       'of coroutine'}
            if self._source_traceback is not None:
                context['source_traceback'] = self._source_traceback
            loop.call_exception_handler(context)

        if cookie_jar is None:
            cookie_jar = CookieJar(loop=loop)
        self._cookie_jar = cookie_jar

        if cookies is not None:
            self._cookie_jar.update_cookies(cookies)
        self._connector = connector
        self._connector_owner = connector_owner
        self._default_auth = auth
        self._version = version
        self._json_serialize = json_serialize
        self._read_timeout = (read_timeout if read_timeout is not sentinel
                              else DEFAULT_TIMEOUT)
        self._conn_timeout = conn_timeout
        self._raise_for_status = raise_for_status
        self._auto_decompress = auto_decompress
        self._trust_env = trust_env

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
            _warnings.warn("Unclosed client session {!r}".format(self),
                           ResourceWarning)
            context = {'client_session': self,
                       'message': 'Unclosed client session'}
            if self._source_traceback is not None:
                context['source_traceback'] = self._source_traceback
            self._loop.call_exception_handler(context)

    def request(self, method, url, **kwargs):
        """Perform HTTP request."""
        return _RequestContextManager(self._request(method, url, **kwargs))

    @asyncio.coroutine
    def _request(self, method, url, *,
                 params=None,
                 data=None,
                 json=None,
                 headers=None,
                 skip_auto_headers=None,
                 auth=None,
                 allow_redirects=True,
                 max_redirects=10,
                 encoding=None,
                 compress=None,
                 chunked=None,
                 expect100=False,
                 read_until_eof=True,
                 proxy=None,
                 proxy_auth=None,
                 timeout=sentinel,
                 verify_ssl=None,
                 fingerprint=None,
                 ssl_context=None,
                 proxy_headers=None):

        # NOTE: timeout clamps existing connect and read timeouts.  We cannot
        # set the default to None because we need to detect if the user wants
        # to use the existing timeouts by setting timeout to None.

        if encoding is not None:
            warnings.warn(
                "encoding parameter is not supported, "
                "please use FormData(charset='utf-8') instead",
                DeprecationWarning)

        if self.closed:
            raise RuntimeError('Session is closed')

        if data is not None and json is not None:
            raise ValueError(
                'data and json parameters can not be used at the same time')
        elif json is not None:
            data = payload.JsonPayload(json, dumps=self._json_serialize)

        if not isinstance(chunked, bool) and chunked is not None:
            warnings.warn(
                'Chunk size is deprecated #1615', DeprecationWarning)

        redirects = 0
        history = []
        version = self._version

        # Merge with default headers and transform to CIMultiDict
        headers = self._prepare_headers(headers)
        proxy_headers = self._prepare_headers(proxy_headers)

        try:
            url = URL(url)
        except ValueError:
            raise InvalidURL(url)

        skip_headers = set(self._skip_auto_headers)
        if skip_auto_headers is not None:
            for i in skip_auto_headers:
                skip_headers.add(istr(i))

        if proxy is not None:
            try:
                proxy = URL(proxy)
            except ValueError:
                raise InvalidURL(url)

        # timeout is cumulative for all request operations
        # (request, redirects, responses, data consuming)
        tm = TimeoutHandle(
            self._loop,
            timeout if timeout is not sentinel else self._read_timeout)
        handle = tm.start()

        url = URL(url)
        timer = tm.timer()
        try:
            with timer:
                while True:
                    url, auth_from_url = strip_auth_from_url(url)
                    if auth and auth_from_url:
                        raise ValueError("Cannot combine AUTH argument with "
                                         "credentials encoded in URL")

                    if auth is None:
                        auth = auth_from_url
                    if auth is None:
                        auth = self._default_auth
                    # It would be confusing if we support explicit
                    # Authorization header with auth argument
                    if (headers is not None and
                            auth is not None and
                            hdrs.AUTHORIZATION in headers):
                        raise ValueError("Cannot combine AUTHORIZATION header "
                                         "with AUTH argument or credentials "
                                         "encoded in URL")

                    url = url.with_fragment(None)
                    cookies = self._cookie_jar.filter_cookies(url)

                    if proxy is not None:
                        proxy = URL(proxy)
                    elif self._trust_env:
                        for scheme, proxy_info in proxies_from_env().items():
                            if scheme == url.scheme:
                                proxy, proxy_auth = proxy_info
                                break

                    req = self._request_class(
                        method, url, params=params, headers=headers,
                        skip_auto_headers=skip_headers, data=data,
                        cookies=cookies, auth=auth, version=version,
                        compress=compress, chunked=chunked,
                        expect100=expect100, loop=self._loop,
                        response_class=self._response_class,
                        proxy=proxy, proxy_auth=proxy_auth, timer=timer,
                        session=self, auto_decompress=self._auto_decompress,
                        verify_ssl=verify_ssl, fingerprint=fingerprint,
                        ssl_context=ssl_context, proxy_headers=proxy_headers)

                    # connection timeout
                    try:
                        with CeilTimeout(self._conn_timeout, loop=self._loop):
                            conn = yield from self._connector.connect(req)
                    except asyncio.TimeoutError as exc:
                        raise ServerTimeoutError(
                            'Connection timeout '
                            'to host {0}'.format(url)) from exc

                    conn.writer.set_tcp_nodelay(True)
                    try:
                        resp = req.send(conn)
                        try:
                            yield from resp.start(conn, read_until_eof)
                        except:
                            resp.close()
                            conn.close()
                            raise
                    except ClientError:
                        raise
                    except OSError as exc:
                        raise ClientOSError(*exc.args) from exc

                    self._cookie_jar.update_cookies(resp.cookies, resp.url)

                    # redirects
                    if resp.status in (
                            301, 302, 303, 307, 308) and allow_redirects:
                        redirects += 1
                        history.append(resp)
                        if max_redirects and redirects >= max_redirects:
                            resp.close()
                            break
                        else:
                            resp.release()

                        # For 301 and 302, mimic IE, now changed in RFC
                        # https://github.com/kennethreitz/requests/pull/269
                        if (resp.status == 303 and
                                resp.method != hdrs.METH_HEAD) \
                                or (resp.status in (301, 302) and
                                    resp.method == hdrs.METH_POST):
                            method = hdrs.METH_GET
                            data = None
                            if headers.get(hdrs.CONTENT_LENGTH):
                                headers.pop(hdrs.CONTENT_LENGTH)

                        r_url = (resp.headers.get(hdrs.LOCATION) or
                                 resp.headers.get(hdrs.URI))
                        if r_url is None:
                            # see github.com/aio-libs/aiohttp/issues/2022
                            break

                        try:
                            r_url = URL(
                                r_url, encoded=not self.requote_redirect_url)

                        except ValueError:
                            raise InvalidURL(r_url)

                        scheme = r_url.scheme
                        if scheme not in ('http', 'https', ''):
                            resp.close()
                            raise ValueError(
                                'Can redirect only to http or https')
                        elif not scheme:
                            r_url = url.join(r_url)

                        if url.origin() != r_url.origin():
                            auth = None
                            headers.pop(hdrs.AUTHORIZATION, None)

                        url = r_url
                        params = None
                        resp.release()
                        continue

                    break

            # check response status
            if self._raise_for_status:
                resp.raise_for_status()

            # register connection
            if handle is not None:
                if resp.connection is not None:
                    resp.connection.add_callback(handle.cancel)
                else:
                    handle.cancel()

            resp._history = tuple(history)
            return resp

        except:
            # cleanup timer
            tm.close()
            if handle:
                handle.cancel()
                handle = None

            raise

    def ws_connect(self, url, *,
                   protocols=(),
                   timeout=10.0,
                   receive_timeout=None,
                   autoclose=True,
                   autoping=True,
                   heartbeat=None,
                   auth=None,
                   origin=None,
                   headers=None,
                   proxy=None,
                   proxy_auth=None,
                   verify_ssl=None,
                   fingerprint=None,
                   ssl_context=None,
                   proxy_headers=None,
                   compress=0):
        """Initiate websocket connection."""
        return _WSRequestContextManager(
            self._ws_connect(url,
                             protocols=protocols,
                             timeout=timeout,
                             receive_timeout=receive_timeout,
                             autoclose=autoclose,
                             autoping=autoping,
                             heartbeat=heartbeat,
                             auth=auth,
                             origin=origin,
                             headers=headers,
                             proxy=proxy,
                             proxy_auth=proxy_auth,
                             verify_ssl=verify_ssl,
                             fingerprint=fingerprint,
                             ssl_context=ssl_context,
                             proxy_headers=proxy_headers,
                             compress=compress))

    @asyncio.coroutine
    def _ws_connect(self, url, *,
                    protocols=(),
                    timeout=10.0,
                    receive_timeout=None,
                    autoclose=True,
                    autoping=True,
                    heartbeat=None,
                    auth=None,
                    origin=None,
                    headers=None,
                    proxy=None,
                    proxy_auth=None,
                    verify_ssl=None,
                    fingerprint=None,
                    ssl_context=None,
                    proxy_headers=None,
                    compress=0):

        if headers is None:
            headers = CIMultiDict()

        default_headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_VERSION: '13',
        }

        for key, value in default_headers.items():
            if key not in headers:
                headers[key] = value

        sec_key = base64.b64encode(os.urandom(16))
        headers[hdrs.SEC_WEBSOCKET_KEY] = sec_key.decode()

        if protocols:
            headers[hdrs.SEC_WEBSOCKET_PROTOCOL] = ','.join(protocols)
        if origin is not None:
            headers[hdrs.ORIGIN] = origin
        if compress:
            extstr = ws_ext_gen(compress=compress)
            headers[hdrs.SEC_WEBSOCKET_EXTENSIONS] = extstr

        # send request
        resp = yield from self.get(url, headers=headers,
                                   read_until_eof=False,
                                   auth=auth,
                                   proxy=proxy,
                                   proxy_auth=proxy_auth,
                                   verify_ssl=verify_ssl,
                                   fingerprint=fingerprint,
                                   ssl_context=ssl_context,
                                   proxy_headers=proxy_headers)

        try:
            # check handshake
            if resp.status != 101:
                raise WSServerHandshakeError(
                    resp.request_info,
                    resp.history,
                    message='Invalid response status',
                    code=resp.status,
                    headers=resp.headers)

            if resp.headers.get(hdrs.UPGRADE, '').lower() != 'websocket':
                raise WSServerHandshakeError(
                    resp.request_info,
                    resp.history,
                    message='Invalid upgrade header',
                    code=resp.status,
                    headers=resp.headers)

            if resp.headers.get(hdrs.CONNECTION, '').lower() != 'upgrade':
                raise WSServerHandshakeError(
                    resp.request_info,
                    resp.history,
                    message='Invalid connection header',
                    code=resp.status,
                    headers=resp.headers)

            # key calculation
            key = resp.headers.get(hdrs.SEC_WEBSOCKET_ACCEPT, '')
            match = base64.b64encode(
                hashlib.sha1(sec_key + WS_KEY).digest()).decode()
            if key != match:
                raise WSServerHandshakeError(
                    resp.request_info,
                    resp.history,
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

            # websocket compress
            notakeover = False
            if compress:
                compress_hdrs = resp.headers.get(hdrs.SEC_WEBSOCKET_EXTENSIONS)
                if compress_hdrs:
                    try:
                        compress, notakeover = ws_ext_parse(compress_hdrs)
                    except WSHandshakeError as exc:
                        raise WSServerHandshakeError(
                            resp.request_info,
                            resp.history,
                            message=exc.args[0],
                            code=resp.status,
                            headers=resp.headers)
                else:
                    compress = 0
                    notakeover = False

            proto = resp.connection.protocol
            reader = FlowControlDataQueue(
                proto, limit=2 ** 16, loop=self._loop)
            proto.set_parser(WebSocketReader(reader), reader)
            resp.connection.writer.set_tcp_nodelay(True)
            writer = WebSocketWriter(
                resp.connection.writer, use_mask=True,
                compress=compress, notakeover=notakeover)
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
                                           self._loop,
                                           receive_timeout=receive_timeout,
                                           heartbeat=heartbeat,
                                           compress=compress,
                                           client_notakeover=notakeover)

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
            if self._connector_owner:
                self._connector.close()
            self._connector = None

        return deprecated_noop('ClientSession.close() is a coroutine')

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


class _BaseRequestContextManager(_BaseCoroMixin):

    __slots__ = ('_resp',)

    def __init__(self, coro):
        super().__init__(coro)
        self._coro = coro

    if PY_35:
        @asyncio.coroutine
        def __aenter__(self):
            self._resp = yield from self._coro
            return self._resp


class _RequestContextManager(_BaseRequestContextManager):
    if PY_35:
        @asyncio.coroutine
        def __aexit__(self, exc_type, exc, tb):
            # We're basing behavior on the exception as it can be caused by
            # user code unrelated to the status of the connection.  If you
            # would like to close a connection you must do that
            # explicitly.  Otherwise connection error handling should kick in
            # and close/recycle the connection as required.
            self._resp.release()


class _WSRequestContextManager(_BaseRequestContextManager):
    if PY_35:
        @asyncio.coroutine
        def __aexit__(self, exc_type, exc, tb):
            yield from self._resp.close()


class _SessionRequestContextManager(_RequestContextManager):

    __slots__ = _RequestContextManager.__slots__ + ('_session', )

    def __init__(self, coro, session):
        super().__init__(coro)
        self._session = session

    @asyncio.coroutine
    def __iter__(self):
        try:
            return (yield from self._coro)
        except BaseException:
            yield from self._session.close()
            raise

    if PY_35:
        def __await__(self):
            try:
                return (yield from self._coro)
            except BaseException:
                yield from self._session.close()
                raise


def request(method, url, *,
            params=None,
            data=None,
            json=None,
            headers=None,
            skip_auto_headers=None,
            cookies=None,
            auth=None,
            allow_redirects=True,
            max_redirects=10,
            encoding=None,
            version=http.HttpVersion11,
            compress=None,
            chunked=None,
            expect100=False,
            connector=None,
            loop=None,
            read_until_eof=True,
            proxy=None,
            proxy_auth=None):
    """Constructs and sends a request. Returns response object.
    method - HTTP method
    url - request url
    params - (optional) Dictionary or bytes to be sent in the query
      string of the new request
    data - (optional) Dictionary, bytes, or file-like object to
      send in the body of the request
    json - (optional) Any json compatibile python object
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
    loop - Optional event loop.
    Usage::
      >>> import aiohttp
      >>> resp = yield from aiohttp.request('GET', 'http://python.org/')
      >>> resp
      <ClientResponse(python.org/) [200]>
      >>> data = yield from resp.read()
    """
    connector_owner = False
    if connector is None:
        connector_owner = True
        connector = TCPConnector(loop=loop, force_close=True)

    session = ClientSession(
        loop=loop, cookies=cookies, version=version,
        connector=connector, connector_owner=connector_owner)

    return _SessionRequestContextManager(
        session._request(method, url,
                         params=params,
                         data=data,
                         json=json,
                         headers=headers,
                         skip_auto_headers=skip_auto_headers,
                         auth=auth,
                         allow_redirects=allow_redirects,
                         max_redirects=max_redirects,
                         encoding=encoding,
                         compress=compress,
                         chunked=chunked,
                         expect100=expect100,
                         read_until_eof=read_until_eof,
                         proxy=proxy,
                         proxy_auth=proxy_auth,),
        session=session)
