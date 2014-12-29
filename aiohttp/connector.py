__all__ = ['BaseConnector', 'TCPConnector', 'ProxyConnector', 'UnixConnector']

import asyncio
import aiohttp
import functools
import http.cookies
import time
import ssl
import socket
import weakref

from .client import ClientRequest
from .errors import ServerDisconnectedError
from .errors import HttpProxyError, ProxyConnectionError
from .errors import ClientOSError, ClientTimeoutError
from .helpers import BasicAuth


class Connection(object):

    def __init__(self, connector, key, request, transport, protocol, loop):
        self._key = key
        self._connector = connector
        self._request = request
        self._transport = transport
        self._protocol = protocol
        self._loop = loop
        self.reader = protocol.reader
        self.writer = protocol.writer
        self._wr = weakref.ref(self, lambda wr, tr=self._transport: tr.close())

    @property
    def loop(self):
        return self._loop

    def close(self):
        if self._transport is not None:
            self._connector._release(
                self._key, self._request, self._transport, self._protocol,
                should_close=True)
            self._transport = None
            self._wr = None

    def release(self):
        if self._transport:
            self._connector._release(
                self._key, self._request, self._transport, self._protocol)
            self._transport = None
            self._wr = None

    def share_cookies(self, cookies):
        if self._connector._share_cookies:  # XXX
            self._connector.update_cookies(cookies)


class BaseConnector(object):
    """Base connector class.

    :param conn_timeout: (optional) Connect timeout.
    :param keepalive_timeout: (optional) Keep-alive timeout.
    :param bool share_cookies: Set to True to keep cookies between requests.
    :param bool force_close: Set to True to froce close and do reconnect
        after each request (and between redirects).
    :param loop: Optional event loop.
    """

    def __init__(self, *, conn_timeout=None, keepalive_timeout=30,
                 share_cookies=False, force_close=False, loop=None):
        self._conns = {}
        self._conn_timeout = conn_timeout
        self._keepalive_timeout = keepalive_timeout
        self._share_cookies = share_cookies
        self._cleanup_handle = None
        self._force_close = force_close

        if loop is None:
            loop = asyncio.get_event_loop()
        self._loop = loop
        self._factory = functools.partial(
            aiohttp.StreamProtocol, loop=loop,
            disconnect_error=ServerDisconnectedError)

        self.cookies = http.cookies.SimpleCookie()
        self._wr = weakref.ref(
            self, lambda wr, f=self._do_close, conns=self._conns: f(conns))

    def _cleanup(self):
        """Cleanup unused transports."""
        if self._cleanup_handle:
            self._cleanup_handle.cancel()
            self._cleanup_handle = None

        now = time.time()

        connections = {}
        for key, conns in self._conns.items():
            alive = []
            for transport, proto, t0 in conns:
                if transport is not None:
                    if proto and not proto.is_connected():
                        transport = None
                    elif (now - t0) > self._keepalive_timeout:
                        transport.close()
                        transport = None

                if transport:
                    alive.append((transport, proto, t0))
            if alive:
                connections[key] = alive

        if connections:
            self._cleanup_handle = self._loop.call_later(
                self._keepalive_timeout, self._cleanup)

        self._conns = connections
        self._wr = weakref.ref(
            self, lambda wr, f=self._do_close, conns=self._conns: f(conns))

    def _start_cleanup_task(self):
        if self._cleanup_handle is None:
            self._cleanup_handle = self._loop.call_later(
                self._keepalive_timeout, self._cleanup)

    def close(self):
        """Close all opened transports."""
        self._do_close(self._conns)

    @staticmethod
    def _do_close(conns):
        for key, data in conns.items():
            for transport, proto, td in data:
                transport.close()

        conns.clear()

    def update_cookies(self, cookies):
        """Update shared cookies."""
        if isinstance(cookies, dict):
            cookies = cookies.items()

        for name, value in cookies:
            if isinstance(value, http.cookies.Morsel):
                # use dict method because SimpleCookie class modifies value
                dict.__setitem__(self.cookies, name, value)
            else:
                self.cookies[name] = value

    @asyncio.coroutine
    def connect(self, req):
        """Get from pool or create new connection."""
        key = (req.host, req.port, req.ssl)

        if self._share_cookies:
            req.update_cookies(self.cookies.items())

        transport, proto = self._get(key)
        if transport is None:
            try:
                if self._conn_timeout:
                    transport, proto = yield from asyncio.wait_for(
                        self._create_connection(req),
                        self._conn_timeout, loop=self._loop)
                else:
                    transport, proto = yield from self._create_connection(req)
            except asyncio.TimeoutError as exc:
                raise ClientTimeoutError() from exc
            except OSError as exc:
                raise ClientOSError() from exc

        return Connection(self, key, req, transport, proto, self._loop)

    def _get(self, key):
        conns = self._conns.get(key)
        while conns:
            transport, proto, t0 = conns.pop()
            if transport is not None and proto.is_connected():
                if (time.time() - t0) > self._keepalive_timeout:
                    transport.close()
                    transport = None
                else:
                    return transport, proto

        return None, None

    def _release(self, key, req, transport, protocol, *, should_close=False):
        resp = req.response

        if not should_close:
            if resp is not None:
                if resp.message is None:
                    should_close = True
                else:
                    should_close = resp.message.should_close

            if self._force_close:
                should_close = True

        reader = protocol.reader
        if should_close or (reader.output and not reader.output.at_eof()):
            self._conns.pop(key, None)
            transport.close()
        else:
            conns = self._conns.get(key)
            if conns is None:
                conns = self._conns[key] = []
            conns.append((transport, protocol, time.time()))
            reader.unset_parser()

            self._start_cleanup_task()

    def _create_connection(self, req, *args, **kwargs):
        raise NotImplementedError()


_SSL_OP_NO_COMPRESSION = getattr(ssl, "OP_NO_COMPRESSION", 0)
_SSH_HAS_CREATE_DEFAULT_CONTEXT = hasattr(ssl, 'create_default_context')


class TCPConnector(BaseConnector):
    """TCP connector.

    :param bool verify_ssl: Set to True to check ssl certifications.
    :param bool resolve: Set to True to do DNS lookup for host name.
    :param familiy: socket address family
    :param args: see :class:`BaseConnector`
    :param kwargs: see :class:`BaseConnector`
    """

    def __init__(self, *args, verify_ssl=True,
                 resolve=False, family=socket.AF_INET, ssl_context=None,
                 **kwargs):
        if not verify_ssl and ssl_context is not None:
            raise ValueError(
                "Either disable ssl certificate validation by "
                "verify_ssl=False or specify ssl_context, not both.")

        super().__init__(*args, **kwargs)

        self._verify_ssl = verify_ssl
        self._ssl_context = ssl_context
        self._family = family
        self._resolve = resolve
        self._resolved_hosts = {}

    @property
    def verify_ssl(self):
        """Do check for ssl certifications?"""
        return self._verify_ssl

    @property
    def ssl_context(self):
        """SSLContext instance for https requests.

        Lazy property, creates context on demand.
        """
        if self._ssl_context is None:
            if not self._verify_ssl:
                sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                sslcontext.options |= ssl.OP_NO_SSLv2
                sslcontext.options |= ssl.OP_NO_SSLv3
                sslcontext.options |= _SSL_OP_NO_COMPRESSION
                sslcontext.set_default_verify_paths()
            elif _SSH_HAS_CREATE_DEFAULT_CONTEXT:
                # Python 3.4+
                sslcontext = ssl.create_default_context()
            else:  # pragma: no cover
                # Fallback for Python 3.3.
                sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                sslcontext.options |= ssl.OP_NO_SSLv2
                sslcontext.options |= ssl.OP_NO_SSLv3
                sslcontext.options |= _SSL_OP_NO_COMPRESSION
                sslcontext.set_default_verify_paths()
                sslcontext.verify_mode = ssl.CERT_REQUIRED
            self._ssl_context = sslcontext
        return self._ssl_context

    @property
    def family(self):
        """Socket family like AF_INET."""
        return self._family

    @property
    def resolve(self):
        """Do DNS lookup for host name?"""
        return self._resolve

    @property
    def resolved_hosts(self):
        """The dict of (host, port) -> (ipaddr, port) pairs."""
        return dict(self._resolved_hosts)

    def clear_resolved_hosts(self, host=None, port=None):
        """Remove specified host/port or clear all resolve cache."""
        if host is not None and port is not None:
            key = (host, port)
            if key in self._resolved_hosts:
                del self._resolved_hosts[key]
        else:
            self._resolved_hosts.clear()

    @asyncio.coroutine
    def _resolve_host(self, host, port):
        if self._resolve:
            key = (host, port)

            if key not in self._resolved_hosts:
                infos = yield from self._loop.getaddrinfo(
                    host, port, type=socket.SOCK_STREAM, family=self._family)

                hosts = []
                for family, _, proto, _, address in infos:
                    hosts.append(
                        {'hostname': host,
                         'host': address[0], 'port': address[1],
                         'family': family, 'proto': proto,
                         'flags': socket.AI_NUMERICHOST})
                self._resolved_hosts[key] = hosts

            return list(self._resolved_hosts[key])
        else:
            return [{'hostname': host, 'host': host, 'port': port,
                     'family': self._family, 'proto': 0, 'flags': 0}]

    def _create_connection(self, req, **kwargs):
        """Create connection.

        Has same keyword arguments as BaseEventLoop.create_connection.
        """
        if req.ssl:
            sslcontext = self.ssl_context
        else:
            sslcontext = None

        hosts = yield from self._resolve_host(req.host, req.port)

        while hosts:
            hinfo = hosts.pop()
            try:
                return (yield from self._loop.create_connection(
                    self._factory, hinfo['host'], hinfo['port'],
                    ssl=sslcontext, family=hinfo['family'],
                    proto=hinfo['proto'], flags=hinfo['flags'],
                    server_hostname=hinfo['hostname'] if sslcontext else None,
                    **kwargs))
            except OSError as exc:
                if not hosts:
                    raise ClientOSError('Can not connect to %s:%s' %
                                        (req.host, req.port)) from exc


class ProxyConnector(TCPConnector):
    """Http Proxy connector.

    :param str proxy: Proxy URL address. Only http proxy supported.
    :param proxy_auth: (optional) Proxy HTTP Basic Auth
    :type proxy_auth: aiohttp.helpers.BasicAuth
    :param args: see :class:`TCPConnector`
    :param kwargs: see :class:`TCPConnector`

    Usage:

    >>> conn = ProxyConnector(proxy="http://some.proxy.com")
    >>> resp = yield from request('GET', 'http://python.org', connector=conn)

    """

    def __init__(self, proxy, *args, proxy_auth=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._proxy = proxy
        self._proxy_auth = proxy_auth
        assert proxy.startswith('http://'), (
            "Only http proxy supported", proxy)
        assert proxy_auth is None or isinstance(proxy_auth, BasicAuth), (
            "proxy_auth must be None or BasicAuth() tuple", proxy_auth)

    @property
    def proxy(self):
        """Proxy URL."""
        return self._proxy

    @asyncio.coroutine
    def _create_connection(self, req, **kwargs):
        proxy_req = ClientRequest(
            'GET', self._proxy,
            headers={'Host': req.host},
            auth=self._proxy_auth,
            loop=self._loop)
        try:
            transport, proto = yield from super()._create_connection(proxy_req)
        except OSError as exc:
            raise ProxyConnectionError(*exc.args) from exc

        req.path = '{scheme}://{host}{path}'.format(scheme=req.scheme,
                                                    host=req.netloc,
                                                    path=req.path)
        if 'AUTHORIZATION' in proxy_req.headers:
            auth = proxy_req.headers['AUTHORIZATION']
            del proxy_req.headers['AUTHORIZATION']
            req.headers['PROXY-AUTHORIZATION'] = auth

        if req.ssl:
            # For HTTPS requests over HTTP proxy
            # we must notify proxy to tunnel connection
            # so we send CONNECT command:
            #   CONNECT www.python.org:443 HTTP/1.1
            #   Host: www.python.org
            #
            # next we must do TLS handshake and so on
            # to do this we must wrap raw socket into secure one
            # asyncio handles this perfectly
            proxy_req.method = 'CONNECT'
            proxy_req.path = '{}:{}'.format(req.host, req.port)
            key = (req.host, req.port, req.ssl)
            conn = Connection(self, key, proxy_req,
                              transport, proto, self._loop)
            proxy_resp = proxy_req.send(conn.writer, conn.reader)
            try:
                resp = yield from proxy_resp.start(conn, True)
            except:
                proxy_resp.close()
                conn.close()
                raise
            else:
                if resp.status != 200:
                    raise HttpProxyError(code=resp.status, message=resp.reason)
                rawsock = transport.get_extra_info('socket', default=None)
                if rawsock is None:
                    raise RuntimeError(
                        "Transport does not expose socket instance")
                transport.pause_reading()
                transport, proto = yield from self._loop.create_connection(
                    self._factory, ssl=True, sock=rawsock,
                    server_hostname=req.host, **kwargs)

        return transport, proto


class UnixConnector(BaseConnector):
    """Unix socket connector.

    :param str path: Unix socket path.
    :param args: see :class:`BaseConnector`
    :param kwargs: see :class:`BaseConnector`

    Usage:

    >>> conn = UnixConnector(path='/path/to/socket')
    >>> resp = yield from request('GET', 'http://python.org', connector=conn)

    """

    def __init__(self, path, *args, **kw):
        super().__init__(*args, **kw)
        self._path = path

    @property
    def path(self):
        """Path to unix socket."""
        return self._path

    @asyncio.coroutine
    def _create_connection(self, req, **kwargs):
        return (yield from self._loop.create_unix_connection(
            self._factory, self._path, **kwargs))
