import asyncio
import aiohttp
import functools
import http.cookies
import ssl
import socket
import sys
import traceback
import warnings

from collections import defaultdict
from hashlib import md5, sha1, sha256
from itertools import chain
from math import ceil
from types import MappingProxyType

from . import hdrs
from .client import ClientRequest
from .errors import ServerDisconnectedError
from .errors import HttpProxyError, ProxyConnectionError
from .errors import ClientOSError, ClientTimeoutError
from .errors import FingerprintMismatch
from .helpers import BasicAuth


__all__ = ('BaseConnector', 'TCPConnector', 'ProxyConnector', 'UnixConnector')

PY_341 = sys.version_info >= (3, 4, 1)
PY_343 = sys.version_info >= (3, 4, 3)

HASHFUNC_BY_DIGESTLEN = {
    16: md5,
    20: sha1,
    32: sha256,
}


class Connection(object):

    _source_traceback = None
    _transport = None

    def __init__(self, connector, key, request, transport, protocol, loop):
        self._key = key
        self._connector = connector
        self._request = request
        self._transport = transport
        self._protocol = protocol
        self._loop = loop
        self.reader = protocol.reader
        self.writer = protocol.writer

        if loop.get_debug():
            self._source_traceback = traceback.extract_stack(sys._getframe(1))

    if PY_341:
        def __del__(self):
            if self._transport is not None:
                if hasattr(self._loop, 'is_closed'):
                    if self._loop.is_closed():
                        return

                self._connector._release(
                    self._key, self._request, self._transport, self._protocol,
                    should_close=True)

                warnings.warn("Unclosed connection {!r}".format(self),
                              ResourceWarning)
                context = {'client_connection': self,
                           'message': 'Unclosed connection'}
                if self._source_traceback is not None:
                    context['source_traceback'] = self._source_traceback
                self._loop.call_exception_handler(context)

    @property
    def loop(self):
        return self._loop

    def close(self):
        if self._transport is not None:
            self._connector._release(
                self._key, self._request, self._transport, self._protocol,
                should_close=True)
            self._transport = None

    def release(self):
        if self._transport is not None:
            self._connector._release(
                self._key, self._request, self._transport, self._protocol,
                should_close=False)
            self._transport = None

    def detach(self):
        self._transport = None

    @property
    def closed(self):
        return self._transport is None


class BaseConnector(object):
    """Base connector class.

    :param conn_timeout: (optional) Connect timeout.
    :param keepalive_timeout: (optional) Keep-alive timeout.
    :param bool force_close: Set to True to force close and do reconnect
        after each request (and between redirects).
    :param loop: Optional event loop.
    """

    _closed = True  # prevent AttributeError in __del__ if ctor was failed
    _source_traceback = None

    def __init__(self, *, conn_timeout=None, keepalive_timeout=30,
                 share_cookies=False, force_close=False, limit=None,
                 loop=None):
        if loop is None:
            loop = asyncio.get_event_loop()

        self._closed = False
        if loop.get_debug():
            self._source_traceback = traceback.extract_stack(sys._getframe(1))

        self._conns = {}
        self._acquired = defaultdict(set)
        self._conn_timeout = conn_timeout
        self._keepalive_timeout = keepalive_timeout
        if share_cookies:
            warnings.warn(
                'Using `share_cookies` is deprecated. '
                'Use Session object instead', DeprecationWarning)
        self._share_cookies = share_cookies
        self._cleanup_handle = None
        self._force_close = force_close
        self._limit = limit
        self._waiters = defaultdict(list)

        self._loop = loop
        self._factory = functools.partial(
            aiohttp.StreamProtocol, loop=loop,
            disconnect_error=ServerDisconnectedError)

        self.cookies = http.cookies.SimpleCookie()

    if PY_341:
        def __del__(self):
            if self._closed:
                return
            if not self._conns:
                return

            self.close()

            warnings.warn("Unclosed connector {!r}".format(self),
                          ResourceWarning)
            context = {'connector': self,
                       'message': 'Unclosed connector'}
            if self._source_traceback is not None:
                context['source_traceback'] = self._source_traceback
            self._loop.call_exception_handler(context)

    @property
    def force_close(self):
        """Ultimately close connection on releasing if True."""
        return self._force_close

    @property
    def limit(self):
        """The limit for simultaneous connections to the same endpoint.

        Endpoints are the same if they are have equal
        (host, port, is_ssl) triple.

        If limit is None the connector has no limit (default).
        """
        return self._limit

    def _cleanup(self):
        """Cleanup unused transports."""
        if self._cleanup_handle:
            self._cleanup_handle.cancel()
            self._cleanup_handle = None

        now = self._loop.time()

        connections = {}
        timeout = self._keepalive_timeout

        for key, conns in self._conns.items():
            alive = []
            for transport, proto, t0 in conns:
                if transport is not None:
                    if proto and not proto.is_connected():
                        transport = None
                    else:
                        delta = t0 + self._keepalive_timeout - now
                        if delta < 0:
                            transport.close()
                            transport = None
                        elif delta < timeout:
                            timeout = delta

                if transport is not None:
                    alive.append((transport, proto, t0))
            if alive:
                connections[key] = alive

        if connections:
            self._cleanup_handle = self._loop.call_at(
                ceil(now + timeout), self._cleanup)

        self._conns = connections

    def _start_cleanup_task(self):
        if self._cleanup_handle is None:
            now = self._loop.time()
            self._cleanup_handle = self._loop.call_at(
                ceil(now + self._keepalive_timeout), self._cleanup)

    def close(self):
        """Close all opened transports."""
        if self._closed:
            return
        self._closed = True

        try:
            if hasattr(self._loop, 'is_closed'):
                if self._loop.is_closed():
                    return

            for key, data in self._conns.items():
                for transport, proto, t0 in data:
                    transport.close()

            for transport in chain(*self._acquired.values()):
                transport.close()

            if self._cleanup_handle:
                self._cleanup_handle.cancel()

        finally:
            self._conns.clear()
            self._acquired.clear()
            self._cleanup_handle = None

    @property
    def closed(self):
        """Is connector closed.

        A readonly property.
        """
        return self._closed

    def update_cookies(self, cookies):
        """Update shared cookies.

        Deprecated, use ClientSession instead.
        """
        if isinstance(cookies, dict):
            cookies = cookies.items()

        for name, value in cookies:
            if PY_343:
                self.cookies[name] = value
            else:
                if isinstance(value, http.cookies.Morsel):
                    # use dict method because SimpleCookie class modifies value
                    dict.__setitem__(self.cookies, name, value)
                else:
                    self.cookies[name] = value

    @asyncio.coroutine
    def connect(self, req):
        """Get from pool or create new connection."""
        key = (req.host, req.port, req.ssl)

        # use short-circuit
        if self._limit is not None:
            while len(self._acquired[key]) >= self._limit:
                fut = asyncio.Future(loop=self._loop)
                self._waiters[key].append(fut)
                yield from fut

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
                raise ClientTimeoutError(
                    'Connection timeout to host %s:%s ssl:%s' % key) from exc
            except OSError as exc:
                raise ClientOSError(
                    'Cannot connect to host %s:%s ssl:%s' % key) from exc

        self._acquired[key].add(transport)
        conn = Connection(self, key, req, transport, proto, self._loop)
        return conn

    def _get(self, key):
        try:
            conns = self._conns[key]
        except KeyError:
            return None, None
        t1 = self._loop.time()
        while conns:
            transport, proto, t0 = conns.pop()
            if transport is not None and proto.is_connected():
                if t1 - t0 > self._keepalive_timeout:
                    transport.close()
                    transport = None
                else:
                    if not conns:
                        # The very last connection was reclaimed: drop the key
                        del self._conns[key]
                    return transport, proto
        # No more connections: drop the key
        del self._conns[key]
        return None, None

    def _release(self, key, req, transport, protocol, *, should_close=False):
        if self._closed:
            # acquired connection is already released on connector closing
            return

        acquired = self._acquired[key]
        try:
            acquired.remove(transport)
        except KeyError:  # pragma: no cover
            # this may be result of undetermenistic order of objects
            # finalization due garbage collection.
            pass
        else:
            if self._limit is not None and len(acquired) < self._limit:
                waiters = self._waiters[key]
                while waiters:
                    waiter = waiters.pop(0)
                    if not waiter.done():
                        waiter.set_result(None)
                        break

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
            transport.close()
        else:
            conns = self._conns.get(key)
            if conns is None:
                conns = self._conns[key] = []
            conns.append((transport, protocol, self._loop.time()))
            reader.unset_parser()

            self._start_cleanup_task()

    @asyncio.coroutine
    def _create_connection(self, req):
        raise NotImplementedError()


_SSL_OP_NO_COMPRESSION = getattr(ssl, "OP_NO_COMPRESSION", 0)
_SSH_HAS_CREATE_DEFAULT_CONTEXT = hasattr(ssl, 'create_default_context')

_marker = object()


class TCPConnector(BaseConnector):
    """TCP connector.

    :param bool verify_ssl: Set to True to check ssl certifications.
    :param bytes fingerprint: Pass the binary md5, sha1, or sha256
        digest of the expected certificate in DER format to verify
        that the certificate the server presents matches. See also
        https://en.wikipedia.org/wiki/Transport_Layer_Security#Certificate_pinning
    :param bool resolve: Set to True to do DNS lookup for host name.
    :param family: socket address family
    :param args: see :class:`BaseConnector`
    :param kwargs: see :class:`BaseConnector`
    """

    def __init__(self, *, verify_ssl=True, fingerprint=None,
                 resolve=_marker, use_dns_cache=_marker,
                 family=socket.AF_INET, ssl_context=None,
                 **kwargs):
        super().__init__(**kwargs)

        if not verify_ssl and ssl_context is not None:
            raise ValueError(
                "Either disable ssl certificate validation by "
                "verify_ssl=False or specify ssl_context, not both.")

        self._verify_ssl = verify_ssl

        if fingerprint:
            digestlen = len(fingerprint)
            hashfunc = HASHFUNC_BY_DIGESTLEN.get(digestlen)
            if not hashfunc:
                raise ValueError('fingerprint has invalid length')
            self._hashfunc = hashfunc
        self._fingerprint = fingerprint

        if resolve is not _marker:
            warnings.warn(("resolve parameter is deprecated, "
                           "use use_dns_cache instead"),
                          DeprecationWarning, stacklevel=2)

        if use_dns_cache is not _marker and resolve is not _marker:
            if use_dns_cache != resolve:
                raise ValueError("use_dns_cache must agree with resolve")
            _use_dns_cache = use_dns_cache
        elif use_dns_cache is not _marker:
            _use_dns_cache = use_dns_cache
        elif resolve is not _marker:
            _use_dns_cache = resolve
        else:
            _use_dns_cache = False

        self._use_dns_cache = _use_dns_cache
        self._cached_hosts = {}
        self._ssl_context = ssl_context
        self._family = family

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
            else:
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
    def use_dns_cache(self):
        """True if local DNS caching is enabled."""
        return self._use_dns_cache

    @property
    def cached_hosts(self):
        """Read-only dict of cached DNS record."""
        return MappingProxyType(self._cached_hosts)

    def clear_dns_cache(self, host=None, port=None):
        """Remove specified host/port or clear all dns local cache."""
        if host is not None and port is not None:
            self._cached_hosts.pop((host, port), None)
        elif host is not None or port is not None:
            raise ValueError("either both host and port "
                             "or none of them are allowed")
        else:
            self._cached_hosts.clear()

    @property
    def resolve(self):
        """Do DNS lookup for host name?"""
        warnings.warn((".resolve property is deprecated, "
                       "use .dns_cache instead"),
                      DeprecationWarning, stacklevel=2)
        return self.use_dns_cache

    @property
    def resolved_hosts(self):
        """The dict of (host, port) -> (ipaddr, port) pairs."""
        warnings.warn((".resolved_hosts property is deprecated, "
                       "use .cached_hosts instead"),
                      DeprecationWarning, stacklevel=2)
        return self.cached_hosts

    def clear_resolved_hosts(self, host=None, port=None):
        """Remove specified host/port or clear all resolve cache."""
        warnings.warn((".clear_resolved_hosts() is deprecated, "
                       "use .clear_dns_cache() instead"),
                      DeprecationWarning, stacklevel=2)
        if host is not None and port is not None:
            self.clear_dns_cache(host, port)
        else:
            self.clear_dns_cache()

    @asyncio.coroutine
    def _resolve_host(self, host, port):
        if self._use_dns_cache:
            key = (host, port)

            if key not in self._cached_hosts:
                infos = yield from self._loop.getaddrinfo(
                    host, port, type=socket.SOCK_STREAM, family=self._family)

                hosts = []
                for family, _, proto, _, address in infos:
                    hosts.append(
                        {'hostname': host,
                         'host': address[0], 'port': address[1],
                         'family': family, 'proto': proto,
                         'flags': socket.AI_NUMERICHOST})
                self._cached_hosts[key] = hosts

            return list(self._cached_hosts[key])
        else:
            return [{'hostname': host, 'host': host, 'port': port,
                     'family': self._family, 'proto': 0, 'flags': 0}]

    @asyncio.coroutine
    def _create_connection(self, req):
        """Create connection.

        Has same keyword arguments as BaseEventLoop.create_connection.
        """
        if req.ssl:
            sslcontext = self.ssl_context
        else:
            sslcontext = None

        hosts = yield from self._resolve_host(req.host, req.port)
        exc = None

        for hinfo in hosts:
            try:
                host = hinfo['host']
                port = hinfo['port']
                transp, proto = yield from self._loop.create_connection(
                    self._factory, host, port,
                    ssl=sslcontext, family=hinfo['family'],
                    proto=hinfo['proto'], flags=hinfo['flags'],
                    server_hostname=hinfo['hostname'] if sslcontext else None)
                has_cert = transp.get_extra_info('sslcontext')
                if has_cert and self._fingerprint:
                    sock = transp.get_extra_info('socket')
                    # gives DER-encoded cert as a sequence of bytes (or None)
                    cert = sock.getpeercert(binary_form=True)
                    assert cert
                    got = self._hashfunc(cert).digest()
                    expected = self._fingerprint
                    if got != expected:
                        transp.close()
                        raise FingerprintMismatch(expected, got, host, port)
                return transp, proto
            except OSError as e:
                exc = e
        else:
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
    >>> session = ClientSession(connector=conn)
    >>> resp = yield from session.get('http://python.org')

    """

    def __init__(self, proxy, *, proxy_auth=None, force_close=True,
                 **kwargs):
        super().__init__(force_close=force_close, **kwargs)
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

    @property
    def proxy_auth(self):
        """Proxy auth info.

        Should be BasicAuth instance.
        """
        return self._proxy_auth

    @asyncio.coroutine
    def _create_connection(self, req):
        proxy_req = ClientRequest(
            hdrs.METH_GET, self._proxy,
            headers={hdrs.HOST: req.host},
            auth=self._proxy_auth,
            loop=self._loop)
        try:
            transport, proto = yield from super()._create_connection(proxy_req)
        except OSError as exc:
            raise ProxyConnectionError(*exc.args) from exc

        if not req.ssl:
            req.path = '{scheme}://{host}{path}'.format(scheme=req.scheme,
                                                        host=req.netloc,
                                                        path=req.path)
        if hdrs.AUTHORIZATION in proxy_req.headers:
            auth = proxy_req.headers[hdrs.AUTHORIZATION]
            del proxy_req.headers[hdrs.AUTHORIZATION]
            req.headers[hdrs.PROXY_AUTHORIZATION] = auth

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
            proxy_req.method = hdrs.METH_CONNECT
            proxy_req.path = '{}:{}'.format(req.host, req.port)
            key = (req.host, req.port, req.ssl)
            conn = Connection(self, key, proxy_req,
                              transport, proto, self._loop)
            self._acquired[key].add(conn._transport)
            proxy_resp = proxy_req.send(conn.writer, conn.reader)
            try:
                resp = yield from proxy_resp.start(conn, True)
            except:
                proxy_resp.close()
                conn.close()
                raise
            else:
                conn.detach()
                if resp.status != 200:
                    raise HttpProxyError(code=resp.status, message=resp.reason)
                rawsock = transport.get_extra_info('socket', default=None)
                if rawsock is None:
                    raise RuntimeError(
                        "Transport does not expose socket instance")
                transport.pause_reading()
                transport, proto = yield from self._loop.create_connection(
                    self._factory, ssl=self.ssl_context, sock=rawsock,
                    server_hostname=req.host)

        return transport, proto


class UnixConnector(BaseConnector):
    """Unix socket connector.

    :param str path: Unix socket path.
    :param args: see :class:`BaseConnector`
    :param kwargs: see :class:`BaseConnector`

    Usage:

    >>> conn = UnixConnector(path='/path/to/socket')
    >>> session = ClientSession(connector=conn)
    >>> resp = yield from session.get('http://python.org')

    """

    def __init__(self, path, **kwargs):
        super().__init__(**kwargs)
        self._path = path

    @property
    def path(self):
        """Path to unix socket."""
        return self._path

    @asyncio.coroutine
    def _create_connection(self, req):
        return (yield from self._loop.create_unix_connection(
            self._factory, self._path))
