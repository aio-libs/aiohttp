import asyncio
import functools
import ssl
import sys
import traceback
import warnings
from collections import defaultdict
from hashlib import md5, sha1, sha256
from itertools import chain
from types import MappingProxyType

from yarl import URL

import aiohttp

from . import hdrs, helpers
from .client import ClientRequest
from .errors import (ClientOSError, ClientTimeoutError, FingerprintMismatch,
                     HttpProxyError, ProxyConnectionError,
                     ServerDisconnectedError)
from .helpers import SimpleCookie, is_ip_address, sentinel
from .resolver import DefaultResolver

__all__ = ('BaseConnector', 'TCPConnector', 'ProxyConnector', 'UnixConnector')

HASHFUNC_BY_DIGESTLEN = {
    16: md5,
    20: sha1,
    32: sha256,
}


class Connection:

    _source_traceback = None
    _transport = None

    def __init__(self, connector, key, request, transport, protocol, loop):
        self._key = key
        self._connector = connector
        self._request = request
        self._transport = transport
        self._protocol = protocol
        self._loop = loop
        self._callbacks = []
        self.reader = protocol.reader
        self.writer = protocol.writer

        if loop.get_debug():
            self._source_traceback = traceback.extract_stack(sys._getframe(1))

    def __repr__(self):
        return 'Connection<{}>'.format(self._key)

    def __del__(self, _warnings=warnings):
        if self._transport is not None:
            _warnings.warn('Unclosed connection {!r}'.format(self),
                           ResourceWarning)
            if self._loop.is_closed():
                return

            self._connector._release(
                self._key, self._request, self._transport, self._protocol,
                should_close=True)

            context = {'client_connection': self,
                       'message': 'Unclosed connection'}
            if self._source_traceback is not None:
                context['source_traceback'] = self._source_traceback
            self._loop.call_exception_handler(context)

    def add_callback(self, callback):
        if callback is not None:
            self._callbacks.append(callback)

    def release_callbacks(self):
        callbacks, self._callbacks = self._callbacks[:], []

        for cb in callbacks:
            try:
                cb()
            except:
                pass

    @property
    def loop(self):
        return self._loop

    def close(self):
        self.release_callbacks()

        if self._transport is not None:
            self._connector._release(
                self._key, self._request, self._transport, self._protocol,
                should_close=True)
            self._transport = None

    def release(self):
        self.release_callbacks()

        if self._transport is not None:
            self._connector._release(
                self._key, self._request, self._transport, self._protocol,
                should_close=False)
            self._transport = None

    def detach(self):
        self.release_callbacks()

        if self._transport is not None:
            self._connector._release_acquired(self._key, self._transport)
        self._transport = None

    @property
    def closed(self):
        return self._transport is None


class BaseConnector(object):
    """Base connector class.

    conn_timeout - (optional) Connect timeout.
    keepalive_timeout - (optional) Keep-alive timeout.
    force_close - Set to True to force close and do reconnect
        after each request (and between redirects).
    limit - The limit of simultaneous connections to the same endpoint.
    disable_cleanup_closed - Disable clean-up closed ssl transports.
    loop - Optional event loop.
    """

    _closed = True  # prevent AttributeError in __del__ if ctor was failed
    _source_traceback = None

    # abort transport after 2 seconds (cleanup broken connections)
    _cleanup_closed_period = 2.0

    def __init__(self, *, conn_timeout=None, keepalive_timeout=sentinel,
                 force_close=False, limit=20, time_service=None,
                 disable_cleanup_closed=False, loop=None):

        if force_close:
            if keepalive_timeout is not None and \
               keepalive_timeout is not sentinel:
                raise ValueError('keepalive_timeout cannot '
                                 'be set if force_close is True')
        else:
            if keepalive_timeout is sentinel:
                keepalive_timeout = 15.0

        if loop is None:
            loop = asyncio.get_event_loop()

        self._closed = False
        if loop.get_debug():
            self._source_traceback = traceback.extract_stack(sys._getframe(1))

        self._conns = {}
        self._acquired = defaultdict(set)
        self._conn_timeout = conn_timeout
        self._keepalive_timeout = keepalive_timeout
        self._force_close = force_close
        self._limit = limit
        self._waiters = defaultdict(list)

        if time_service is not None:
            self._time_service_owner = False
            self._time_service = time_service
        else:
            self._time_service_owner = True
            self._time_service = helpers.TimeService(loop)

        self._loop = loop
        self._factory = functools.partial(
            aiohttp.StreamProtocol, loop=loop,
            disconnect_error=ServerDisconnectedError)

        self.cookies = SimpleCookie()

        # start keep-alive connection cleanup task
        self._cleanup_handle = None
        if (keepalive_timeout is not sentinel and
                keepalive_timeout is not None):
            self._cleanup()

        # start cleanup closed transports task
        self._cleanup_closed_handle = None
        self._cleanup_closed_disabled = disable_cleanup_closed
        self._cleanup_closed_transports = []
        self._cleanup_closed()

    def __del__(self, _warnings=warnings):
        if self._closed:
            return
        if not self._conns:
            return

        conns = [repr(c) for c in self._conns.values()]

        self.close()

        _warnings.warn("Unclosed connector {!r}".format(self),
                       ResourceWarning)
        context = {'connector': self,
                   'connections': conns,
                   'message': 'Unclosed connector'}
        if self._source_traceback is not None:
            context['source_traceback'] = self._source_traceback
        self._loop.call_exception_handler(context)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    @property
    def conn_timeout(self):
        return self._conn_timeout

    @property
    def force_close(self):
        """Ultimately close connection on releasing if True."""
        return self._force_close

    @property
    def limit(self):
        """The limit for simultaneous connections to the same endpoint.

        Endpoints are the same if they are have equal
        (host, port, is_ssl) triple.

        If limit is None the connector has no limit.
        The default limit size is 20.
        """
        return self._limit

    def _cleanup(self):
        """Cleanup unused transports."""
        if self._cleanup_handle:
            self._cleanup_handle.cancel()

        now = self._time_service.loop_time()

        if self._conns:
            connections = {}
            deadline = now - self._keepalive_timeout
            for key, conns in self._conns.items():
                alive = []
                for transport, proto, use_time in conns:
                    if transport is not None:
                        if proto.is_connected():
                            if use_time - deadline < 0:
                                transport.close()
                                if (key[-1] and
                                        not self._cleanup_closed_disabled):
                                    self._cleanup_closed_transports.append(
                                        transport)
                            else:
                                alive.append((transport, proto, use_time))

                if alive:
                    connections[key] = alive

            self._conns = connections

        self._cleanup_handle = self._time_service.call_later(
            self._keepalive_timeout / 2.0, self._cleanup)

    def _cleanup_closed(self):
        """Double confirmation for transport close.
        Some broken ssl servers may leave socket open without proper close.
        """
        if self._cleanup_closed_handle:
            self._cleanup_closed_handle.cancel()

        for transport in self._cleanup_closed_transports:
            transport.abort()

        self._cleanup_closed_transports = []

        if not self._cleanup_closed_disabled:
            self._cleanup_closed_handle = self._time_service.call_later(
                self._cleanup_closed_period, self._cleanup_closed)

    def close(self):
        """Close all opened transports."""
        ret = helpers.create_future(self._loop)
        ret.set_result(None)
        if self._closed:
            return ret
        self._closed = True

        try:
            if self._loop.is_closed():
                return ret

            if self._time_service_owner:
                self._time_service.close()

            for key, data in self._conns.items():
                for transport, proto, t0 in data:
                    transport.close()

            for transport in chain(*self._acquired.values()):
                transport.close()

            # cacnel cleanup task
            if self._cleanup_handle:
                self._cleanup_handle.cancel()

            # cacnel cleanup close task
            if self._cleanup_closed_handle:
                self._cleanup_closed_handle.cancel()

            for transport in self._cleanup_closed_transports:
                transport.abort()

        finally:
            self._conns.clear()
            self._acquired.clear()
            self._cleanup_handle = None
            self._cleanup_closed_transports.clear()
            self._cleanup_closed_handle = None

        return ret

    @property
    def closed(self):
        """Is connector closed.

        A readonly property.
        """
        return self._closed

    @asyncio.coroutine
    def connect(self, req):
        """Get from pool or create new connection."""
        key = (req.host, req.port, req.ssl)

        limit = self._limit
        if limit is not None:
            fut = helpers.create_future(self._loop)
            waiters = self._waiters[key]

            # The limit defines the maximum number of concurrent connections
            # for a key. Waiters must be counted against the limit, even before
            # the underlying connection is created.
            available = limit - len(waiters) - len(self._acquired[key])

            # Don't wait if there are connections available.
            if available > 0:
                fut.set_result(None)

            # This connection will now count towards the limit.
            waiters.append(fut)

        try:
            if limit is not None:
                yield from fut

            transport, proto = self._get(key)
            if transport is None:
                try:
                    if self._conn_timeout:
                        transport, proto = yield from asyncio.wait_for(
                            self._create_connection(req),
                            self._conn_timeout, loop=self._loop)
                    else:
                        transport, proto = \
                            yield from self._create_connection(req)

                except asyncio.TimeoutError as exc:
                    raise ClientTimeoutError(
                        'Connection timeout to host {0[0]}:{0[1]} ssl:{0[2]}'
                        .format(key)) from exc
                except OSError as exc:
                    raise ClientOSError(
                        exc.errno,
                        'Cannot connect to host {0[0]}:{0[1]} ssl:{0[2]} [{1}]'
                        .format(key, exc.strerror)) from exc
        except:
            self._release_waiter(key)
            raise

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
                    if key[-1] and not self._cleanup_closed_disabled:
                        self._cleanup_closed_transports.append(transport)
                else:
                    if not conns:
                        # The very last connection was reclaimed: drop the key
                        del self._conns[key]
                    return transport, proto

        # No more connections: drop the key
        del self._conns[key]
        return None, None

    def _release_waiter(self, key):
        waiters = self._waiters[key]
        while waiters:
            waiter = waiters.pop(0)
            if not waiter.done():
                waiter.set_result(None)
                break

    def _release_acquired(self, key, transport):
        if self._closed:
            # acquired connection is already released on connector closing
            return

        acquired = self._acquired[key]
        try:
            acquired.remove(transport)
        except KeyError:  # pragma: no cover
            # this may be result of undetermenistic order of objects
            # finalization due garbage collection.
            return None

        return acquired

    def _release(self, key, req, transport, protocol, *, should_close=False):
        if self._closed:
            # acquired connection is already released on connector closing
            return

        acquired = self._release_acquired(key, transport)

        if self._limit is not None and acquired is not None:
            if len(acquired) < self._limit:
                self._release_waiter(key)

        resp = req.response

        if not should_close:
            if self._force_close:
                should_close = True
            elif resp is not None:
                should_close = resp._should_close

        reader = protocol.reader
        if should_close or (reader.output and not reader.output.at_eof()):
            transport.close()

            if key[-1] and not self._cleanup_closed_disabled:
                self._cleanup_closed_transports.append(transport)
        else:
            conns = self._conns.get(key)
            if conns is None:
                conns = self._conns[key] = []
            conns.append((transport, protocol, self._loop.time()))
            reader.unset_parser()

    @asyncio.coroutine
    def _create_connection(self, req):
        raise NotImplementedError()


_SSL_OP_NO_COMPRESSION = getattr(ssl, "OP_NO_COMPRESSION", 0)


class TCPConnector(BaseConnector):
    """TCP connector.

    verify_ssl - Set to True to check ssl certifications.
    fingerprint - Pass the binary md5, sha1, or sha256
        digest of the expected certificate in DER format to verify
        that the certificate the server presents matches. See also
        https://en.wikipedia.org/wiki/Transport_Layer_Security#Certificate_pinning
    resolve - (Deprecated) Set to True to do DNS lookup for
        host name.
    resolver - Enable DNS lookups and use this
        resolver
    use_dns_cache - Use memory cache for DNS lookups.
    family - socket address family
    local_addr - local tuple of (host, port) to bind socket to

    conn_timeout - (optional) Connect timeout.
    keepalive_timeout - (optional) Keep-alive timeout.
    force_close - Set to True to force close and do reconnect
        after each request (and between redirects).
    limit - The limit of simultaneous connections to the same endpoint.
    loop - Optional event loop.
    """

    def __init__(self, *, verify_ssl=True, fingerprint=None,
                 resolve=sentinel, use_dns_cache=sentinel,
                 family=0, ssl_context=None, local_addr=None, resolver=None,
                 conn_timeout=None, keepalive_timeout=sentinel,
                 force_close=False, limit=20,
                 loop=None):
        super().__init__(conn_timeout=conn_timeout,
                         keepalive_timeout=keepalive_timeout,
                         force_close=force_close, limit=limit, loop=loop)

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
            elif hashfunc is md5 or hashfunc is sha1:
                warnings.simplefilter('always')
                warnings.warn('md5 and sha1 are insecure and deprecated. '
                              'Use sha256.',
                              DeprecationWarning, stacklevel=2)
            self._hashfunc = hashfunc
        self._fingerprint = fingerprint

        if resolve is not sentinel:
            warnings.warn(("resolve parameter is deprecated, "
                           "use use_dns_cache instead"),
                          DeprecationWarning, stacklevel=2)

        if use_dns_cache is not sentinel and resolve is not sentinel:
            if use_dns_cache != resolve:
                raise ValueError("use_dns_cache must agree with resolve")
            _use_dns_cache = use_dns_cache
        elif use_dns_cache is not sentinel:
            _use_dns_cache = use_dns_cache
        elif resolve is not sentinel:
            _use_dns_cache = resolve
        else:
            _use_dns_cache = True

        if resolver is None:
            resolver = DefaultResolver(loop=self._loop)
        self._resolver = resolver

        self._use_dns_cache = _use_dns_cache
        self._cached_hosts = {}
        self._ssl_context = ssl_context
        self._family = family
        self._local_addr = local_addr

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
            else:
                sslcontext = ssl.create_default_context()
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
        if is_ip_address(host):
            return [{'hostname': host, 'host': host, 'port': port,
                     'family': self._family, 'proto': 0, 'flags': 0}]

        if self._use_dns_cache:
            key = (host, port)

            if key not in self._cached_hosts:
                self._cached_hosts[key] = yield from \
                    self._resolver.resolve(host, port, family=self._family)

            return self._cached_hosts[key]
        else:
            res = yield from self._resolver.resolve(
                host, port, family=self._family)
            return res

    @asyncio.coroutine
    def _create_connection(self, req):
        """Create connection.

        Has same keyword arguments as BaseEventLoop.create_connection.
        """
        if req.proxy:
            transport, proto = yield from self._create_proxy_connection(req)
        else:
            transport, proto = yield from self._create_direct_connection(req)

        return transport, proto

    @asyncio.coroutine
    def _create_direct_connection(self, req):
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
                    server_hostname=hinfo['hostname'] if sslcontext else None,
                    local_addr=self._local_addr)
                has_cert = transp.get_extra_info('sslcontext')
                if has_cert and self._fingerprint:
                    sock = transp.get_extra_info('socket')
                    if not hasattr(sock, 'getpeercert'):
                        # Workaround for asyncio 3.5.0
                        # Starting from 3.5.1 version
                        # there is 'ssl_object' extra info in transport
                        sock = transp._ssl_protocol._sslpipe.ssl_object
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
            raise ClientOSError(exc.errno,
                                'Can not connect to %s:%s [%s]' %
                                (req.host, req.port, exc.strerror)) from exc

    @asyncio.coroutine
    def _create_proxy_connection(self, req):
        proxy_req = ClientRequest(
            hdrs.METH_GET, req.proxy,
            headers={hdrs.HOST: req.headers[hdrs.HOST]},
            auth=req.proxy_auth,
            loop=self._loop)
        try:
            # create connection to proxy server
            transport, proto = yield from self._create_direct_connection(
                proxy_req)
        except OSError as exc:
            raise ProxyConnectionError(*exc.args) from exc

        if hdrs.AUTHORIZATION in proxy_req.headers:
            auth = proxy_req.headers[hdrs.AUTHORIZATION]
            del proxy_req.headers[hdrs.AUTHORIZATION]
            if not req.ssl:
                req.headers[hdrs.PROXY_AUTHORIZATION] = auth
            else:
                proxy_req.headers[hdrs.PROXY_AUTHORIZATION] = auth

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
            proxy_req.url = req.url
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
                try:
                    if resp.status != 200:
                        raise HttpProxyError(code=resp.status,
                                             message=resp.reason)
                    rawsock = transport.get_extra_info('socket', default=None)
                    if rawsock is None:
                        raise RuntimeError(
                            "Transport does not expose socket instance")
                    # Duplicate the socket, so now we can close proxy transport
                    rawsock = rawsock.dup()
                finally:
                    transport.close()

                transport, proto = yield from self._loop.create_connection(
                    self._factory, ssl=self.ssl_context, sock=rawsock,
                    server_hostname=req.host)
            finally:
                proxy_resp.close()

        return transport, proto


class ProxyConnector(TCPConnector):
    """Http Proxy connector.
    Deprecated, use ClientSession.request with proxy parameters.
    Is still here for backward compatibility.

    proxy - Proxy URL address. Only HTTP proxy supported.
    proxy_auth - (optional) Proxy HTTP Basic Auth
    proxy_auth - aiohttp.helpers.BasicAuth
    conn_timeout - (optional) Connect timeout.
    keepalive_timeout - (optional) Keep-alive timeout.
    force_close - Set to True to force close and do reconnect
        after each request (and between redirects).
    limit - The limit of simultaneous connections to the same endpoint.
    loop - Optional event loop.

    Usage:

    >>> conn = ProxyConnector(proxy="http://some.proxy.com")
    >>> session = ClientSession(connector=conn)
    >>> resp = yield from session.get('http://python.org')

    """

    def __init__(self, proxy, *, proxy_auth=None, force_close=True,
                 conn_timeout=None, keepalive_timeout=sentinel,
                 limit=20, loop=None):
        warnings.warn("ProxyConnector is deprecated, use "
                      "client.get(url, proxy=proxy_url) instead",
                      DeprecationWarning)
        super().__init__(force_close=force_close,
                         conn_timeout=conn_timeout,
                         keepalive_timeout=keepalive_timeout,
                         limit=limit, loop=loop)
        proxy = URL(proxy)
        self._proxy = proxy
        self._proxy_auth = proxy_auth

    @property
    def proxy(self):
        return self._proxy

    @property
    def proxy_auth(self):
        return self._proxy_auth

    @asyncio.coroutine
    def _create_connection(self, req):
        """
        Use TCPConnector _create_connection, to emulate old ProxyConnector.
        """
        req.update_proxy(self._proxy, self._proxy_auth)
        transport, proto = yield from super()._create_connection(req)

        return transport, proto


class UnixConnector(BaseConnector):
    """Unix socket connector.

    path - Unix socket path.
    conn_timeout - (optional) Connect timeout.
    keepalive_timeout - (optional) Keep-alive timeout.
    force_close - Set to True to force close and do reconnect
        after each request (and between redirects).
    limit - The limit of simultaneous connections to the same endpoint.
    loop - Optional event loop.

    Usage:

    >>> conn = UnixConnector(path='/path/to/socket')
    >>> session = ClientSession(connector=conn)
    >>> resp = yield from session.get('http://python.org')

    """

    def __init__(self, path, force_close=False, conn_timeout=None,
                 keepalive_timeout=sentinel, limit=20, loop=None):
        super().__init__(force_close=force_close,
                         conn_timeout=conn_timeout,
                         keepalive_timeout=keepalive_timeout,
                         limit=limit, loop=loop)
        self._path = path

    @property
    def path(self):
        """Path to unix socket."""
        return self._path

    @asyncio.coroutine
    def _create_connection(self, req):
        return (yield from self._loop.create_unix_connection(
            self._factory, self._path))
