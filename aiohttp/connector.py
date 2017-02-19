import asyncio
import functools
import ssl
import sys
import traceback
import warnings
from collections import defaultdict
from hashlib import md5, sha1, sha256
from types import MappingProxyType

from . import hdrs, helpers
from .client_exceptions import (ClientConnectorError, ClientHttpProxyError,
                                ClientProxyConnectionError,
                                ServerFingerprintMismatch, ServerTimeoutError)
from .client_proto import HttpClientProtocol
from .client_reqrep import ClientRequest
from .helpers import SimpleCookie, is_ip_address, sentinel
from .resolver import DefaultResolver

__all__ = ('BaseConnector', 'TCPConnector', 'UnixConnector')

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
        self.protocol = protocol
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
        if self._transport is not None:
            self._connector._release_acquired(self._transport)
        self._transport = None

    @property
    def closed(self):
        return self._transport is None


class _TransportPlaceholder:
    """ placeholder for BaseConnector.connect function """

    def close(self):
        pass


class BaseConnector(object):
    """Base connector class.

    conn_timeout - (optional) Connect timeout.
    keepalive_timeout - (optional) Keep-alive timeout.
    force_close - Set to True to force close and do reconnect
        after each request (and between redirects).
    limit - The total number of simultaneous connections.
    limit_per_host - Number of simultaneous connections to one host.
    disable_cleanup_closed - Disable clean-up closed ssl transports.
    loop - Optional event loop.
    """

    _closed = True  # prevent AttributeError in __del__ if ctor was failed
    _source_traceback = None

    # abort transport after 2 seconds (cleanup broken connections)
    _cleanup_closed_period = 2.0

    def __init__(self, *, conn_timeout=None, keepalive_timeout=sentinel,
                 force_close=False, limit=100, limit_per_host=0,
                 time_service=None, disable_cleanup_closed=False, loop=None):

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
        self._limit = limit
        self._limit_per_host = limit_per_host
        self._acquired = set()
        self._acquired_per_host = defaultdict(set)
        self._conn_timeout = conn_timeout
        self._keepalive_timeout = keepalive_timeout
        self._force_close = force_close
        self._waiters = defaultdict(list)

        if time_service is not None:
            self._time_service_owner = False
            self._time_service = time_service
        else:
            self._time_service_owner = True
            self._time_service = helpers.TimeService(loop)

        self._loop = loop
        self._factory = functools.partial(HttpClientProtocol, loop=loop)

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
        """The total number for simultaneous connections.

        If limit is 0 the connector has no limit.
        The default limit size is 100.
        """
        return self._limit

    @property
    def limit_per_host(self):
        """The limit_per_host for simultaneous connections
        to the same endpoint.

        Endpoints are the same if they are have equal
        (host, port, is_ssl) triple.

        """
        return self._limit_per_host

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

            for data in self._conns.values():
                for transport, proto, t0 in data:
                    transport.close()

            for transport in self._acquired:
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
            self._waiters.clear()
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

        if self._limit:
            # total calc available connections
            available = self._limit - len(self._waiters) - len(self._acquired)

            # check limit per host
            if (self._limit_per_host and available > 0 and
                    key in self._acquired_per_host):
                available = self._limit_per_host - len(
                    self._acquired_per_host.get(key))

        elif self._limit_per_host and key in self._acquired_per_host:
            # check limit per host
            available = self._limit_per_host - len(
                self._acquired_per_host.get(key))
        else:
            available = 1

        # Wait if there are no available connections.
        if available <= 0:
            fut = helpers.create_future(self._loop)

            # This connection will now count towards the limit.
            waiters = self._waiters[key]
            waiters.append(fut)
            yield from fut
            waiters.remove(fut)
            if not waiters:
                del self._waiters[key]

        transport, proto = self._get(key)
        if transport is None:
            placeholder = _TransportPlaceholder()
            self._acquired.add(placeholder)
            self._acquired_per_host[key].add(placeholder)
            try:
                with self._time_service.timeout(self._conn_timeout):
                    transport, proto = yield from self._create_connection(req)
            except asyncio.TimeoutError as exc:
                raise ServerTimeoutError(
                    'Connection timeout to host {0[0]}:{0[1]} ssl:{0[2]}'
                    .format(key)) from exc
            except OSError as exc:
                raise ClientConnectorError(
                    exc.errno,
                    'Cannot connect to host {0[0]}:{0[1]} ssl:{0[2]} [{1}]'
                    .format(key, exc.strerror)) from exc
            finally:
                self._acquired.remove(placeholder)
                self._acquired_per_host[key].remove(placeholder)

        self._acquired.add(transport)
        self._acquired_per_host[key].add(transport)
        return Connection(self, key, req, transport, proto, self._loop)

    def _get(self, key):
        try:
            conns = self._conns[key]
        except KeyError:
            return None, None

        t1 = self._time_service.loop_time()
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

    def _release_waiter(self):
        # always release only one waiter

        if self._limit:
            # if we have limit and we have available
            if self._limit - len(self._acquired) > 0:
                for key, waiters in self._waiters.items():
                    if waiters:
                        if not waiters[0].done():
                            waiters[0].set_result(None)
                        break

        elif self._limit_per_host:
            # if we have dont have limit but have limit per host
            # then release first available
            for key, waiters in self._waiters.items():
                if waiters:
                    if not waiters[0].done():
                        waiters[0].set_result(None)
                    break

    def _release_acquired(self, key, transport):
        if self._closed:
            # acquired connection is already released on connector closing
            return

        try:
            self._acquired.remove(transport)
            self._acquired_per_host[key].remove(transport)
            if not self._acquired_per_host[key]:
                del self._acquired_per_host[key]
        except KeyError:  # pragma: no cover
            # this may be result of undetermenistic order of objects
            # finalization due garbage collection.
            pass
        else:
            self._release_waiter()

    def _release(self, key, req, transport, protocol, *, should_close=False):
        if self._closed:
            # acquired connection is already released on connector closing
            return

        self._release_acquired(key, transport)

        resp = req.response

        if not should_close:
            if self._force_close:
                should_close = True
            elif resp is not None:
                should_close = resp._should_close

        if should_close or protocol.should_close:
            transport.close()

            if key[-1] and not self._cleanup_closed_disabled:
                self._cleanup_closed_transports.append(transport)
        else:
            conns = self._conns.get(key)
            if conns is None:
                conns = self._conns[key] = []
            conns.append((transport, protocol, self._time_service.loop_time()))
            # reader.unset_parser()

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
    limit - The total number of simultaneous connections.
    limit_per_host - Number of simultaneous connections to one host.
    loop - Optional event loop.
    """

    def __init__(self, *, verify_ssl=True, fingerprint=None,
                 resolve=sentinel, use_dns_cache=True,
                 family=0, ssl_context=None, local_addr=None,
                 resolver=None, time_service=None,
                 conn_timeout=None, keepalive_timeout=sentinel,
                 force_close=False, limit=100, limit_per_host=0, loop=None):
        super().__init__(time_service=time_service, conn_timeout=conn_timeout,
                         keepalive_timeout=keepalive_timeout,
                         force_close=force_close,
                         limit=limit, limit_per_host=limit_per_host, loop=loop)

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

        if resolver is None:
            resolver = DefaultResolver(loop=self._loop)
        self._resolver = resolver

        self._use_dns_cache = use_dns_cache
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
                        raise ServerFingerprintMismatch(
                            expected, got, host, port)
                return transp, proto
            except OSError as e:
                exc = e
        else:
            raise ClientConnectorError(
                exc.errno,
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
            raise ClientProxyConnectionError(*exc.args) from exc

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
            proxy_resp = proxy_req.send(conn)
            try:
                resp = yield from proxy_resp.start(conn, True)
            except:
                proxy_resp.close()
                conn.close()
                raise
            else:
                conn._transport = None
                try:
                    if resp.status != 200:
                        raise ClientHttpProxyError(code=resp.status,
                                                   message=resp.reason,
                                                   headers=resp.headers)
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


class UnixConnector(BaseConnector):
    """Unix socket connector.

    path - Unix socket path.
    conn_timeout - (optional) Connect timeout.
    keepalive_timeout - (optional) Keep-alive timeout.
    force_close - Set to True to force close and do reconnect
        after each request (and between redirects).
    limit - The total number of simultaneous connections.
    limit_per_host - Number of simultaneous connections to one host.
    loop - Optional event loop.

    Usage:

    >>> conn = UnixConnector(path='/path/to/socket')
    >>> session = ClientSession(connector=conn)
    >>> resp = yield from session.get('http://python.org')

    """

    def __init__(self, path, force_close=False,
                 time_service=None,
                 conn_timeout=None, keepalive_timeout=sentinel,
                 limit=100, limit_per_host=0, loop=None):
        super().__init__(force_close=force_close,
                         time_service=time_service,
                         conn_timeout=conn_timeout,
                         keepalive_timeout=keepalive_timeout,
                         limit=limit, limit_per_host=limit_per_host, loop=loop)
        self._path = path

    @property
    def path(self):
        """Path to unix socket."""
        return self._path

    @asyncio.coroutine
    def _create_connection(self, req):
        return (yield from self._loop.create_unix_connection(
            self._factory, self._path))
