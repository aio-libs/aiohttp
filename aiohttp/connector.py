import asyncio
import functools
import sys
import traceback
import warnings
from collections import defaultdict
from contextlib import suppress
from hashlib import md5, sha1, sha256
from http.cookies import SimpleCookie
from itertools import cycle, islice
from time import monotonic
from types import MappingProxyType

from . import hdrs, helpers
from .client_exceptions import (ClientConnectionError,
                                ClientConnectorCertificateError,
                                ClientConnectorError, ClientConnectorSSLError,
                                ClientHttpProxyError,
                                ClientProxyConnectionError,
                                ClientSocksProxyError,
                                ServerFingerprintMismatch, certificate_errors,
                                ssl_errors)
from .client_proto import ResponseHandler
from .client_reqrep import ClientRequest
from .helpers import is_ip_address, noop, sentinel
from .locks import EventResultOrError
from .resolver import DefaultResolver


try:
    import aiosocks
except ImportError:  # pragma: no cover
    aiosocks = None

try:
    import ssl
except ImportError:  # pragma: no cover
    ssl = None


__all__ = ('BaseConnector', 'TCPConnector', 'UnixConnector')

HASHFUNC_BY_DIGESTLEN = {
    16: md5,
    20: sha1,
    32: sha256,
}


class Connection:

    _source_traceback = None
    _transport = None

    def __init__(self, connector, key, protocol, loop):
        self._key = key
        self._connector = connector
        self._loop = loop
        self._protocol = protocol
        self._callbacks = []

        if loop.get_debug():
            self._source_traceback = traceback.extract_stack(sys._getframe(1))

    def __repr__(self):
        return 'Connection<{}>'.format(self._key)

    def __del__(self, _warnings=warnings):
        if self._protocol is not None:
            _warnings.warn('Unclosed connection {!r}'.format(self),
                           ResourceWarning)
            if self._loop.is_closed():
                return

            self._connector._release(
                self._key, self._protocol, should_close=True)

            context = {'client_connection': self,
                       'message': 'Unclosed connection'}
            if self._source_traceback is not None:
                context['source_traceback'] = self._source_traceback
            self._loop.call_exception_handler(context)

    @property
    def loop(self):
        return self._loop

    @property
    def transport(self):
        return self._protocol.transport

    @property
    def protocol(self):
        return self._protocol

    @property
    def writer(self):
        return self._protocol.writer

    def add_callback(self, callback):
        if callback is not None:
            self._callbacks.append(callback)

    def _notify_release(self):
        callbacks, self._callbacks = self._callbacks[:], []

        for cb in callbacks:
            with suppress(Exception):
                cb()

    def close(self):
        self._notify_release()

        if self._protocol is not None:
            self._connector._release(
                self._key, self._protocol, should_close=True)
            self._protocol = None

    def release(self):
        self._notify_release()

        if self._protocol is not None:
            self._connector._release(
                self._key, self._protocol,
                should_close=self._protocol.should_close)
            self._protocol = None

    def detach(self):
        self._notify_release()

        if self._protocol is not None:
            self._connector._release_acquired(self._protocol)
        self._protocol = None

    @property
    def closed(self):
        return self._protocol is None or not self._protocol.is_connected()


class _TransportPlaceholder:
    """ placeholder for BaseConnector.connect function """

    def close(self):
        pass


class BaseConnector:
    """Base connector class.

    keepalive_timeout - (optional) Keep-alive timeout.
    force_close - Set to True to force close and do reconnect
        after each request (and between redirects).
    limit - The total number of simultaneous connections.
    limit_per_host - Number of simultaneous connections to one host.
    enable_cleanup_closed - Enables clean-up closed ssl transports.
                            Disabled by default.
    loop - Optional event loop.
    """

    _closed = True  # prevent AttributeError in __del__ if ctor was failed
    _source_traceback = None

    # abort transport after 2 seconds (cleanup broken connections)
    _cleanup_closed_period = 2.0

    def __init__(self, *, keepalive_timeout=sentinel,
                 force_close=False, limit=100, limit_per_host=0,
                 enable_cleanup_closed=False, loop=None):

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
        self._keepalive_timeout = keepalive_timeout
        self._force_close = force_close
        self._waiters = defaultdict(list)

        self._loop = loop
        self._factory = functools.partial(ResponseHandler, loop=loop)

        self.cookies = SimpleCookie()

        # start keep-alive connection cleanup task
        self._cleanup_handle = None

        # start cleanup closed transports task
        self._cleanup_closed_handle = None
        self._cleanup_closed_disabled = not enable_cleanup_closed
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

        now = self._loop.time()
        timeout = self._keepalive_timeout

        if self._conns:
            connections = {}
            deadline = now - timeout
            for key, conns in self._conns.items():
                alive = []
                for proto, use_time in conns:
                    if proto.is_connected():
                        if use_time - deadline < 0:
                            transport = proto.close()
                            if key[-1] and not self._cleanup_closed_disabled:
                                self._cleanup_closed_transports.append(
                                    transport)
                        else:
                            alive.append((proto, use_time))

                if alive:
                    connections[key] = alive

            self._conns = connections

        if self._conns:
            self._cleanup_handle = helpers.weakref_handle(
                self, '_cleanup', timeout, self._loop)

    def _drop_acquired_per_host(self, key, val):
        acquired_per_host = self._acquired_per_host
        if key not in acquired_per_host:
            return
        conns = acquired_per_host[key]
        conns.remove(val)
        if not conns:
            del self._acquired_per_host[key]

    def _cleanup_closed(self):
        """Double confirmation for transport close.
        Some broken ssl servers may leave socket open without proper close.
        """
        if self._cleanup_closed_handle:
            self._cleanup_closed_handle.cancel()

        for transport in self._cleanup_closed_transports:
            if transport is not None:
                transport.abort()

        self._cleanup_closed_transports = []

        if not self._cleanup_closed_disabled:
            self._cleanup_closed_handle = helpers.weakref_handle(
                self, '_cleanup_closed',
                self._cleanup_closed_period, self._loop)

    def close(self):
        """Close all opened transports."""
        if self._closed:
            return

        self._closed = True

        try:
            if self._loop.is_closed():
                return noop()

            # cancel cleanup task
            if self._cleanup_handle:
                self._cleanup_handle.cancel()

            # cancel cleanup close task
            if self._cleanup_closed_handle:
                self._cleanup_closed_handle.cancel()

            for data in self._conns.values():
                for proto, t0 in data:
                    proto.close()

            for proto in self._acquired:
                proto.close()

            for transport in self._cleanup_closed_transports:
                if transport is not None:
                    transport.abort()

        finally:
            self._conns.clear()
            self._acquired.clear()
            self._waiters.clear()
            self._cleanup_handle = None
            self._cleanup_closed_transports.clear()
            self._cleanup_closed_handle = None

    @property
    def closed(self):
        """Is connector closed.

        A readonly property.
        """
        return self._closed

    async def connect(self, req, traces=None):
        """Get from pool or create new connection."""
        key = req.connection_key

        if self._limit:
            # total calc available connections
            available = self._limit - len(self._acquired)

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
            fut = self._loop.create_future()

            # This connection will now count towards the limit.
            waiters = self._waiters[key]
            waiters.append(fut)

            if traces:
                for trace in traces:
                    await trace.send_connection_queued_start()

            try:
                await fut
            finally:
                # remove a waiter even if it was cancelled
                waiters.remove(fut)
                if not waiters:
                    del self._waiters[key]

            if traces:
                for trace in traces:
                    await trace.send_connection_queued_end()

        proto = self._get(key)
        if proto is None:
            placeholder = _TransportPlaceholder()
            self._acquired.add(placeholder)
            self._acquired_per_host[key].add(placeholder)

            if traces:
                for trace in traces:
                    await trace.send_connection_create_start()

            try:
                proto = await self._create_connection(
                    req,
                    traces=traces
                )
                if self._closed:
                    proto.close()
                    raise ClientConnectionError("Connector is closed.")
            except Exception:
                # signal to waiter
                if key in self._waiters:
                    for waiter in self._waiters[key]:
                        if not waiter.done():
                            waiter.set_result(None)
                            break
                raise
            finally:
                if not self._closed:
                    self._acquired.remove(placeholder)
                    self._drop_acquired_per_host(key, placeholder)

            if traces:
                for trace in traces:
                    await trace.send_connection_create_end()
        else:
            if traces:
                for trace in traces:
                    await trace.send_connection_reuseconn()

        self._acquired.add(proto)
        self._acquired_per_host[key].add(proto)
        return Connection(self, key, proto, self._loop)

    def _get(self, key):
        try:
            conns = self._conns[key]
        except KeyError:
            return None

        t1 = self._loop.time()
        while conns:
            proto, t0 = conns.pop()
            if proto.is_connected():
                if t1 - t0 > self._keepalive_timeout:
                    transport = proto.close()
                    # only for SSL transports
                    if key[-1] and not self._cleanup_closed_disabled:
                        self._cleanup_closed_transports.append(transport)
                else:
                    if not conns:
                        # The very last connection was reclaimed: drop the key
                        del self._conns[key]
                    return proto

        # No more connections: drop the key
        del self._conns[key]
        return None

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

    def _release_acquired(self, key, proto):
        if self._closed:
            # acquired connection is already released on connector closing
            return

        try:
            self._acquired.remove(proto)
            self._drop_acquired_per_host(key, proto)
        except KeyError:  # pragma: no cover
            # this may be result of undetermenistic order of objects
            # finalization due garbage collection.
            pass
        else:
            self._release_waiter()

    def _release(self, key, protocol, *, should_close=False):
        if self._closed:
            # acquired connection is already released on connector closing
            return

        self._release_acquired(key, protocol)

        if self._force_close:
            should_close = True

        if should_close or protocol.should_close:
            transport = protocol.close()

            if key[-1] and not self._cleanup_closed_disabled:
                self._cleanup_closed_transports.append(transport)
        else:
            conns = self._conns.get(key)
            if conns is None:
                conns = self._conns[key] = []
            conns.append((protocol, self._loop.time()))

            if self._cleanup_handle is None:
                self._cleanup_handle = helpers.weakref_handle(
                    self, '_cleanup', self._keepalive_timeout, self._loop)

    async def _create_connection(self, req, traces=None):
        raise NotImplementedError()


class _DNSCacheTable:

    def __init__(self, ttl=None):
        self._addrs = {}
        self._addrs_rr = {}
        self._timestamps = {}
        self._ttl = ttl

    def __contains__(self, host):
        return host in self._addrs

    @property
    def addrs(self):
        return self._addrs

    def add(self, host, addrs):
        self._addrs[host] = addrs
        self._addrs_rr[host] = cycle(addrs)

        if self._ttl:
            self._timestamps[host] = monotonic()

    def remove(self, host):
        self._addrs.pop(host, None)
        self._addrs_rr.pop(host, None)

        if self._ttl:
            self._timestamps.pop(host, None)

    def clear(self):
        self._addrs.clear()
        self._addrs_rr.clear()
        self._timestamps.clear()

    def next_addrs(self, host):
        # Return an iterator that will get at maximum as many addrs
        # there are for the specific host starting from the last
        # not itereated addr.
        return islice(self._addrs_rr[host], len(self._addrs[host]))

    def expired(self, host):
        if self._ttl is None:
            return False

        return self._timestamps[host] + self._ttl < monotonic()


class TCPConnector(BaseConnector):
    """TCP connector.

    verify_ssl - Set to True to check ssl certifications.
    fingerprint - Pass the binary sha256
        digest of the expected certificate in DER format to verify
        that the certificate the server presents matches. See also
        https://en.wikipedia.org/wiki/Transport_Layer_Security#Certificate_pinning
    resolver - Enable DNS lookups and use this
        resolver
    use_dns_cache - Use memory cache for DNS lookups.
    ttl_dns_cache - Max seconds having cached a DNS entry, None forever.
    family - socket address family
    local_addr - local tuple of (host, port) to bind socket to

    keepalive_timeout - (optional) Keep-alive timeout.
    force_close - Set to True to force close and do reconnect
        after each request (and between redirects).
    limit - The total number of simultaneous connections.
    limit_per_host - Number of simultaneous connections to one host.
    enable_cleanup_closed - Enables clean-up closed ssl transports.
                            Disabled by default.
    loop - Optional event loop.
    """

    def __init__(self, *, verify_ssl=True, fingerprint=None,
                 use_dns_cache=True, ttl_dns_cache=10,
                 family=0, ssl_context=None, local_addr=None,
                 resolver=None, keepalive_timeout=sentinel,
                 force_close=False, limit=100, limit_per_host=0,
                 enable_cleanup_closed=False, loop=None):
        super().__init__(keepalive_timeout=keepalive_timeout,
                         force_close=force_close,
                         limit=limit, limit_per_host=limit_per_host,
                         enable_cleanup_closed=enable_cleanup_closed,
                         loop=loop)

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
                raise ValueError('md5 and sha1 are insecure and '
                                 'not supported. Use sha256.')
            self._hashfunc = hashfunc
        self._fingerprint = fingerprint

        if resolver is None:
            resolver = DefaultResolver(loop=self._loop)
        self._resolver = resolver

        self._use_dns_cache = use_dns_cache
        self._cached_hosts = _DNSCacheTable(ttl=ttl_dns_cache)
        self._throttle_dns_events = {}
        self._ssl_context = ssl_context
        self._family = family
        self._local_addr = local_addr

    def close(self):
        """Close all ongoing DNS calls."""
        for ev in self._throttle_dns_events.values():
            ev.cancel()

        super().close()

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
        if ssl is None:  # pragma: no cover
            raise RuntimeError('SSL is not supported.')

        if self._ssl_context is None:
            if not self._verify_ssl:
                sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                sslcontext.options |= ssl.OP_NO_SSLv2
                sslcontext.options |= ssl.OP_NO_SSLv3
                sslcontext.options |= ssl.OP_NO_COMPRESSION
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
        return MappingProxyType(self._cached_hosts.addrs)

    def clear_dns_cache(self, host=None, port=None):
        """Remove specified host/port or clear all dns local cache."""
        if host is not None and port is not None:
            self._cached_hosts.remove((host, port))
        elif host is not None or port is not None:
            raise ValueError("either both host and port "
                             "or none of them are allowed")
        else:
            self._cached_hosts.clear()

    async def _resolve_host(self, host, port, traces=None):
        if is_ip_address(host):
            return [{'hostname': host, 'host': host, 'port': port,
                     'family': self._family, 'proto': 0, 'flags': 0}]

        if not self._use_dns_cache:

            if traces:
                for trace in traces:
                    await trace.send_dns_resolvehost_start()

            res = (await self._resolver.resolve(
                host, port, family=self._family))

            if traces:
                for trace in traces:
                    await trace.send_dns_resolvehost_end()

            return res

        key = (host, port)

        if (key in self._cached_hosts) and \
                (not self._cached_hosts.expired(key)):

            if traces:
                for trace in traces:
                    await trace.send_dns_cache_hit()

            return self._cached_hosts.next_addrs(key)

        if key in self._throttle_dns_events:
            if traces:
                for trace in traces:
                    await trace.send_dns_cache_hit()
            await self._throttle_dns_events[key].wait()
        else:
            if traces:
                for trace in traces:
                    await trace.send_dns_cache_miss()
            self._throttle_dns_events[key] = \
                EventResultOrError(self._loop)
            try:

                if traces:
                    for trace in traces:
                        await trace.send_dns_resolvehost_start()

                addrs = await \
                    asyncio.shield(self._resolver.resolve(host,
                                                          port,
                                                          family=self._family),
                                   loop=self._loop)
                if traces:
                    for trace in traces:
                        await trace.send_dns_resolvehost_end()

                self._cached_hosts.add(key, addrs)
                self._throttle_dns_events[key].set()
            except Exception as e:
                # any DNS exception, independently of the implementation
                # is set for the waiters to raise the same exception.
                self._throttle_dns_events[key].set(exc=e)
                raise
            finally:
                self._throttle_dns_events.pop(key)

        return self._cached_hosts.next_addrs(key)

    async def _create_connection(self, req, traces=None):
        """Create connection.

        Has same keyword arguments as BaseEventLoop.create_connection.
        """
        if req.proxy:
            if req.proxy.scheme == 'http':
                _, proto = await self._create_http_proxy_connection(
                    req,
                    traces=None
                )
            elif req.proxy.scheme in ['socks4', 'socks5']:
                _, proto = await self._create_socks_proxy_connection(req)
            else:
                raise ValueError('Unsupported proxy type')
        else:
            _, proto = await self._create_direct_connection(
                req,
                traces=None
            )

        return proto

    def _get_ssl_context(self, req):
        """Logic to get the correct SSL context

        0. if req.ssl is false, return None

        1. if ssl_context is specified in req, use it
        2. if _ssl_context is specified in self, use it
        3. otherwise:
            1. if verify_ssl is not specified in req, use self.ssl_context
               (will generate a default context according to self.verify_ssl)
            2. if verify_ssl is True in req, generate a default SSL context
            3. if verify_ssl is False in req, generate a SSL context that
               won't verify
        """
        if req.ssl:
            sslcontext = req.ssl_context or self._ssl_context
            if not sslcontext:
                if req.verify_ssl is None:
                    sslcontext = self.ssl_context
                elif req.verify_ssl:
                    sslcontext = ssl.create_default_context()
                else:
                    sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                    sslcontext.options |= ssl.OP_NO_SSLv2
                    sslcontext.options |= ssl.OP_NO_SSLv3
                    sslcontext.options |= ssl.OP_NO_COMPRESSION
                    sslcontext.set_default_verify_paths()
        else:
            sslcontext = None
        return sslcontext

    def _get_fingerprint_and_hashfunc(self, req):
        if req.fingerprint:
            return (req.fingerprint, req._hashfunc)
        elif self.fingerprint:
            return (self.fingerprint, self._hashfunc)
        else:
            return (None, None)

    async def _wrap_create_connection(self, *args,
                                      req, client_error=ClientConnectorError,
                                      **kwargs):
        try:
            if req.proxy and req.proxy.scheme in ['socks4', 'socks5']:
                try:
                    return await aiosocks.create_connection(*args, **kwargs)
                except aiosocks.SocksError as exc:
                    raise ClientSocksProxyError() from exc
            else:
                return await self._loop.create_connection(*args, **kwargs)
        except certificate_errors as exc:
            raise ClientConnectorCertificateError(
                req.connection_key, exc) from exc
        except ssl_errors as exc:
            raise ClientConnectorSSLError(req.connection_key, exc) from exc
        except OSError as exc:
            raise client_error(req.connection_key, exc) from exc

    def _check_fingerprint(self, req, transp, host, port):
        fingerprint, hashfunc = self._get_fingerprint_and_hashfunc(req)

        has_cert = transp.get_extra_info('sslcontext')
        if has_cert and fingerprint:
            sslobj = transp.get_extra_info('ssl_object')
            # gives DER-encoded cert as a sequence of bytes (or None)
            cert = sslobj.getpeercert(binary_form=True)
            assert cert
            got = hashfunc(cert).digest()
            expected = fingerprint
            if got != expected:
                transp.close()
                if not self._cleanup_closed_disabled:
                    self._cleanup_closed_transports.append(transp)
                raise ServerFingerprintMismatch(
                    expected, got, host, port)

    async def _create_direct_connection(self, req,
                                        *, client_error=ClientConnectorError,
                                        traces=None):
        sslcontext = self._get_ssl_context(req)

        try:
            hosts = await self._resolve_host(
                req.url.raw_host,
                req.port,
                traces=traces)
        except OSError as exc:
            # in case of proxy it is not ClientProxyConnectionError
            # it is problem of resolving proxy ip itself
            raise ClientConnectorError(req.connection_key, exc) from exc

        last_exc = None

        for hinfo in hosts:
            host = hinfo['host']
            port = hinfo['port']

            try:
                transp, proto = await self._wrap_create_connection(
                    self._factory, host, port,
                    ssl=sslcontext, family=hinfo['family'],
                    proto=hinfo['proto'], flags=hinfo['flags'],
                    server_hostname=hinfo['hostname'] if sslcontext else None,
                    local_addr=self._local_addr,
                    req=req, client_error=client_error)
            except ClientConnectorError as exc:
                last_exc = exc
                continue

            try:
                self._check_fingerprint(req, transp, host, port)
            except ServerFingerprintMismatch as exc:
                last_exc = exc
                continue
            return transp, proto
        else:
            raise last_exc

    async def _create_http_proxy_connection(self, req, traces=None):
        headers = {}
        if req.proxy_headers is not None:
            headers = req.proxy_headers
        headers[hdrs.HOST] = req.headers[hdrs.HOST]

        proxy_req = ClientRequest(
            hdrs.METH_GET, req.proxy,
            headers=headers,
            auth=req.proxy_auth,
            loop=self._loop,
            verify_ssl=req.verify_ssl,
            fingerprint=req.fingerprint,
            ssl_context=req.ssl_context)

        # create connection to proxy server
        transport, proto = await self._create_direct_connection(
            proxy_req, client_error=ClientProxyConnectionError)

        auth = proxy_req.headers.pop(hdrs.AUTHORIZATION, None)
        if auth is not None:
            if not req.ssl:
                req.headers[hdrs.PROXY_AUTHORIZATION] = auth
            else:
                proxy_req.headers[hdrs.PROXY_AUTHORIZATION] = auth

        if req.ssl:
            sslcontext = self._get_ssl_context(req)
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
            conn = Connection(self, key, proto, self._loop)
            proxy_resp = proxy_req.send(conn)
            try:
                resp = await proxy_resp.start(conn, True)
            except Exception:
                proxy_resp.close()
                conn.close()
                raise
            else:
                conn._protocol = None
                conn._transport = None
                try:
                    if resp.status != 200:
                        raise ClientHttpProxyError(
                            proxy_resp.request_info,
                            resp.history,
                            code=resp.status,
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

                transport, proto = await self._wrap_create_connection(
                    self._factory, ssl=sslcontext, sock=rawsock,
                    server_hostname=req.host,
                    req=req)
            finally:
                proxy_resp.close()

        return transport, proto

    async def _create_socks_proxy_connection(self, req):
        if aiosocks is None:
            raise RuntimeError(
                "{} requires aiosocks library".format(req.proxy.scheme))

        sslcontext = self._get_ssl_context(req)

        if not req.socks_remote_resolve:
            try:
                dst_hosts = list(await self._resolve_host(req.host, req.port))
                dst = dst_hosts[0]['host'], dst_hosts[0]['port']
            except OSError as exc:
                raise ClientConnectorError(
                    req.connection_key, exc) from exc
        else:
            dst = req.host, req.port

        try:
            proxy_hosts = await self._resolve_host(
                req.proxy.host, req.proxy.port)
        except OSError as exc:
            raise ClientConnectorError(
                req.connection_key, exc) from exc

        last_exc = None

        for hinfo in proxy_hosts:
            if req.proxy.scheme == 'socks4':
                proxy = aiosocks.Socks4Addr(hinfo['host'], hinfo['port'])
            else:
                proxy = aiosocks.Socks5Addr(hinfo['host'], hinfo['port'])

            try:
                transp, proto = await self._wrap_create_connection(
                    self._factory, proxy, req.proxy_auth, dst,
                    loop=self._loop, remote_resolve=req.socks_remote_resolve,
                    ssl=sslcontext, family=hinfo['family'],
                    proto=hinfo['proto'], flags=hinfo['flags'],
                    local_addr=self._local_addr, req=req,
                    client_error=ClientProxyConnectionError,
                    server_hostname=req.host if sslcontext else None)
            except ClientConnectorError as exc:
                last_exc = exc
                continue

            try:
                self._check_fingerprint(req, transp, req.host, req.port)
            except ServerFingerprintMismatch as exc:
                last_exc = exc
                continue
            return transp, proto
        else:
            raise last_exc


class UnixConnector(BaseConnector):
    """Unix socket connector.

    path - Unix socket path.
    keepalive_timeout - (optional) Keep-alive timeout.
    force_close - Set to True to force close and do reconnect
        after each request (and between redirects).
    limit - The total number of simultaneous connections.
    limit_per_host - Number of simultaneous connections to one host.
    loop - Optional event loop.
    """

    def __init__(self, path, force_close=False, keepalive_timeout=sentinel,
                 limit=100, limit_per_host=0, loop=None):
        super().__init__(force_close=force_close,
                         keepalive_timeout=keepalive_timeout,
                         limit=limit, limit_per_host=limit_per_host, loop=loop)
        self._path = path

    @property
    def path(self):
        """Path to unix socket."""
        return self._path

    async def _create_connection(self, req, traces=None):
        try:
            _, proto = await self._loop.create_unix_connection(
                self._factory, self._path)
        except OSError as exc:
            raise ClientConnectorError(req.connection_key, exc) from exc

        return proto
