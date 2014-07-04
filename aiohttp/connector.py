__all__ = ['BaseConnector', 'TCPConnector', 'UnixConnector',
           'SocketConnector', 'UnixSocketConnector', 'ProxyConnector']

import asyncio
import aiohttp
import functools
import http.cookies
import time
import ssl
import socket
import weakref

from .errors import HttpProxyError
from .errors import ProxyConnectionError
from .client import ClientRequest


class Connection(object):

    def __init__(self, connector, key, request, transport, protocol):
        self._key = key
        self._connector = connector
        self._request = request
        self._transport = transport
        self._protocol = protocol
        self.reader = protocol.reader
        self.writer = protocol.writer
        self._wr = weakref.ref(self, lambda wr, tr=self._transport: tr.close())

    def close(self):
        if self._transport is not None:
            self._transport.close()
            self._transport = None
            self._wr = None

    def release(self):
        if self._transport:
            self._connector._release(
                self._key, self._request, self._transport, self._protocol)
            self._transport = None
            self._wr = None


class BaseConnector(object):

    def __init__(self, *, conn_timeout=None, keepalive_timeout=30,
                 share_cookies=False, force_close=False, loop=None, **kwargs):
        self._conns = {}
        self._conn_timeout = conn_timeout
        self._keepalive_timeout = keepalive_timeout
        self._share_cookies = share_cookies
        self._cleanup_handle = None
        self._force_close = force_close

        if loop is None:
            loop = asyncio.get_event_loop()
        self._loop = loop
        self._factory = functools.partial(aiohttp.StreamProtocol, loop=loop)

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
        key = (req.host, req.port, req.ssl)

        if self._share_cookies:
            req.update_cookies(self.cookies.items())

        transport, proto = self._get(key)
        if transport is None:
            if self._conn_timeout:
                transport, proto = yield from asyncio.wait_for(
                    self._create_connection(req),
                    self._conn_timeout, loop=self._loop)
            else:
                transport, proto = yield from self._create_connection(req)

        return Connection(self, key, req, transport, proto)

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

    def _release(self, key, req, transport, protocol):
        resp = req.response
        should_close = False

        if resp is not None:
            if resp.message is None:
                should_close = True
            else:
                should_close = resp.message.should_close
                if self._share_cookies and resp.cookies:
                    self.update_cookies(resp.cookies.items())

        if self._force_close:
            should_close = True

        reader = protocol.reader
        if should_close or (reader.output and not reader.output.at_eof()):
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


class TCPConnector(BaseConnector):

    def __init__(self, *args, verify_ssl=True,
                 resolve=False, family=socket.AF_INET, **kwargs):
        super().__init__(*args, **kwargs)

        self._verify_ssl = verify_ssl
        self._family = family
        self._resolve = resolve
        self._resolved_hosts = {}

    @property
    def verify_ssl(self):
        """Do check for ssl certifications?"""
        return self._verify_ssl

    @property
    def family(self):
        """Socket family like AF_INET"""
        return self._family

    @property
    def resolve(self):
        """Do DNS lookup for host name?"""
        return self._resolve

    @property
    def resolved_hosts(self):
        """The dict of (host, port) -> (ipaddr, port) pairs"""
        return dict(self._resolved_hosts)

    def clear_resolved_hosts(self, host=None, port=None):
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
        """Create connection. Has same keyword arguments
        as BaseEventLoop.create_connection
        """
        sslcontext = req.ssl
        if req.ssl and not self._verify_ssl:
            sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            sslcontext.options |= ssl.OP_NO_SSLv2
            sslcontext.set_default_verify_paths()

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
            except OSError:
                if not hosts:
                    raise


class ProxyConnector(TCPConnector):
    """Http Proxy connector."""

    def __init__(self, proxy, proxy_login=None, proxy_passwd=None,
                 *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._proxy = proxy
        self._basic_login = proxy_login
        self._basic_passwd = proxy_passwd
        assert proxy.startswith('http://'), (
            "Only http proxy supported", proxy)

    @property
    def proxy(self):
        return self._proxy

    @asyncio.coroutine
    def _create_connection(self, req, **kwargs):
        proxy_req = ClientRequest(
            'GET', self._proxy,
            headers={'Host': req.host},
            auth=aiohttp.BasicAuth(self._basic_login, self._basic_passwd),
            loop=self._loop)
        try:
            transport, proto = yield from super()._create_connection(proxy_req)
        except OSError as exc:
            raise ProxyConnectionError(*exc.args) from exc
        req.path = '{scheme}://{host}{path}'.format(scheme=req.scheme,
                                                    host=req.host,
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
            conn = Connection(self, key, proxy_req, transport, proto)
            proxy_resp = proxy_req.send(conn.writer, conn.reader)
            try:
                resp = yield from proxy_resp.start(conn, True)
            except:
                proxy_resp.close()
                conn.close()
                raise
            else:
                if resp.status != 200:
                    raise HttpProxyError(resp.status, resp.reason)
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

    def __init__(self, path, *args, **kw):
        super().__init__(*args, **kw)

        self._path = path

    @property
    def path(self):
        """Path to unix socket"""
        return self._path

    @asyncio.coroutine
    def _create_connection(self, req, **kwargs):
        return (yield from self._loop.create_unix_connection(
            self._factory, self._path, **kwargs))


SocketConnector = TCPConnector
UnixSocketConnector = UnixConnector
