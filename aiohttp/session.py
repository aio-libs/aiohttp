"""http client session support."""

__all__ = ['Session']

import asyncio
import aiohttp
import functools
import http.cookies
import time


class Session:

    def __init__(self, reuse_timeout=30, loop=None):
        self._conns = {}
        self._reuse_timeout = reuse_timeout
        self._cleanup_handle = None
        self.cookies = http.cookies.SimpleCookie()

        if loop is None:
            loop = asyncio.get_event_loop()
        self._loop = loop

    def __del__(self):
        self.close()

    def _cleanup(self):
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
                    elif (now - t0) > self._reuse_timeout:
                        transport.close()
                        transport = None

                if transport:
                    alive.append((transport, proto, t0))
            if alive:
                connections[key] = alive

        if connections:
            self._cleanup_handle = self._loop.call_later(
                self._reuse_timeout, self._cleanup)

        self._conns = connections

    def _start_cleanup_task(self):
        if self._cleanup_handle is None:
            self._cleanup_handle = self._loop.call_later(
                self._reuse_timeout, self._cleanup)

    def close(self):
        """Close all opened transports."""
        for key, data in self._conns.items():
            for transport, proto, td in data:
                transport.close()

        self._conns.clear()

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
    def start(self, req, loop, params=None, new_conn=False, set_cookies=True):
        key = (req.host, req.port, req.ssl)

        if set_cookies and self.cookies:
            req.update_cookies(self.cookies.items())

        if not new_conn:
            transport, proto, t0 = self._get(key)
            if transport is not None:
                if proto and not proto.is_connected():
                    transport = None
                elif (time.time() - t0) > self._reuse_timeout:
                    transport.close()
                    transport = None

        if new_conn or transport is None:
            if params is not None:
                transport, proto = yield from loop.create_connection(
                    functools.partial(aiohttp.StreamProtocol, loop=loop),
                    params['host'], params['port'],
                    ssl=params['ssl'], family=params['family'],
                    proto=params['proto'], flags=params['flags'])
            else:
                transport, proto = yield from loop.create_connection(
                    functools.partial(aiohttp.StreamProtocol, loop=loop),
                    req.host, req.port, ssl=req.ssl)

        wrp = TransportWrapper(self._release, key, transport, proto, req)

        return transport, proto, wrp

    def _get(self, key):
        conns = self._conns.get(key)
        if conns:
            return conns.pop()

        return None, None, None

    def _release(self, req, key, conn):
        resp = req.response
        should_close = False

        if resp is not None:
            if resp.message is None:
                should_close = True
            else:
                should_close = resp.message.should_close
                if resp.cookies:
                    self.update_cookies(resp.cookies.items())

        if should_close:
            conn[0].close()
        else:
            conns = self._conns.get(key)
            if conns is None:
                conns = self._conns[key] = []
            conns.append(conn)
            conn[1].unset_parser()

            self._start_cleanup_task()


class TransportWrapper:

    def __init__(self, release, key, transport, protocol, request):
        self.release = release
        self.key = key
        self.transport = transport
        self.protocol = protocol
        self.request = request

    def close(self, force=False):
        if force:
            self.transport.close()
        else:
            self.release(self.request, self.key,
                         (self.transport, self.protocol, time.time()))
