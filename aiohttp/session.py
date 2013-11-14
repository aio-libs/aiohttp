"""http client session support."""

__all__ = ['Session']

import asyncio
import aiohttp
import functools
import http.cookies


class Session:

    def __init__(self):
        self._conns = {}
        self.cookies = http.cookies.SimpleCookie()

    def __del__(self):
        self.close()

    def close(self):
        """Close all opened transports."""
        for key, data in self._conns.items():
            for transport, proto in data:
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
            transport, proto = self._get(key)
            if proto and not proto.is_connected():
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

        return None, None

    def _release(self, req, key, conn):
        resp = req.response
        should_close = False

        if resp is not None:
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
                         (self.transport, self.protocol))
