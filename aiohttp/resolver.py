import asyncio
import socket

from .abc import AbstractResolver

__all__ = ('ThreadedResolver', 'AsyncResolver', 'DefaultResolver')

try:
    import aiodns
except ImportError:  # pragma: no cover
    aiodns = None


class ThreadedResolver(AbstractResolver):
    """Use Executor for synchronous getaddrinfo() calls, which defaults to
    concurrent.futures.ThreadPoolExecutor.
    """

    def __init__(self, loop=None):
        if loop is None:
            loop = asyncio.get_event_loop()
        self._loop = loop

    @asyncio.coroutine
    def resolve(self, host, port=0, family=socket.AF_INET):
        infos = yield from self._loop.getaddrinfo(
            host, port, type=socket.SOCK_STREAM, family=family)

        hosts = []
        for family, _, proto, _, address in infos:
            hosts.append(
                {'hostname': host,
                 'host': address[0], 'port': address[1],
                 'family': family, 'proto': proto,
                 'flags': socket.AI_NUMERICHOST})

        return hosts

    @asyncio.coroutine
    def close(self):
        pass


class AsyncResolver(AbstractResolver):
    """Use the `aiodns` package to make asynchronous DNS lookups"""

    def __init__(self, loop=None, *args, **kwargs):
        if loop is None:
            loop = asyncio.get_event_loop()

        if aiodns is None:
            raise RuntimeError("Resolver requires aiodns library")

        self._loop = loop
        self._resolver = aiodns.DNSResolver(*args, loop=loop, **kwargs)

    @asyncio.coroutine
    def resolve(self, host, port=0, family=socket.AF_INET):
        hosts_v4 = hosts_v6 = None
        if family in [socket.AF_INET, socket.AF_UNSPEC]:
            try:
                hosts_v4 = yield from \
                    self.resolve_with_query(host, port, socket.AF_INET)
            except aiodns.error.DNSError:
                if family == socket.AF_INET:
                    raise
        if family in [socket.AF_INET6, socket.AF_UNSPEC]:
            try:
                hosts_v6 = yield from \
                    self.resolve_with_query(host, port, socket.AF_INET6)
            except aiodns.error.DNSError:
                if family == socket.AF_INET6 or not hosts_v4:
                    raise
        return (hosts_v4 or []) + (hosts_v6 or [])

    @asyncio.coroutine
    def resolve_with_query(self, host, port=0, family=socket.AF_INET):
        if family == socket.AF_INET6:
            qtype = 'AAAA'
        else:
            qtype = 'A'

        hosts = []
        resp = yield from self._resolver.query(host, qtype)

        if resp:
            for rr in resp:
                hosts.append(
                    {'hostname': host,
                     'host': rr.host, 'port': port,
                     'family': family, 'proto': 0,
                     'flags': socket.AI_NUMERICHOST})

        return hosts

    @asyncio.coroutine
    def close(self):
        return self._resolver.cancel()


DefaultResolver = AsyncResolver if aiodns else ThreadedResolver
