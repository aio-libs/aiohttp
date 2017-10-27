import asyncio
import socket

from .abc import AbstractResolver


__all__ = ('ThreadedResolver', 'AsyncResolver', 'DefaultResolver')

try:
    import aiodns
    # aiodns_default = hasattr(aiodns.DNSResolver, 'gethostbyname')
except ImportError:  # pragma: no cover
    aiodns = None

aiodns_default = False


class ThreadedResolver(AbstractResolver):
    """Use Executor for synchronous getaddrinfo() calls, which defaults to
    concurrent.futures.ThreadPoolExecutor.
    """

    def __init__(self, loop=None):
        if loop is None:
            loop = asyncio.get_event_loop()
        self._loop = loop

    async def resolve(self, host, port=0, family=socket.AF_INET):
        infos = await self._loop.getaddrinfo(
            host, port, type=socket.SOCK_STREAM, family=family)

        hosts = []
        for family, _, proto, _, address in infos:
            hosts.append(
                {'hostname': host,
                 'host': address[0], 'port': address[1],
                 'family': family, 'proto': proto,
                 'flags': socket.AI_NUMERICHOST})

        return hosts

    async def close(self):
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

        if not hasattr(self._resolver, 'gethostbyname'):
            # aiodns 1.1 is not available, fallback to DNSResolver.query
            self.resolve = self._resolve_with_query

    async def resolve(self, host, port=0, family=socket.AF_INET):
        try:
            resp = await self._resolver.gethostbyname(host, family)
        except aiodns.error.DNSError as exc:
            msg = exc.args[1] if len(exc.args) >= 1 else "DNS lookup failed"
            raise OSError(msg) from exc
        hosts = []
        for address in resp.addresses:
            hosts.append(
                {'hostname': host,
                 'host': address, 'port': port,
                 'family': family, 'proto': 0,
                 'flags': socket.AI_NUMERICHOST})

        if not hosts:
            raise OSError("DNS lookup failed")

        return hosts

    async def _resolve_with_query(self, host, port=0, family=socket.AF_INET):
        if family == socket.AF_INET6:
            qtype = 'AAAA'
        else:
            qtype = 'A'

        try:
            resp = await self._resolver.query(host, qtype)
        except aiodns.error.DNSError as exc:
            msg = exc.args[1] if len(exc.args) >= 1 else "DNS lookup failed"
            raise OSError(msg) from exc

        hosts = []
        for rr in resp:
            hosts.append(
                {'hostname': host,
                 'host': rr.host, 'port': port,
                 'family': family, 'proto': 0,
                 'flags': socket.AI_NUMERICHOST})

        if not hosts:
            raise OSError("DNS lookup failed")

        return hosts

    async def close(self):
        return self._resolver.cancel()


DefaultResolver = AsyncResolver if aiodns_default else ThreadedResolver
