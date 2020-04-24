import socket
from typing import Any, Dict, List

from .abc import AbstractResolver
from .helpers import get_running_loop

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

    def __init__(self) -> None:
        self._loop = get_running_loop()

    async def resolve(self, host: str, port: int=0,
                      family: int=socket.AF_INET) -> List[Dict[str, Any]]:
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

    async def close(self) -> None:
        pass


class AsyncResolver(AbstractResolver):
    """Use the `aiodns` package to make asynchronous DNS lookups"""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        if aiodns is None:
            raise RuntimeError("Resolver requires aiodns library")

        self._loop = get_running_loop()
        self._resolver = aiodns.DNSResolver(*args, loop=self._loop, **kwargs)

    async def resolve(self, host: str, port: int=0,
                      family: int=socket.AF_INET) -> List[Dict[str, Any]]:
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

    async def close(self) -> None:
        return self._resolver.cancel()


DefaultResolver = AsyncResolver if aiodns_default else ThreadedResolver
