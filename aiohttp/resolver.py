import asyncio
import socket
import weakref
from typing import Any, List, Optional, Tuple, Type, Union

from .abc import AbstractResolver, ResolveResult

__all__ = ("ThreadedResolver", "AsyncResolver", "DefaultResolver")


try:
    import aiodns

    aiodns_default = hasattr(aiodns.DNSResolver, "getaddrinfo")
except ImportError:
    aiodns = None  # type: ignore[assignment]
    aiodns_default = False


_NUMERIC_SOCKET_FLAGS = socket.AI_NUMERICHOST | socket.AI_NUMERICSERV
_NAME_SOCKET_FLAGS = socket.NI_NUMERICHOST | socket.NI_NUMERICSERV
_AI_ADDRCONFIG = socket.AI_ADDRCONFIG
if hasattr(socket, "AI_MASK"):
    _AI_ADDRCONFIG &= socket.AI_MASK


class ThreadedResolver(AbstractResolver):
    """Threaded resolver.

    Uses an Executor for synchronous getaddrinfo() calls.
    concurrent.futures.ThreadPoolExecutor is used by default.
    """

    def __init__(self) -> None:
        self._loop = asyncio.get_running_loop()

    async def resolve(
        self, host: str, port: int = 0, family: socket.AddressFamily = socket.AF_INET
    ) -> List[ResolveResult]:
        infos = await self._loop.getaddrinfo(
            host,
            port,
            type=socket.SOCK_STREAM,
            family=family,
            flags=_AI_ADDRCONFIG,
        )

        hosts: List[ResolveResult] = []
        for family, _, proto, _, address in infos:
            if family == socket.AF_INET6:
                if len(address) < 3:
                    # IPv6 is not supported by Python build,
                    # or IPv6 is not enabled in the host
                    continue
                if address[3]:
                    # This is essential for link-local IPv6 addresses.
                    # LL IPv6 is a VERY rare case. Strictly speaking, we should use
                    # getnameinfo() unconditionally, but performance makes sense.
                    resolved_host, _port = await self._loop.getnameinfo(
                        address, _NAME_SOCKET_FLAGS
                    )
                    port = int(_port)
                else:
                    resolved_host, port = address[:2]
            else:  # IPv4
                assert family == socket.AF_INET
                resolved_host, port = address  # type: ignore[misc]
            hosts.append(
                ResolveResult(
                    hostname=host,
                    host=resolved_host,
                    port=port,
                    family=family,
                    proto=proto,
                    flags=_NUMERIC_SOCKET_FLAGS,
                )
            )

        return hosts

    async def close(self) -> None:
        pass


class AsyncResolver(AbstractResolver):
    """Use the `aiodns` package to make asynchronous DNS lookups"""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        if aiodns is None:
            raise RuntimeError("Resolver requires aiodns library")

        self._manager: Optional[_DNSResolverManager] = None
        # If custom args are provided, create a dedicated resolver instance
        # This means each AsyncResolver with custom args gets its own
        # aiodns.DNSResolver instance
        if args or kwargs:
            self._resolver = aiodns.DNSResolver(*args, **kwargs)
            return
        # Use the shared resolver from the manager for default arguments
        self._manager = _DNSResolverManager()
        self._resolver = self._manager.get_resolver()
        self._manager.register_client(self)

    async def resolve(
        self, host: str, port: int = 0, family: socket.AddressFamily = socket.AF_INET
    ) -> List[ResolveResult]:
        try:
            resp = await self._resolver.getaddrinfo(
                host,
                port=port,
                type=socket.SOCK_STREAM,
                family=family,
                flags=_AI_ADDRCONFIG,
            )
        except aiodns.error.DNSError as exc:
            msg = exc.args[1] if len(exc.args) >= 1 else "DNS lookup failed"
            raise OSError(None, msg) from exc
        hosts: List[ResolveResult] = []
        for node in resp.nodes:
            address: Union[Tuple[bytes, int], Tuple[bytes, int, int, int]] = node.addr
            family = node.family
            if family == socket.AF_INET6:
                if len(address) > 3 and address[3]:
                    # This is essential for link-local IPv6 addresses.
                    # LL IPv6 is a VERY rare case. Strictly speaking, we should use
                    # getnameinfo() unconditionally, but performance makes sense.
                    result = await self._resolver.getnameinfo(
                        (address[0].decode("ascii"), *address[1:]),
                        _NAME_SOCKET_FLAGS,
                    )
                    resolved_host = result.node
                else:
                    resolved_host = address[0].decode("ascii")
                    port = address[1]
            else:  # IPv4
                assert family == socket.AF_INET
                resolved_host = address[0].decode("ascii")
                port = address[1]
            hosts.append(
                ResolveResult(
                    hostname=host,
                    host=resolved_host,
                    port=port,
                    family=family,
                    proto=0,
                    flags=_NUMERIC_SOCKET_FLAGS,
                )
            )

        if not hosts:
            raise OSError(None, "DNS lookup failed")

        return hosts

    async def close(self) -> None:
        if self._manager:
            # Unregister from the manager if using the shared resolver
            self._manager.unregister_client(self)
            return
        # Otherwise cancel our dedicated resolver
        self._resolver.cancel()


class _DNSResolverManager:
    """Manager for aiodns.DNSResolver objects.

    This class manages a single shared aiodns.DNSResolver instance
    with no custom arguments.
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init()
        return cls._instance

    def _init(self) -> None:
        if aiodns is None:
            raise RuntimeError("DNSResolverManager requires aiodns library")
        self._resolver = None
        self._clients = weakref.WeakSet()

    def get_resolver(self) -> "aiodns.DNSResolver":
        """Get or create the shared aiodns.DNSResolver instance."""
        if not self._resolver:
            self._resolver = aiodns.DNSResolver()
        return self._resolver

    def register_client(self, client: "AsyncResolver") -> None:
        """Register an AsyncResolver client."""
        self._clients.add(client)

    def unregister_client(self, client: "AsyncResolver") -> None:
        """Unregister an AsyncResolver client when it's closed."""
        self._clients.discard(client)

        # If there are no more clients, close the resolver
        if not self._clients and self._resolver:
            self._resolver.cancel()
            self._resolver = None


_DefaultType = Type[Union[AsyncResolver, ThreadedResolver]]
DefaultResolver: _DefaultType = AsyncResolver if aiodns_default else ThreadedResolver
