"""This is a collection of semi-complete examples that get included into the cookbook page."""

import asyncio
import logging
import operator
import socket
import time
import weakref
from collections.abc import AsyncIterator, Awaitable, Callable, Hashable, Sequence
from contextlib import asynccontextmanager, suppress

from aiohttp import (
    ClientError,
    ClientHandlerType,
    ClientRequest,
    ClientResponse,
    ClientSession,
    TCPConnector,
)
from aiohttp.abc import AbstractResolver, ResolveResult
from aiohttp.tracing import Trace


class SSRFError(ClientError):
    """A request was made to a blacklisted host."""


async def retry_middleware(
    req: ClientRequest, handler: ClientHandlerType
) -> ClientResponse:
    for _ in range(3):  # Try up to 3 times
        resp = await handler(req)
        if resp.ok:
            return resp
    return resp  # type: ignore[possibly-undefined]


async def api_logging_middleware(
    req: ClientRequest, handler: ClientHandlerType
) -> ClientResponse:
    # We use middlewares=() to avoid infinite recursion.
    async with req.session.post("/log", data=req.url.host, middlewares=()) as resp:
        if not resp.ok:
            logging.warning("Log endpoint failed")

    return await handler(req)


class TokenRefresh401Middleware:
    def __init__(self, refresh_token: str, access_token: str):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.lock = asyncio.Lock()

    async def __call__(
        self, req: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        for _ in range(2):  # Retry at most one time
            token = self.access_token
            req.headers["Authorization"] = f"Bearer {token}"
            resp = await handler(req)
            if resp.status != 401:
                return resp
            async with self.lock:
                if token != self.access_token:  # Already refreshed
                    continue
                url = "https://api.example/refresh"
                async with req.session.post(url, data=self.refresh_token) as resp:
                    # Add error handling as needed
                    data = await resp.json()
                    self.access_token = data["access_token"]
        return resp  # type: ignore[possibly-undefined]


class TokenRefreshExpiryMiddleware:
    def __init__(self, refresh_token: str):
        self.access_token = ""
        self.expires_at = 0
        self.refresh_token = refresh_token
        self.lock = asyncio.Lock()

    async def __call__(
        self, req: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        if self.expires_at <= time.time():
            token = self.access_token
            async with self.lock:
                if token == self.access_token:  # Still not refreshed
                    url = "https://api.example/refresh"
                    async with req.session.post(url, data=self.refresh_token) as resp:
                        # Add error handling as needed
                        data = await resp.json()
                        self.access_token = data["access_token"]
                        self.expires_at = data["expires_at"]

        req.headers["Authorization"] = f"Bearer {self.access_token}"
        return await handler(req)


async def token_refresh_preemptively_example() -> None:
    async def set_token(session: ClientSession, event: asyncio.Event) -> None:
        while True:
            async with session.post("/refresh") as resp:
                token = await resp.json()
                session.headers["Authorization"] = f"Bearer {token['auth']}"
                event.set()
                await asyncio.sleep(token["valid_duration"])

    @asynccontextmanager
    async def auto_refresh_client() -> AsyncIterator[ClientSession]:
        async with ClientSession() as session:
            ready = asyncio.Event()
            t = asyncio.create_task(set_token(session, ready))
            await ready.wait()
            yield session
            t.cancel()
            with suppress(asyncio.CancelledError):
                await t

    async with auto_refresh_client() as sess:
        ...


async def ssrf_middleware(
    req: ClientRequest, handler: ClientHandlerType
) -> ClientResponse:
    # WARNING: This is a simplified example for demonstration purposes only.
    # A complete implementation should also check:
    # - IPv6 loopback (::1)
    # - Private IP ranges (10.x.x.x, 192.168.x.x, 172.16-31.x.x)
    # - Link-local addresses (169.254.x.x, fe80::/10)
    # - Other internal hostnames and aliases
    if req.url.host in {"127.0.0.1", "localhost"}:
        raise SSRFError(req.url.host)
    return await handler(req)


class SSRFConnector(TCPConnector):
    async def _resolve_host(
        self, host: str, port: int, traces: Sequence[Trace] | None = None
    ) -> list[ResolveResult]:
        res = await super()._resolve_host(host, port, traces)
        # WARNING: This is a simplified example - should also check ::1, private ranges, etc.
        if any(r["host"] in {"127.0.0.1"} for r in res):
            raise SSRFError()
        return res


async def by_host(req: ClientRequest) -> Hashable:
    return req.url.raw_host


class RateLimitMiddleware:
    def __init__(
        self,
        limit: int,
        period: float,
        key: Callable[[ClientRequest], Awaitable[Hashable]] = by_host,
    ):
        if operator.index(limit) < 1 or not period > 0:
            raise ValueError("limit must be at least 1, and period positive")
        self.limit = limit
        self.period = period
        self.key = key
        # The release timers keep a semaphore alive while any of its slots is taken
        self.slots: weakref.WeakValueDictionary[Hashable, asyncio.Semaphore] = (
            weakref.WeakValueDictionary()
        )

    async def __call__(
        self, req: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        key = await self.key(req)
        slots = self.slots.setdefault(key, asyncio.Semaphore(self.limit))
        await slots.acquire()
        asyncio.get_running_loop().call_later(self.period, slots.release)
        return await handler(req)


def by_resolved_ip(
    resolver: AbstractResolver,
) -> Callable[[ClientRequest], Awaitable[Hashable]]:
    lookups: dict[str, asyncio.Task[str]] = {}

    async def lookup(host: str) -> str:
        try:
            results = await resolver.resolve(host, family=socket.AF_UNSPEC)
        except OSError:
            # The connector's own lookup reports the error
            lookups.pop(host, None)
            return host
        # AF_INET sorts before AF_INET6, so IPv4 addresses come first
        return min((r["family"], r["host"]) for r in results)[1]

    async def by_ip(req: ClientRequest) -> Hashable:
        host = req.url.raw_host
        assert host is not None
        if req.proxy is not None:
            return host
        if host not in lookups:
            lookups[host] = asyncio.create_task(lookup(host))
        # A cancelled request must not cancel the lookup that other requests await
        return await asyncio.shield(lookups[host])

    return by_ip
