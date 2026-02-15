#!/usr/bin/env python3
"""
Rate-limiting middleware example (client-side).

Uses a token-bucket algorithm with optional per-domain limiting and
automatic Retry-After respect.
"""

import asyncio
import logging
import time
from collections import defaultdict
from http import HTTPStatus

from aiohttp import ClientHandlerType, ClientRequest, ClientResponse, ClientSession

logging.basicConfig(level=logging.INFO)
_LOGGER = logging.getLogger(__name__)


class TokenBucket:
    """Token bucket rate limiter implementation."""

    def __init__(self, rate: float, burst: int) -> None:
        self.rate = rate
        self.burst = burst
        self.tokens = float(burst)
        self.last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Acquire a token, waiting if necessary."""
        while True:
            async with self._lock:
                now = time.monotonic()
                self._refill(now)
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                wait_time = (1 - self.tokens) / self.rate

            await asyncio.sleep(wait_time)

    def _refill(self, now: float) -> None:
        elapsed = now - self.last_refill
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        self.last_refill = now


class RateLimitMiddleware:
    """Middleware that rate limits requests using token bucket algorithm."""

    def __init__(
        self,
        rate: float = 10.0,
        burst: int = 10,
        per_domain: bool = False,
        respect_retry_after: bool = True,
    ) -> None:
        self.rate = rate
        self.burst = burst
        self.per_domain = per_domain
        self.respect_retry_after = respect_retry_after
        self._global_bucket = TokenBucket(rate, burst)
        self._domain_buckets: dict[str, TokenBucket] = defaultdict(
            lambda: TokenBucket(rate, burst)
        )

    def _get_bucket(self, request: ClientRequest) -> TokenBucket:
        if self.per_domain:
            domain = request.url.host or "unknown"
            return self._domain_buckets[domain]
        return self._global_bucket

    async def _handle_retry_after(self, response: ClientResponse) -> None:
        if response.status != HTTPStatus.TOO_MANY_REQUESTS:
            return
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                wait_seconds = float(retry_after)
                _LOGGER.info("Server requested Retry-After: %ss", wait_seconds)
                await asyncio.sleep(wait_seconds)
            except ValueError:
                _LOGGER.debug(
                    "Retry-After is not a number (likely HTTP-date): %s", retry_after
                )

    async def __call__(
        self,
        request: ClientRequest,
        handler: ClientHandlerType,
    ) -> ClientResponse:
        """Execute request with rate limiting."""
        bucket = self._get_bucket(request)
        await bucket.acquire()

        response = await handler(request)

        if self.respect_retry_after:
            await self._handle_retry_after(response)

        return response


# ------------------------------------------------------------------
# Simple demo
async def main() -> None:
    rate_limit = RateLimitMiddleware(rate=5.0, burst=2)

    async with ClientSession(
        base_url="http://httpbin.org", middlewares=(rate_limit,)
    ) as session:
        for i in range(5):
            async with session.get("/get") as resp:
                print(f"Request {i + 1}: {resp.status}")


if __name__ == "__main__":
    asyncio.run(main())
