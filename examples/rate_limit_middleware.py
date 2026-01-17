#!/usr/bin/env python3
"""
Example of using rate limiting middleware with aiohttp client.

This example shows how to implement a middleware that limits request rate
to avoid overwhelming servers or hitting API rate limits. The implementation
uses a token bucket algorithm that allows for burst traffic while maintaining
an average rate limit.

Features:
- Token bucket rate limiting with configurable rate and burst size
- Per-domain rate limiting for multi-host scenarios
- Automatic Retry-After header handling
- Support for both global and per-domain limits
"""

import asyncio
import logging
import time
from collections import defaultdict
from http import HTTPStatus

from aiohttp import ClientHandlerType, ClientRequest, ClientResponse, ClientSession, web

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

    async def acquire(self) -> float:
        """Acquire a token, returning wait time if bucket is empty."""
        async with self._lock:
            now = time.monotonic()
            self._refill(now)
            if self.tokens >= 1:
                self.tokens -= 1
                return 0.0
            wait_time = (1 - self.tokens) / self.rate
            return wait_time

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
                pass  # Retry-After may be an HTTP-date; ignore if not a number

    async def __call__(
        self,
        request: ClientRequest,
        handler: ClientHandlerType,
    ) -> ClientResponse:
        """Execute request with rate limiting."""
        bucket = self._get_bucket(request)
        wait_time = await bucket.acquire()
        if wait_time > 0:
            _LOGGER.debug("Rate limited, waiting %.2fs", wait_time)
            await asyncio.sleep(wait_time)

        response = await handler(request)

        if self.respect_retry_after:
            await self._handle_retry_after(response)

        return response


class TestServer:
    """Test server that simulates rate limiting."""

    def __init__(self) -> None:
        self.request_times: list[float] = []
        self.rate_limit_counter = 0

    async def handle_api(self, request: web.Request) -> web.Response:
        """Normal API endpoint that tracks request timing."""
        self.request_times.append(time.monotonic())
        return web.json_response(
            {
                "message": "Success",
                "request_count": len(self.request_times),
            }
        )

    async def handle_rate_limited(self, request: web.Request) -> web.Response:
        """Endpoint simulating server-side rate limiting."""
        self.rate_limit_counter += 1
        if self.rate_limit_counter <= 2:
            return web.Response(
                status=429,
                text="Too Many Requests",
                headers={"Retry-After": "1"},
            )
        return web.json_response({"message": "Rate limit cleared"})

    async def handle_stats(self, request: web.Request) -> web.Response:
        """Return request timing statistics."""
        if len(self.request_times) < 2:
            return web.json_response({"intervals": [], "average_rate": 0})
        intervals = [
            self.request_times[i] - self.request_times[i - 1]
            for i in range(1, len(self.request_times))
        ]
        avg_rate = 1.0 / (sum(intervals) / len(intervals)) if intervals else 0
        return web.json_response(
            {
                "intervals": [round(i, 3) for i in intervals],
                "average_rate": round(avg_rate, 2),
            }
        )

    async def handle_reset(self, request: web.Request) -> web.Response:
        """Reset server state."""
        self.request_times = []
        self.rate_limit_counter = 0
        return web.Response(text="Reset")


async def run_test_server() -> web.AppRunner:
    """Run a test server with rate limiting simulation."""
    app = web.Application()
    server = TestServer()

    app.router.add_get("/api", server.handle_api)
    app.router.add_get("/rate-limited", server.handle_rate_limited)
    app.router.add_get("/stats", server.handle_stats)
    app.router.add_post("/reset", server.handle_reset)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "localhost", 8080)
    await site.start()
    return runner


async def run_tests() -> None:
    """Run rate limit middleware tests."""
    rate_limit = RateLimitMiddleware(rate=5.0, burst=2, per_domain=False)

    async with ClientSession(middlewares=(rate_limit,)) as session:
        await session.post("http://localhost:8080/reset")

        print("=== Test 1: Burst requests (limit: 5/s, burst: 2) ===")
        print("Sending 5 requests rapidly...")
        start = time.monotonic()

        for i in range(5):
            async with session.get("http://localhost:8080/api") as resp:
                data = await resp.json()
                elapsed = time.monotonic() - start
                print(f"Request {i + 1}: {elapsed:.2f}s - {data['message']}")

        print("\n=== Test 2: Check actual request rate ===")
        async with session.get("http://localhost:8080/stats") as resp:
            stats = await resp.json()
            print(f"Request intervals: {stats['intervals']}")
            print(f"Average rate: {stats['average_rate']} req/s")

        print("\n=== Test 3: Server-side 429 with Retry-After ===")
        await session.post("http://localhost:8080/reset")
        for i in range(3):
            async with session.get("http://localhost:8080/rate-limited") as resp:
                text = await resp.text() if resp.status == 429 else (await resp.json())
                print(f"Request {i + 1}: Status {resp.status} - {text}")

    print("\n=== Test 4: Per-domain rate limiting ===")
    per_domain_limit = RateLimitMiddleware(rate=10.0, burst=1, per_domain=True)

    async with ClientSession(middlewares=(per_domain_limit,)) as session:
        await session.post("http://localhost:8080/reset")
        print("Simulating requests to different 'domains' (same server)...")
        print("(In real usage, different domains get separate rate limits)")

        start = time.monotonic()
        for i in range(3):
            async with session.get("http://localhost:8080/api") as resp:
                elapsed = time.monotonic() - start
                print(f"Request {i + 1} to localhost: {elapsed:.2f}s")


async def main() -> None:
    server = await run_test_server()

    try:
        await run_tests()
    finally:
        await server.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
