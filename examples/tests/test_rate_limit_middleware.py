"""
Tests for the rate_limit_middleware.py example.

Run with:
    pytest examples/tests/test_rate_limit_middleware.py -v
"""

import asyncio
import time

import pytest

from aiohttp import web
from aiohttp.pytest_plugin import AiohttpClient
from rate_limit_middleware import RateLimitMiddleware, TokenBucket


async def _ok_handler(request: web.Request) -> web.Response:
    return web.Response(text="OK")


def _make_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/api", _ok_handler)
    return app


@pytest.mark.asyncio
async def test_token_bucket_allows_burst() -> None:
    """Tokens up to burst size should be available immediately."""
    bucket = TokenBucket(rate=10.0, burst=3)
    start = time.monotonic()
    for _ in range(3):
        await bucket.acquire()
    elapsed = time.monotonic() - start
    # All three should be nearly instant (burst)
    assert elapsed < 0.05


@pytest.mark.asyncio
async def test_token_bucket_refills_after_idle() -> None:
    """After draining, idle time should replenish burst slots."""
    bucket = TokenBucket(rate=100.0, burst=1)
    await bucket.acquire()
    await asyncio.sleep(0.05)
    start = time.monotonic()
    await bucket.acquire()
    elapsed = time.monotonic() - start
    # Should be near-instant because idle refilled the slot
    assert elapsed < 0.02


@pytest.mark.asyncio
async def test_token_bucket_fifo_ordering() -> None:
    """Concurrent acquires should be served in FIFO order."""
    bucket = TokenBucket(rate=100.0, burst=1)
    order: list[int] = []

    async def numbered_acquire(n: int) -> None:
        await bucket.acquire()
        order.append(n)

    tasks = [asyncio.create_task(numbered_acquire(i)) for i in range(3)]
    await asyncio.gather(*tasks)
    assert order == [0, 1, 2]


@pytest.mark.asyncio
async def test_rate_limit_middleware_throttles(
    aiohttp_client: AiohttpClient,
) -> None:
    """Global middleware should throttle requests beyond burst."""
    middleware = RateLimitMiddleware(rate=50.0, burst=2)
    client = await aiohttp_client(_make_app(), middlewares=(middleware,))

    start = time.monotonic()
    for _ in range(4):
        resp = await client.get("/api")
        assert resp.status == 200
    elapsed = time.monotonic() - start

    # 2 burst + 2 throttled at 50/s ≈ 0.04s minimum wait.
    # Upper bound (0.5s) catches hangs or accidental double-sleeps
    # while staying generous enough for CI environments.
    assert 0.02 <= elapsed < 0.5


@pytest.mark.asyncio
async def test_rate_limit_middleware_per_domain(
    aiohttp_client: AiohttpClient,
) -> None:
    """Per-domain middleware should isolate buckets per host."""
    middleware = RateLimitMiddleware(rate=100.0, burst=1, per_domain=True)
    client = await aiohttp_client(_make_app(), middlewares=(middleware,))

    start = time.monotonic()
    # Same host, so they share a bucket — second request should wait
    resp1 = await client.get("/api")
    resp2 = await client.get("/api")
    elapsed = time.monotonic() - start

    assert resp1.status == 200
    assert resp2.status == 200
    # Upper bound catches unexpected delays without being flaky on CI
    assert 0.005 <= elapsed < 0.5


@pytest.mark.asyncio
async def test_rate_limit_middleware_respects_retry_after(
    aiohttp_client: AiohttpClient,
) -> None:
    """Middleware should sleep when server returns 429 + Retry-After."""
    call_count = 0

    async def rate_limited_handler(request: web.Request) -> web.Response:
        nonlocal call_count
        call_count += 1
        if call_count <= 1:
            return web.Response(
                status=429,
                headers={"Retry-After": "0.1"},
            )
        return web.Response(text="OK")

    app = web.Application()
    app.router.add_get("/api", rate_limited_handler)

    middleware = RateLimitMiddleware(rate=100.0, burst=10, respect_retry_after=True)
    client = await aiohttp_client(app, middlewares=(middleware,))

    start = time.monotonic()
    resp = await client.get("/api")
    elapsed = time.monotonic() - start

    assert resp.status == 429
    # Upper bound catches unexpected delays without being flaky on CI
    assert 0.08 <= elapsed < 0.5
