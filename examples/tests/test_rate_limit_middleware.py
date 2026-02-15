"""
Tests for the rate_limit_middleware.py example.

Run with:
    pytest examples/tests/test_rate_limit_middleware.py -v
"""

import asyncio
import time
from unittest.mock import AsyncMock

import pytest
from rate_limit_middleware import RateLimitMiddleware, TokenBucket


@pytest.mark.asyncio
async def test_token_bucket_allows_burst() -> None:
    """Tokens up to burst size should be available immediately."""
    bucket = TokenBucket(rate=10.0, burst=3)
    for _ in range(3):
        await bucket.acquire()
    assert bucket.tokens < 1


@pytest.mark.asyncio
async def test_token_bucket_refills_over_time() -> None:
    """After draining, bucket should refill based on rate."""
    bucket = TokenBucket(rate=100.0, burst=1)
    await bucket.acquire()
    await asyncio.sleep(0.05)
    # After 50ms at rate=100/s, ~5 tokens should have been added
    await bucket.acquire()


@pytest.mark.asyncio
async def test_rate_limit_middleware_global() -> None:
    """Global middleware should throttle sequential requests."""
    middleware = RateLimitMiddleware(rate=50.0, burst=2)

    fake_response = AsyncMock()
    fake_response.status = 200
    fake_response.headers = {}
    handler = AsyncMock(return_value=fake_response)
    fake_request = AsyncMock()
    fake_request.url.host = "example.com"

    start = time.monotonic()
    for _ in range(4):
        await middleware(fake_request, handler)
    elapsed = time.monotonic() - start

    assert handler.call_count == 4
    # 2 burst + 2 throttled at 50/s ≈ 0.04s minimum wait
    assert elapsed >= 0.02


@pytest.mark.asyncio
async def test_rate_limit_middleware_per_domain() -> None:
    """Per-domain middleware should isolate buckets per host."""
    middleware = RateLimitMiddleware(rate=100.0, burst=1, per_domain=True)

    fake_response = AsyncMock()
    fake_response.status = 200
    fake_response.headers = {}
    handler = AsyncMock(return_value=fake_response)

    req_a = AsyncMock()
    req_a.url.host = "domain-a.com"
    req_b = AsyncMock()
    req_b.url.host = "domain-b.com"

    # Both domains should have independent burst allowance
    await middleware(req_a, handler)
    await middleware(req_b, handler)
    assert handler.call_count == 2


@pytest.mark.asyncio
async def test_rate_limit_middleware_respects_retry_after() -> None:
    """Middleware should sleep when server returns 429 + Retry-After."""
    middleware = RateLimitMiddleware(rate=100.0, burst=10, respect_retry_after=True)

    fake_response = AsyncMock()
    fake_response.status = 429
    fake_response.headers = {"Retry-After": "0.1"}
    handler = AsyncMock(return_value=fake_response)
    fake_request = AsyncMock()
    fake_request.url.host = "example.com"

    start = time.monotonic()
    await middleware(fake_request, handler)
    elapsed = time.monotonic() - start

    assert elapsed >= 0.08  # Allow small timing variance
