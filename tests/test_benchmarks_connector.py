"""codspeed benchmarks for connector waiter scheduling."""

import asyncio
from collections import OrderedDict
from typing import TYPE_CHECKING

import pytest

import aiohttp
from aiohttp.client_reqrep import ConnectionKey

if TYPE_CHECKING:
    from pytest_codspeed import BenchmarkFixture
else:
    pytest_codspeed = pytest.importorskip("pytest_codspeed")
    BenchmarkFixture = pytest_codspeed.BenchmarkFixture


@pytest.mark.parametrize("host_count", (400, 800, 1600))
def test_release_waiters_across_distinct_hosts(
    event_loop: asyncio.AbstractEventLoop,
    benchmark: BenchmarkFixture,
    host_count: int,
) -> None:
    async def drain_waiters() -> None:
        connector = aiohttp.BaseConnector(limit=0)
        for index in range(host_count):
            key = ConnectionKey(f"host-{index}", 80, False, True, None, None)
            waiter = event_loop.create_future()
            connector._waiters.setdefault(key, OrderedDict())[waiter] = None

        for _ in range(host_count):
            connector._release_waiter()

        await connector.close()

    @benchmark
    def _run() -> None:
        event_loop.run_until_complete(drain_waiters())
