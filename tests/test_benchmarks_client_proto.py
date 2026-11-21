"""codspeed benchmarks for client protocol timeout scheduling."""

import asyncio
from typing import TYPE_CHECKING

import pytest

from aiohttp.client_proto import ResponseHandler

if TYPE_CHECKING:
    from pytest_codspeed import BenchmarkFixture
else:
    pytest_codspeed = pytest.importorskip("pytest_codspeed")
    BenchmarkFixture = pytest_codspeed.BenchmarkFixture


RECEIVES = 10_000


def test_read_timeout_schedule_per_receive(
    event_loop: asyncio.AbstractEventLoop, benchmark: BenchmarkFixture
) -> None:
    """Measure the former cancel-and-schedule path over repeated receives."""
    proto = ResponseHandler(loop=event_loop)

    def run() -> None:
        handle = event_loop.call_later(30, proto._on_read_timeout)
        for _ in range(1, RECEIVES):
            handle.cancel()
            handle = event_loop.call_later(30, proto._on_read_timeout)
        handle.cancel()

    def drain_cancelled_timers() -> None:
        event_loop.run_until_complete(asyncio.sleep(0))

    benchmark.pedantic(
        run, setup=drain_cancelled_timers, teardown=drain_cancelled_timers
    )


def test_read_timeout_reused_schedule(
    event_loop: asyncio.AbstractEventLoop, benchmark: BenchmarkFixture
) -> None:
    """Measure repeated deadline refreshes with one retained timer handle."""
    proto = ResponseHandler(loop=event_loop)
    proto.set_response_params(read_timeout=30)

    def run() -> None:
        proto.start_timeout()
        for _ in range(RECEIVES):
            proto._reschedule_timeout()
        proto._drop_timeout()

    def drain_cancelled_timers() -> None:
        event_loop.run_until_complete(asyncio.sleep(0))

    benchmark.pedantic(
        run,
        setup=drain_cancelled_timers,
        teardown=drain_cancelled_timers,
    )
