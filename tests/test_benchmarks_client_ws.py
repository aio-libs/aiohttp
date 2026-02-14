"""codspeed benchmarks for websocket client."""

import asyncio
import time
from collections.abc import Callable
from unittest import mock

import pytest
from pytest_codspeed import BenchmarkFixture

from aiohttp import ClientWSTimeout, client, web
from aiohttp._websocket.helpers import MSG_SIZE
from aiohttp.pytest_plugin import AiohttpClient


def _make_client_ws(loop: asyncio.AbstractEventLoop) -> client.ClientWebSocketResponse:
    response = mock.Mock()
    response.connection = None
    return client.ClientWebSocketResponse(
        mock.Mock(),
        mock.Mock(),
        None,
        response,
        ClientWSTimeout(ws_receive=10.0),
        True,
        True,
        loop,
        heartbeat=0.05,
    )


def _drive_chunk_bursts(
    loop: asyncio.AbstractEventLoop,
    on_data_received: Callable[[], None],
    *,
    bursts: int,
    burst_size: int,
) -> None:
    for _ in range(bursts):
        for _ in range(burst_size):
            on_data_received()
        loop.run_until_complete(asyncio.sleep(0))


def _measure_chunk_cost(
    loop: asyncio.AbstractEventLoop,
    on_data_received: Callable[[], None],
    *,
    bursts: int,
    burst_size: int,
    min_seconds: float,
) -> tuple[float, int]:
    start = time.perf_counter()
    chunk_calls = 0
    while True:
        _drive_chunk_bursts(
            loop, on_data_received, bursts=bursts, burst_size=burst_size
        )
        chunk_calls += bursts * burst_size
        if time.perf_counter() - start >= min_seconds:
            break
    elapsed = time.perf_counter() - start
    return elapsed, chunk_calls


@pytest.mark.internal  # Local machine comparison, not intended as CI signal.
@pytest.mark.dev_mode  # Off by default; run explicitly for local perf checks.
def test_heartbeat_reset_coalesced_vs_immediate(
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Measure coalesced vs immediate heartbeat reset cost on one machine."""
    bursts = 200
    burst_size = 64
    min_seconds_per_strategy = 2.0

    ws_coalesced = _make_client_ws(loop)
    ws_immediate = _make_client_ws(loop)

    def immediate_on_data_received() -> None:
        if ws_immediate._heartbeat is None:
            return
        ws_immediate._reset_heartbeat()

    # Warm up both paths before timing to reduce one-time effects.
    _drive_chunk_bursts(
        loop, ws_coalesced._on_data_received, bursts=bursts, burst_size=burst_size
    )
    _drive_chunk_bursts(
        loop, immediate_on_data_received, bursts=bursts, burst_size=burst_size
    )

    coalesced_elapsed, coalesced_calls = _measure_chunk_cost(
        loop,
        ws_coalesced._on_data_received,
        bursts=bursts,
        burst_size=burst_size,
        min_seconds=min_seconds_per_strategy,
    )
    immediate_elapsed, immediate_calls = _measure_chunk_cost(
        loop,
        immediate_on_data_received,
        bursts=bursts,
        burst_size=burst_size,
        min_seconds=min_seconds_per_strategy,
    )

    coalesced_ns_per_call = (coalesced_elapsed / coalesced_calls) * 1e9
    immediate_ns_per_call = (immediate_elapsed / immediate_calls) * 1e9
    speedup_ratio = immediate_ns_per_call / coalesced_ns_per_call

    # For review replies, report these numbers from a local run on the same
    # machine. speedup_ratio > 1 means coalescing is faster.
    print(
        "heartbeat reset benchmark: "
        f"coalesced={coalesced_ns_per_call:.1f}ns/call, "
        f"immediate={immediate_ns_per_call:.1f}ns/call, "
        f"speedup={speedup_ratio:.2f}x"
    )


def test_one_thousand_round_trip_websocket_text_messages(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark round trip of 1000 WebSocket text messages."""
    message_count = 1000

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        for _ in range(message_count):
            await ws.send_str("answer")
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    async def run_websocket_benchmark() -> None:
        client = await aiohttp_client(app)
        resp = await client.ws_connect("/")
        for _ in range(message_count):
            await resp.receive()
        await resp.close()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_websocket_benchmark())


@pytest.mark.parametrize("msg_size", [6, MSG_SIZE * 4], ids=["small", "large"])
def test_one_thousand_round_trip_websocket_binary_messages(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
    msg_size: int,
) -> None:
    """Benchmark round trip of 1000 WebSocket binary messages."""
    message_count = 1000
    raw_message = b"x" * msg_size

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        for _ in range(message_count):
            await ws.send_bytes(raw_message)
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    async def run_websocket_benchmark() -> None:
        client = await aiohttp_client(app)
        resp = await client.ws_connect("/")
        for _ in range(message_count):
            await resp.receive()
        await resp.close()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_websocket_benchmark())


def test_one_thousand_large_round_trip_websocket_text_messages(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark round trip of 100 large WebSocket text messages."""
    message_count = 100
    raw_message = "x" * MSG_SIZE * 4

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        for _ in range(message_count):
            await ws.send_str(raw_message)
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    async def run_websocket_benchmark() -> None:
        client = await aiohttp_client(app)
        resp = await client.ws_connect("/")
        for _ in range(message_count):
            await resp.receive()
        await resp.close()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_websocket_benchmark())


@pytest.mark.usefixtures("parametrize_zlib_backend")
def test_client_send_large_websocket_compressed_messages(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark send of compressed WebSocket binary messages."""
    message_count = 10
    raw_message = b"x" * 2**19  # 512 KiB

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        for _ in range(message_count):
            await ws.receive()
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    async def run_websocket_benchmark() -> None:
        client = await aiohttp_client(app)
        resp = await client.ws_connect("/", compress=15)
        for _ in range(message_count):
            await resp.send_bytes(raw_message)
        await resp.close()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_websocket_benchmark())


@pytest.mark.usefixtures("parametrize_zlib_backend")
def test_client_receive_large_websocket_compressed_messages(
    loop: asyncio.AbstractEventLoop,
    aiohttp_client: AiohttpClient,
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark receive of compressed WebSocket binary messages."""
    message_count = 10
    raw_message = b"x" * 2**19  # 512 KiB

    async def handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        for _ in range(message_count):
            await ws.send_bytes(raw_message)
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route("GET", "/", handler)

    async def run_websocket_benchmark() -> None:
        client = await aiohttp_client(app)
        resp = await client.ws_connect("/", compress=15)
        for _ in range(message_count):
            await resp.receive()
        await resp.close()

    @benchmark
    def _run() -> None:
        loop.run_until_complete(run_websocket_benchmark())
