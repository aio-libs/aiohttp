"""codspeed benchmarks for http websocket."""

import asyncio

from pytest_codspeed import BenchmarkFixture  # type: ignore[import-untyped]

from aiohttp import DataQueue
from aiohttp.http_websocket import WebSocketReader, WSMessage


def test_read_one_hundred_websocket_text_messages(
    loop: asyncio.AbstractEventLoop, benchmark: BenchmarkFixture
) -> None:
    queue: DataQueue[WSMessage] = DataQueue()
    reader = WebSocketReader(queue, loop=loop)

    @benchmark
    def _run() -> None:
        reader.feed_data(b"81")
