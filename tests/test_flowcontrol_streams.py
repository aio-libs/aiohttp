import asyncio
from unittest import mock

import pytest

from aiohttp import streams
from aiohttp.base_protocol import BaseProtocol


@pytest.fixture
def protocol() -> BaseProtocol:
    return mock.create_autospec(BaseProtocol, spec_set=True, instance=True, _reading_paused=False)  # type: ignore[no-any-return]


@pytest.fixture
def stream(
    loop: asyncio.AbstractEventLoop, protocol: BaseProtocol
) -> streams.StreamReader:
    return streams.StreamReader(protocol, limit=1, loop=loop)


@pytest.fixture
def buffer(
    loop: asyncio.AbstractEventLoop, protocol: BaseProtocol
) -> streams.FlowControlDataQueue[str]:
    return streams.FlowControlDataQueue[str](protocol, limit=1, loop=loop)


class TestFlowControlStreamReader:
    async def test_read(self, stream: streams.StreamReader) -> None:
        stream.feed_data(b"da")
        res = await stream.read(1)
        assert res == b"d"
        assert not stream._protocol.resume_reading.called  # type: ignore[attr-defined]

    async def test_read_resume_paused(self, stream: streams.StreamReader) -> None:
        stream.feed_data(b"test")
        stream._protocol._reading_paused = True

        res = await stream.read(1)
        assert res == b"t"
        assert stream._protocol.pause_reading.called  # type: ignore[attr-defined]

    async def test_readline(self, stream: streams.StreamReader) -> None:
        stream.feed_data(b"d\n")
        res = await stream.readline()
        assert res == b"d\n"
        assert not stream._protocol.resume_reading.called  # type: ignore[attr-defined]

    async def test_readline_resume_paused(self, stream: streams.StreamReader) -> None:
        stream._protocol._reading_paused = True
        stream.feed_data(b"d\n")
        res = await stream.readline()
        assert res == b"d\n"
        assert stream._protocol.resume_reading.called  # type: ignore[attr-defined]

    async def test_readany(self, stream: streams.StreamReader) -> None:
        stream.feed_data(b"data")
        res = await stream.readany()
        assert res == b"data"
        assert not stream._protocol.resume_reading.called  # type: ignore[attr-defined]

    async def test_readany_resume_paused(self, stream: streams.StreamReader) -> None:
        stream._protocol._reading_paused = True
        stream.feed_data(b"data")
        res = await stream.readany()
        assert res == b"data"
        assert stream._protocol.resume_reading.called  # type: ignore[attr-defined]

    async def test_readchunk(self, stream: streams.StreamReader) -> None:
        stream.feed_data(b"data")
        res, end_of_http_chunk = await stream.readchunk()
        assert res == b"data"
        assert not end_of_http_chunk
        assert not stream._protocol.resume_reading.called  # type: ignore[attr-defined]

    async def test_readchunk_resume_paused(self, stream: streams.StreamReader) -> None:
        stream._protocol._reading_paused = True
        stream.feed_data(b"data")
        res, end_of_http_chunk = await stream.readchunk()
        assert res == b"data"
        assert not end_of_http_chunk
        assert stream._protocol.resume_reading.called  # type: ignore[attr-defined]

    async def test_readexactly(self, stream: streams.StreamReader) -> None:
        stream.feed_data(b"data")
        res = await stream.readexactly(3)
        assert res == b"dat"
        assert not stream._protocol.resume_reading.called  # type: ignore[attr-defined]

    async def test_feed_data(self, stream: streams.StreamReader) -> None:
        stream._protocol._reading_paused = False
        stream.feed_data(b"datadata")
        assert stream._protocol.pause_reading.called  # type: ignore[attr-defined]

    async def test_read_nowait(self, stream: streams.StreamReader) -> None:
        stream._protocol._reading_paused = True
        stream.feed_data(b"data1")
        stream.feed_data(b"data2")
        stream.feed_data(b"data3")
        res = await stream.read(5)
        assert res == b"data1"
        assert stream._protocol.resume_reading.call_count == 0  # type: ignore[attr-defined]

        res = stream.read_nowait(5)
        assert res == b"data2"
        assert stream._protocol.resume_reading.call_count == 0  # type: ignore[attr-defined]

        res = stream.read_nowait(5)
        assert res == b"data3"
        assert stream._protocol.resume_reading.call_count == 1  # type: ignore[attr-defined]

        stream._protocol._reading_paused = False
        res = stream.read_nowait(5)
        assert res == b""
        assert stream._protocol.resume_reading.call_count == 1  # type: ignore[attr-defined]


class TestFlowControlDataQueue:
    def test_feed_pause(self, buffer: streams.FlowControlDataQueue[str]) -> None:
        buffer._protocol._reading_paused = False
        buffer.feed_data("x" * 100)

        assert buffer._protocol.pause_reading.called  # type: ignore[attr-defined]

    async def test_resume_on_read(
        self, buffer: streams.FlowControlDataQueue[str]
    ) -> None:
        buffer.feed_data("x" * 100)

        buffer._protocol._reading_paused = True
        await buffer.read()
        assert buffer._protocol.resume_reading.called  # type: ignore[attr-defined]
