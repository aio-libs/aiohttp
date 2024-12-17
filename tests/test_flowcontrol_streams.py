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

    async def test_resumed_on_eof(self, stream: streams.StreamReader) -> None:
        stream.feed_data(b"data")
        assert stream._protocol.pause_reading.call_count == 1  # type: ignore[attr-defined]
        assert stream._protocol.resume_reading.call_count == 0  # type: ignore[attr-defined]
        stream._protocol._reading_paused = True

        stream.feed_eof()
        assert stream._protocol.resume_reading.call_count == 1  # type: ignore[attr-defined]


async def test_stream_reader_eof_when_full() -> None:
    loop = asyncio.get_event_loop()
    protocol = BaseProtocol(loop=loop)
    protocol.transport = asyncio.Transport()
    stream = streams.StreamReader(protocol, 1024, loop=loop)

    data_len = stream._high_water + 1
    stream.feed_data(b"0" * data_len)
    assert protocol._reading_paused
    stream.feed_eof()
    assert not protocol._reading_paused
