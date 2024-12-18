import asyncio
from unittest import mock

import pytest

from aiohttp import streams
from aiohttp.base_protocol import BaseProtocol


@pytest.fixture
def protocol():
    return mock.Mock(_reading_paused=False)


@pytest.fixture
def stream(loop, protocol):
    return streams.StreamReader(protocol, limit=1, loop=loop)


@pytest.fixture
def buffer(loop, protocol: mock.Mock) -> streams.FlowControlDataQueue:
    out = streams.FlowControlDataQueue(protocol, limit=1, loop=loop)
    out._allow_pause = True
    return out


class TestFlowControlStreamReader:
    async def test_read(self, stream) -> None:
        stream.feed_data(b"da", 2)
        res = await stream.read(1)
        assert res == b"d"
        assert not stream._protocol.resume_reading.called

    async def test_read_resume_paused(self, stream) -> None:
        stream.feed_data(b"test", 4)
        stream._protocol._reading_paused = True

        res = await stream.read(1)
        assert res == b"t"
        assert stream._protocol.pause_reading.called

    async def test_readline(self, stream) -> None:
        stream.feed_data(b"d\n", 5)
        res = await stream.readline()
        assert res == b"d\n"
        assert not stream._protocol.resume_reading.called

    async def test_readline_resume_paused(self, stream) -> None:
        stream._protocol._reading_paused = True
        stream.feed_data(b"d\n", 5)
        res = await stream.readline()
        assert res == b"d\n"
        assert stream._protocol.resume_reading.called

    async def test_readany(self, stream) -> None:
        stream.feed_data(b"data", 4)
        res = await stream.readany()
        assert res == b"data"
        assert not stream._protocol.resume_reading.called

    async def test_readany_resume_paused(self, stream) -> None:
        stream._protocol._reading_paused = True
        stream.feed_data(b"data", 4)
        res = await stream.readany()
        assert res == b"data"
        assert stream._protocol.resume_reading.called

    async def test_readchunk(self, stream) -> None:
        stream.feed_data(b"data", 4)
        res, end_of_http_chunk = await stream.readchunk()
        assert res == b"data"
        assert not end_of_http_chunk
        assert not stream._protocol.resume_reading.called

    async def test_readchunk_resume_paused(self, stream) -> None:
        stream._protocol._reading_paused = True
        stream.feed_data(b"data", 4)
        res, end_of_http_chunk = await stream.readchunk()
        assert res == b"data"
        assert not end_of_http_chunk
        assert stream._protocol.resume_reading.called

    async def test_readexactly(self, stream) -> None:
        stream.feed_data(b"data", 4)
        res = await stream.readexactly(3)
        assert res == b"dat"
        assert not stream._protocol.resume_reading.called

    async def test_feed_data(self, stream) -> None:
        stream._protocol._reading_paused = False
        stream.feed_data(b"datadata", 8)
        assert stream._protocol.pause_reading.called

    async def test_read_nowait(self, stream) -> None:
        stream._protocol._reading_paused = True
        stream.feed_data(b"data1", 5)
        stream.feed_data(b"data2", 5)
        stream.feed_data(b"data3", 5)
        res = await stream.read(5)
        assert res == b"data1"
        assert stream._protocol.resume_reading.call_count == 0

        res = stream.read_nowait(5)
        assert res == b"data2"
        assert stream._protocol.resume_reading.call_count == 0

        res = stream.read_nowait(5)
        assert res == b"data3"
        assert stream._protocol.resume_reading.call_count == 1

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


async def test_flow_control_data_queue_waiter_cancelled(
    buffer: streams.FlowControlDataQueue,
) -> None:
    """Test that the waiter is cancelled it is cleared."""
    task = asyncio.create_task(buffer.read())
    await asyncio.sleep(0)
    assert buffer._waiter is not None
    buffer._waiter.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task
    assert buffer._waiter is None


async def test_flow_control_data_queue_has_buffer(
    buffer: streams.FlowControlDataQueue,
) -> None:
    """Test reading from the buffer."""
    data = object()
    buffer.feed_data(data, 100)
    assert buffer._size == 100
    read_data = await buffer.read()
    assert read_data is data
    assert buffer._size == 0


async def test_flow_control_data_queue_read_with_exception(
    buffer: streams.FlowControlDataQueue,
) -> None:
    """Test reading when the buffer is empty and an exception is set."""
    buffer.set_exception(ValueError("unique_string"))
    with pytest.raises(ValueError, match="unique_string"):
        await buffer.read()


def test_flow_control_data_queue_feed_pause(
    buffer: streams.FlowControlDataQueue,
) -> None:
    """Test feeding data and pausing the reader."""
    buffer._protocol._reading_paused = False
    buffer.feed_data(object(), 100)
    assert buffer._protocol.pause_reading.called

    buffer._protocol._reading_paused = True
    buffer._protocol.pause_reading.reset_mock()
    buffer.feed_data(object(), 100)
    assert not buffer._protocol.pause_reading.called


async def test_flow_control_data_queue_resume_on_read(
    buffer: streams.FlowControlDataQueue,
) -> None:
    """Test that the reader is resumed when reading."""
    buffer.feed_data(object(), 100)

    buffer._protocol._reading_paused = True
    await buffer.read()
    assert buffer._protocol.resume_reading.called


async def test_flow_control_data_queue_read_eof(
    buffer: streams.FlowControlDataQueue,
) -> None:
    """Test that reading after eof raises EofStream."""
    buffer.feed_eof()
    with pytest.raises(streams.EofStream):
        await buffer.read()


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
