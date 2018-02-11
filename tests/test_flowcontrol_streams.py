import asyncio
import unittest
from unittest import mock

import pytest

from aiohttp import streams


@pytest.fixture
def protocol():
    return mock.Mock(_reading_paused=False)


@pytest.fixture
def stream(loop, protocol):
    out = streams.StreamReader(protocol, limit=1, loop=loop)
    out._allow_pause = True
    return out


class TestFlowControlStreamReader:

    async def test_read(self, stream):
        stream.feed_data(b'da', 2)
        res = await stream.read(1)
        assert res == b'd'
        assert not stream._protocol.resume_reading.called

    async def test_read_resume_paused(self, stream):
        stream.feed_data(b'test', 4)
        stream._protocol._reading_paused = True

        res = await stream.read(1)
        assert res == b't'
        assert stream._protocol.pause_reading.called

    async def test_readline(self, stream):
        stream.feed_data(b'd\n', 5)
        res = await stream.readline()
        assert res == b'd\n'
        assert not stream._protocol.resume_reading.called

    async def test_readline_resume_paused(self, stream):
        stream._protocol._reading_paused = True
        stream.feed_data(b'd\n', 5)
        res = await stream.readline()
        assert res == b'd\n'
        assert stream._protocol.resume_reading.called

    async def test_readany(self, stream):
        stream.feed_data(b'data', 4)
        res = await stream.readany()
        assert res == b'data'
        assert not stream._protocol.resume_reading.called

    async def test_readany_resume_paused(self, stream):
        stream._protocol._reading_paused = True
        stream.feed_data(b'data', 4)
        res = await stream.readany()
        assert res == b'data'
        assert stream._protocol.resume_reading.called

    async def test_readchunk(self, stream):
        stream.feed_data(b'data', 4)
        res, end_of_http_chunk = await stream.readchunk()
        assert res == b'data'
        assert not end_of_http_chunk
        assert not stream._protocol.resume_reading.called

    async def test_readchunk_resume_paused(self, stream):
        stream._protocol._reading_paused = True
        stream.feed_data(b'data', 4)
        res, end_of_http_chunk = await stream.readchunk()
        assert res == b'data'
        assert not end_of_http_chunk
        assert stream._protocol.resume_reading.called

    async def test_readexactly(self, stream):
        stream.feed_data(b'data', 4)
        res = await stream.readexactly(3)
        assert res == b'dat'
        assert not stream._protocol.resume_reading.called

    async def test_feed_data(self, stream):
        stream._protocol._reading_paused = False
        stream.feed_data(b'datadata', 8)
        assert stream._protocol.pause_reading.called

    async def test_read_nowait(self, stream):
        stream._protocol._reading_paused = True
        stream.feed_data(b'data1', 5)
        stream.feed_data(b'data2', 5)
        stream.feed_data(b'data3', 5)
        res = await stream.read(5)
        assert res == b'data1'
        assert stream._protocol.resume_reading.call_count == 0

        res = stream.read_nowait(5)
        assert res == b'data2'
        assert stream._protocol.resume_reading.call_count == 0

        res = stream.read_nowait(5)
        assert res == b'data3'
        assert stream._protocol.resume_reading.call_count == 1

        stream._protocol._reading_paused = False
        res = stream.read_nowait(5)
        assert res == b''
        assert stream._protocol.resume_reading.call_count == 1


class FlowControlMixin:

    def test_feed_pause(self):
        out = self._make_one()
        out._protocol._reading_paused = False
        out.feed_data(object(), 100)

        self.assertTrue(out._protocol.pause_reading.called)

    def test_resume_on_read(self):
        out = self._make_one()
        out.feed_data(object(), 100)

        out._protocol._reading_paused = True
        self.loop.run_until_complete(out.read())
        self.assertTrue(out._protocol.resume_reading.called)


class TestFlowControlDataQueue(unittest.TestCase, FlowControlMixin):

    def setUp(self):
        self.protocol = mock.Mock()
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def _make_one(self, *args, **kwargs):
        out = streams.FlowControlDataQueue(
            self.protocol, limit=1, loop=self.loop, *args, **kwargs)
        out._allow_pause = True
        return out
