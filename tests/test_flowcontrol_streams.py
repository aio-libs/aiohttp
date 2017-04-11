import asyncio
import unittest
from unittest import mock

from aiohttp import streams


class TestFlowControlStreamReader(unittest.TestCase):

    def setUp(self):
        self.protocol = mock.Mock(_reading_paused=False)
        self.transp = self.protocol.transport
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def _make_one(self, allow_pause=True, *args, **kwargs):
        out = streams.FlowControlStreamReader(
            self.protocol, buffer_limit=1, loop=self.loop, *args, **kwargs)
        out._allow_pause = allow_pause
        return out

    def test_read(self):
        r = self._make_one()
        r.feed_data(b'da', 2)
        res = self.loop.run_until_complete(r.read(1))
        self.assertEqual(res, b'd')
        self.assertFalse(r._protocol.resume_reading.called)

    def test_read_resume_paused(self):
        r = self._make_one()
        r.feed_data(b'test', 4)
        r._protocol._reading_paused = True

        res = self.loop.run_until_complete(r.read(1))
        self.assertEqual(res, b't')
        self.assertTrue(r._protocol.pause_reading.called)

    def test_readline(self):
        r = self._make_one()
        r.feed_data(b'data\n', 5)
        res = self.loop.run_until_complete(r.readline())
        self.assertEqual(res, b'data\n')
        self.assertFalse(r._protocol.resume_reading.called)

    def test_readline_resume_paused(self):
        r = self._make_one()
        r._protocol._reading_paused = True
        r.feed_data(b'data\n', 5)
        res = self.loop.run_until_complete(r.readline())
        self.assertEqual(res, b'data\n')
        self.assertTrue(r._protocol.resume_reading.called)

    def test_readany(self):
        r = self._make_one()
        r.feed_data(b'data', 4)
        res = self.loop.run_until_complete(r.readany())
        self.assertEqual(res, b'data')
        self.assertFalse(r._protocol.resume_reading.called)

    def test_readany_resume_paused(self):
        r = self._make_one()
        r._protocol._reading_paused = True
        r.feed_data(b'data', 4)
        res = self.loop.run_until_complete(r.readany())
        self.assertEqual(res, b'data')
        self.assertTrue(r._protocol.resume_reading.called)

    def test_readchunk(self):
        r = self._make_one()
        r.feed_data(b'data', 4)
        res = self.loop.run_until_complete(r.readchunk())
        self.assertEqual(res, b'data')
        self.assertFalse(r._protocol.resume_reading.called)

    def test_readchunk_resume_paused(self):
        r = self._make_one()
        r._protocol._reading_paused = True
        r.feed_data(b'data', 4)
        res = self.loop.run_until_complete(r.readchunk())
        self.assertEqual(res, b'data')
        self.assertTrue(r._protocol.resume_reading.called)

    def test_readexactly(self):
        r = self._make_one()
        r.feed_data(b'data', 4)
        res = self.loop.run_until_complete(r.readexactly(3))
        self.assertEqual(res, b'dat')
        self.assertFalse(r._protocol.resume_reading.called)

    def test_readexactly_resume_paused(self):
        r = self._make_one()
        r._protocol._reading_paused = True
        r.feed_data(b'data', 4)
        res = self.loop.run_until_complete(r.readexactly(3))
        self.assertEqual(res, b'dat')
        self.assertTrue(r._protocol.resume_reading.called)

    def test_feed_data(self):
        r = self._make_one()
        r._protocol._reading_paused = False
        r.feed_data(b'datadata', 8)
        self.assertTrue(r._protocol.pause_reading.called)

    def test_read_nowait(self):
        r = self._make_one()
        r._protocol._reading_paused = True
        r.feed_data(b'data1', 5)
        r.feed_data(b'data2', 5)
        r.feed_data(b'data3', 5)
        res = self.loop.run_until_complete(r.read(5))
        self.assertTrue(res == b'data1')
        self.assertTrue(r._protocol.resume_reading.call_count == 0)

        res = r.read_nowait(5)
        self.assertTrue(res == b'data2')
        self.assertTrue(r._protocol.resume_reading.call_count == 0)

        res = r.read_nowait(5)
        self.assertTrue(res == b'data3')
        self.assertTrue(r._protocol.resume_reading.call_count == 1)

        r._protocol._reading_paused = False
        res = r.read_nowait(5)
        self.assertTrue(res == b'')
        self.assertTrue(r._protocol.resume_reading.call_count == 1)


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


class TestFlowControlChunksQueue(unittest.TestCase, FlowControlMixin):

    def setUp(self):
        self.protocol = mock.Mock()
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def _make_one(self, *args, **kwargs):
        out = streams.FlowControlChunksQueue(
            self.protocol, limit=1, loop=self.loop, *args, **kwargs)
        out._allow_pause = True
        return out

    def test_read_eof(self):
        out = self._make_one()
        read_task = asyncio.Task(out.read(), loop=self.loop)

        def cb():
            out.feed_eof()
        self.loop.call_soon(cb)

        self.loop.run_until_complete(read_task)
        self.assertTrue(out.at_eof())

    def test_read_until_eof(self):
        item = object()

        out = self._make_one()
        out.feed_data(item, 1)
        out.feed_eof()

        data = self.loop.run_until_complete(out.read())
        self.assertIs(data, item)

        thing = self.loop.run_until_complete(out.read())
        self.assertEqual(thing, b'')
        self.assertTrue(out.at_eof())

    def test_readany(self):
        out = self._make_one()
        self.assertIs(out.read.__func__, out.readany.__func__)
