import asyncio
import unittest
from unittest import mock

from aiohttp import streams


class TestFlowControlStreamReader(unittest.TestCase):

    def setUp(self):
        self.stream = mock.Mock(paused=False)
        self.transp = self.stream.transport
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def _make_one(self, *args, **kwargs):
        return streams.FlowControlStreamReader(
            self.stream, limit=1, loop=self.loop, *args, **kwargs)

    def test_read(self):
        r = self._make_one()
        r._stream.paused = True
        r.feed_data(b'da', 2)
        res = self.loop.run_until_complete(r.read(1))
        self.assertEqual(res, b'd')
        self.assertTrue(self.transp.resume_reading.called)

    def test_readline(self):
        r = self._make_one()
        r._stream.paused = True
        r.feed_data(b'data\n', 5)
        res = self.loop.run_until_complete(r.readline())
        self.assertEqual(res, b'data\n')
        self.assertTrue(self.transp.resume_reading.called)

    def test_readany(self):
        r = self._make_one()
        r._stream.paused = True
        r.feed_data(b'data', 4)
        res = self.loop.run_until_complete(r.readany())
        self.assertEqual(res, b'data')
        self.assertTrue(self.transp.resume_reading.called)

    def test_readexactly(self):
        r = self._make_one()
        r._stream.paused = True
        r.feed_data(b'data', 4)
        res = self.loop.run_until_complete(r.readexactly(3))
        self.assertEqual(res, b'dat')
        self.assertTrue(self.transp.resume_reading.called)

    def test_feed_data(self):
        r = self._make_one()
        r._stream.paused = False
        r.feed_data(b'datadata', 8)
        self.assertTrue(self.transp.pause_reading.called)

    def test_read_nowait(self):
        r = self._make_one()
        r._stream.paused = False
        r.feed_data(b'data1', 5)
        r.feed_data(b'data2', 5)
        r.feed_data(b'data3', 5)
        self.assertTrue(self.stream.paused)

        res = self.loop.run_until_complete(r.read(5))
        self.assertTrue(res == b'data1')
        # _buffer_size > _buffer_limit
        self.assertTrue(self.transp.pause_reading.call_count == 1)
        self.assertTrue(self.transp.resume_reading.call_count == 0)
        self.assertTrue(self.stream.paused)

        r._stream.paused = False
        res = r.read_nowait(5)
        self.assertTrue(res == b'data2')
        # _buffer_size > _buffer_limit
        self.assertTrue(self.transp.pause_reading.call_count == 2)
        self.assertTrue(self.transp.resume_reading.call_count == 0)
        self.assertTrue(self.stream.paused)

        res = r.read_nowait(5)
        self.assertTrue(res == b'data3')
        # _buffer_size < _buffer_limit
        self.assertTrue(self.transp.pause_reading.call_count == 2)
        self.assertTrue(self.transp.resume_reading.call_count == 1)
        self.assertTrue(not self.stream.paused)

        res = r.read_nowait(5)
        self.assertTrue(res == b'')
        # _buffer_size < _buffer_limit
        self.assertTrue(self.transp.pause_reading.call_count == 2)
        self.assertTrue(self.transp.resume_reading.call_count == 1)
        self.assertTrue(not self.stream.paused)

    def test_rudimentary_transport(self):
        self.transp.resume_reading.side_effect = NotImplementedError()
        self.transp.pause_reading.side_effect = NotImplementedError()
        self.stream.paused = True

        r = self._make_one()
        self.assertTrue(self.transp.pause_reading.call_count == 0)
        self.assertTrue(self.transp.resume_reading.call_count == 1)
        self.assertTrue(self.stream.paused)

        r.feed_data(b'data', 4)
        res = self.loop.run_until_complete(r.read(4))
        self.assertTrue(self.transp.pause_reading.call_count == 0)
        self.assertTrue(self.transp.resume_reading.call_count == 2)
        self.assertTrue(self.stream.paused)
        self.assertTrue(res == b'data')

        self.stream.paused = False
        r.feed_data(b'data', 4)
        res = self.loop.run_until_complete(r.read(1))
        self.assertTrue(self.transp.pause_reading.call_count == 2)
        self.assertTrue(self.transp.resume_reading.call_count == 2)
        self.assertTrue(not self.stream.paused)
        self.assertTrue(res == b'd')


class FlowControlMixin:

    def test_resume_on_init(self):
        stream = mock.Mock()
        stream.paused = True

        streams.FlowControlDataQueue(stream, limit=1, loop=self.loop)
        self.assertTrue(stream.transport.resume_reading.called)
        self.assertFalse(stream.paused)

    def test_no_transport_in_init(self):
        stream = mock.Mock()
        stream.paused = True
        stream.transport = None

        streams.FlowControlDataQueue(stream, limit=1, loop=self.loop)
        self.assertTrue(stream.paused)

    def test_feed_no_waiter(self):
        out = self._make_one()
        out.feed_data(object(), 100)

        self.assertTrue(self.stream.transport.pause_reading.called)

    def test_feed_no_transport(self):
        self.stream.transport = None

        out = self._make_one()
        self.stream.paused = False
        out.feed_data(object(), 100)

        self.assertFalse(self.stream.paused)

    def test_feed_with_waiter(self):
        self.stream.paused = False

        out = self._make_one()
        read_task = asyncio.Task(out.read(), loop=self.loop)

        def cb():
            out.feed_data(object(), 100)
        self.loop.call_soon(cb)
        self.loop.run_until_complete(read_task)

        self.assertFalse(self.stream.transport.pause_reading.called)
        self.assertFalse(self.stream.paused)

    def test_resume_on_read(self):
        out = self._make_one()
        out.feed_data(object(), 100)
        self.assertTrue(self.stream.paused)

        self.loop.run_until_complete(out.read())

        self.assertTrue(self.stream.transport.resume_reading.called)
        self.assertFalse(self.stream.paused)

    def test_resume_on_read_no_transport(self):
        item = object()

        out = self._make_one()
        out.feed_data(item, 100)
        self.assertTrue(self.stream.paused)

        self.stream.transport = None
        res = self.loop.run_until_complete(out.read())

        self.assertIs(res, item)
        self.assertTrue(self.stream.paused)

    def test_no_resume_on_read(self):
        out = self._make_one()
        out.feed_data(object(), 100)
        out.feed_data(object(), 100)
        out.feed_data(object(), 100)
        self.assertTrue(self.stream.paused)
        self.stream.transport.reset_mock()

        self.loop.run_until_complete(out.read())

        self.assertFalse(self.stream.transport.resume_reading.called)
        self.assertTrue(self.stream.paused)

    def test_pause_on_read(self):
        out = self._make_one()
        out._buffer.append((object(), 100))
        out._buffer.append((object(), 100))
        out._buffer.append((object(), 100))
        out._size = 300
        self.stream.paused = False

        self.loop.run_until_complete(out.read())

        self.assertTrue(self.stream.transport.pause_reading.called)
        self.assertTrue(self.stream.paused)

    def test_no_pause_on_read(self):
        item = object()

        out = self._make_one()
        out._buffer.append((item, 100))
        out._size = 100
        self.stream.paused = False

        res = self.loop.run_until_complete(out.read())

        self.assertIs(res, item)
        self.assertFalse(self.stream.transport.pause_reading.called)
        self.assertFalse(self.stream.paused)

    def test_no_pause_on_read_no_transport(self):
        item = object()

        out = self._make_one()
        out._buffer.append((item, 100))
        out._buffer.append((object(), 100))
        out._buffer.append((object(), 100))
        out._size = 300
        self.stream.paused = False
        self.stream.transport = None

        res = self.loop.run_until_complete(out.read())
        self.assertIs(res, item)
        self.assertFalse(self.stream.paused)


class TestFlowControlDataQueue(unittest.TestCase, FlowControlMixin):

    def setUp(self):
        self.stream = mock.Mock()
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def _make_one(self, *args, **kwargs):
        return streams.FlowControlDataQueue(
            self.stream, limit=1, loop=self.loop, *args, **kwargs)


class TestFlowControlChunksQueue(unittest.TestCase, FlowControlMixin):

    def setUp(self):
        self.stream = mock.Mock()
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def _make_one(self, *args, **kwargs):
        return streams.FlowControlChunksQueue(
            self.stream, limit=1, loop=self.loop, *args, **kwargs)

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
