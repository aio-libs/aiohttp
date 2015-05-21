"""Tests for streams.py"""

import asyncio
import unittest
from unittest import mock

from aiohttp import streams
from aiohttp import test_utils


class TestStreamReader(unittest.TestCase):

    DATA = b'line1\nline2\nline3\n'

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def _make_one(self, *args, **kwargs):
        return streams.StreamReader(loop=self.loop, *args, **kwargs)

    def test_create_waiter(self):
        stream = self._make_one()
        stream._waiter = asyncio.Future(loop=self.loop)
        self.assertRaises(RuntimeError, stream._create_waiter, 'test')

    @mock.patch('aiohttp.streams.asyncio')
    def test_ctor_global_loop(self, m_asyncio):
        stream = streams.StreamReader()
        self.assertIs(stream._loop, m_asyncio.get_event_loop.return_value)

    def test_at_eof(self):
        stream = self._make_one()
        self.assertFalse(stream.at_eof())

        stream.feed_data(b'some data\n')
        self.assertFalse(stream.at_eof())

        self.loop.run_until_complete(stream.readline())
        self.assertFalse(stream.at_eof())

        stream.feed_data(b'some data\n')
        stream.feed_eof()
        self.loop.run_until_complete(stream.readline())
        self.assertTrue(stream.at_eof())

    def test_wait_eof(self):
        stream = self._make_one()
        wait_task = asyncio.Task(stream.wait_eof(), loop=self.loop)

        def cb():
            yield from asyncio.sleep(0.1, loop=self.loop)
            stream.feed_eof()

        asyncio.Task(cb(), loop=self.loop)
        self.loop.run_until_complete(wait_task)
        self.assertTrue(stream.is_eof())
        self.assertIsNone(stream._eof_waiter)

    def test_wait_eof_eof(self):
        stream = self._make_one()
        stream.feed_eof()
        wait_task = asyncio.Task(stream.wait_eof(), loop=self.loop)
        self.loop.run_until_complete(wait_task)
        self.assertTrue(stream.is_eof())

    def test_feed_empty_data(self):
        stream = self._make_one()

        stream.feed_data(b'')
        self.assertEqual(b'', stream._buffer)

    def test_feed_nonempty_data(self):
        stream = self._make_one()

        stream.feed_data(self.DATA)
        self.assertEqual(self.DATA, stream._buffer)

    def test_read_zero(self):
        # Read zero bytes.
        stream = self._make_one()
        stream.feed_data(self.DATA)

        data = self.loop.run_until_complete(stream.read(0))
        self.assertEqual(b'', data)
        self.assertEqual(self.DATA, stream._buffer)

    def test_read(self):
        # Read bytes.
        stream = self._make_one()
        read_task = asyncio.Task(stream.read(30), loop=self.loop)

        def cb():
            stream.feed_data(self.DATA)
        self.loop.call_soon(cb)

        data = self.loop.run_until_complete(read_task)
        self.assertEqual(self.DATA, data)
        self.assertEqual(b'', stream._buffer)

    def test_read_line_breaks(self):
        # Read bytes without line breaks.
        stream = self._make_one()
        stream.feed_data(b'line1')
        stream.feed_data(b'line2')

        data = self.loop.run_until_complete(stream.read(5))

        self.assertEqual(b'line1', data)
        self.assertEqual(b'line2', stream._buffer)

    def test_read_eof(self):
        # Read bytes, stop at eof.
        stream = self._make_one()
        read_task = asyncio.Task(stream.read(1024), loop=self.loop)

        def cb():
            stream.feed_eof()
        self.loop.call_soon(cb)

        data = self.loop.run_until_complete(read_task)
        self.assertEqual(b'', data)
        self.assertEqual(b'', stream._buffer)
        self.assertIs(data, streams.EOF_MARKER)

    @mock.patch('aiohttp.streams.internal_logger')
    def test_read_eof_infinit(self, internal_logger):
        # Read bytes.
        stream = self._make_one()
        stream.feed_eof()

        self.loop.run_until_complete(stream.read())
        self.loop.run_until_complete(stream.read())
        self.loop.run_until_complete(stream.read())
        self.loop.run_until_complete(stream.read())
        self.loop.run_until_complete(stream.read())
        self.loop.run_until_complete(stream.read())
        self.assertTrue(internal_logger.warning.called)

    def test_read_until_eof(self):
        # Read all bytes until eof.
        stream = self._make_one()
        read_task = asyncio.Task(stream.read(-1), loop=self.loop)

        def cb():
            stream.feed_data(b'chunk1\n')
            stream.feed_data(b'chunk2')
            stream.feed_eof()
        self.loop.call_soon(cb)

        data = self.loop.run_until_complete(read_task)

        self.assertEqual(b'chunk1\nchunk2', data)
        self.assertEqual(b'', stream._buffer)

    def test_read_exception(self):
        stream = self._make_one()
        stream.feed_data(b'line\n')

        data = self.loop.run_until_complete(stream.read(2))
        self.assertEqual(b'li', data)

        stream.set_exception(ValueError())
        self.assertRaises(
            ValueError, self.loop.run_until_complete, stream.read(2))

    def test_readline(self):
        # Read one line. 'readline' will need to wait for the data
        # to come from 'cb'
        stream = self._make_one()
        stream.feed_data(b'chunk1 ')
        read_task = asyncio.Task(stream.readline(), loop=self.loop)

        def cb():
            stream.feed_data(b'chunk2 ')
            stream.feed_data(b'chunk3 ')
            stream.feed_data(b'\n chunk4')
        self.loop.call_soon(cb)

        line = self.loop.run_until_complete(read_task)
        self.assertEqual(b'chunk1 chunk2 chunk3 \n', line)
        self.assertEqual(b' chunk4', stream._buffer)

    def test_readline_limit_with_existing_data(self):
        # Read one line. The data is in StreamReader's buffer
        # before the event loop is run.

        stream = self._make_one(limit=3)
        stream.feed_data(b'li')
        stream.feed_data(b'ne1\nline2\n')

        self.assertRaises(
            ValueError, self.loop.run_until_complete, stream.readline())
        # The buffer should contain the remaining data after exception
        self.assertEqual(b'line2\n', stream._buffer)

        stream = streams.StreamReader(limit=3, loop=self.loop)
        stream.feed_data(b'li')
        stream.feed_data(b'ne1')
        stream.feed_data(b'li')

        self.assertRaises(
            ValueError, self.loop.run_until_complete, stream.readline())
        # No b'\n' at the end. The 'limit' is set to 3. So before
        # waiting for the new data in buffer, 'readline' will consume
        # the entire buffer, and since the length of the consumed data
        # is more than 3, it will raise a ValueError. The buffer is
        # expected to be empty now.
        self.assertEqual(b'', stream._buffer)

    def test_readline_limit(self):
        # Read one line. StreamReaders are fed with data after
        # their 'readline' methods are called.

        stream = self._make_one(limit=7)

        def cb():
            stream.feed_data(b'chunk1')
            stream.feed_data(b'chunk2')
            stream.feed_data(b'chunk3\n')
            stream.feed_eof()
        self.loop.call_soon(cb)

        self.assertRaises(
            ValueError, self.loop.run_until_complete, stream.readline())
        # The buffer had just one line of data, and after raising
        # a ValueError it should be empty.
        self.assertEqual(b'', stream._buffer)

        stream = self._make_one(limit=7)

        def cb():
            stream.feed_data(b'chunk1')
            stream.feed_data(b'chunk2\n')
            stream.feed_data(b'chunk3\n')
            stream.feed_eof()
        self.loop.call_soon(cb)

        self.assertRaises(
            ValueError, self.loop.run_until_complete, stream.readline())
        self.assertEqual(b'chunk3\n', stream._buffer)

    def test_readline_nolimit_nowait(self):
        # All needed data for the first 'readline' call will be
        # in the buffer.
        stream = self._make_one()
        stream.feed_data(self.DATA[:6])
        stream.feed_data(self.DATA[6:])

        line = self.loop.run_until_complete(stream.readline())

        self.assertEqual(b'line1\n', line)
        self.assertEqual(b'line2\nline3\n', stream._buffer)

    def test_readline_eof(self):
        stream = self._make_one()
        stream.feed_data(b'some data')
        stream.feed_eof()

        line = self.loop.run_until_complete(stream.readline())
        self.assertEqual(b'some data', line)

    def test_readline_empty_eof(self):
        stream = self._make_one()
        stream.feed_eof()

        line = self.loop.run_until_complete(stream.readline())
        self.assertEqual(b'', line)
        self.assertIs(line, streams.EOF_MARKER)

    def test_readline_read_byte_count(self):
        stream = self._make_one()
        stream.feed_data(self.DATA)

        self.loop.run_until_complete(stream.readline())

        data = self.loop.run_until_complete(stream.read(7))

        self.assertEqual(b'line2\nl', data)
        self.assertEqual(b'ine3\n', stream._buffer)

    def test_readline_exception(self):
        stream = self._make_one()
        stream.feed_data(b'line\n')

        data = self.loop.run_until_complete(stream.readline())
        self.assertEqual(b'line\n', data)

        stream.set_exception(ValueError())
        self.assertRaises(
            ValueError, self.loop.run_until_complete, stream.readline())
        self.assertEqual(b'', stream._buffer)

    def test_readexactly_zero_or_less(self):
        # Read exact number of bytes (zero or less).
        stream = self._make_one()
        stream.feed_data(self.DATA)

        data = self.loop.run_until_complete(stream.readexactly(0))
        self.assertEqual(b'', data)
        self.assertEqual(self.DATA, stream._buffer)

        data = self.loop.run_until_complete(stream.readexactly(-1))
        self.assertEqual(b'', data)
        self.assertEqual(self.DATA, stream._buffer)

    def test_readexactly(self):
        # Read exact number of bytes.
        stream = self._make_one()

        n = 2 * len(self.DATA)
        read_task = asyncio.Task(stream.readexactly(n), loop=self.loop)

        def cb():
            stream.feed_data(self.DATA)
            stream.feed_data(self.DATA)
            stream.feed_data(self.DATA)
        self.loop.call_soon(cb)

        data = self.loop.run_until_complete(read_task)
        self.assertEqual(self.DATA + self.DATA, data)
        self.assertEqual(self.DATA, stream._buffer)

    def test_readexactly_eof(self):
        # Read exact number of bytes (eof).
        stream = self._make_one()
        n = 2 * len(self.DATA)
        read_task = asyncio.Task(stream.readexactly(n), loop=self.loop)

        def cb():
            stream.feed_data(self.DATA)
            stream.feed_eof()
        self.loop.call_soon(cb)

        with self.assertRaises(asyncio.IncompleteReadError) as cm:
            self.loop.run_until_complete(read_task)
        self.assertEqual(cm.exception.partial, self.DATA)
        self.assertEqual(cm.exception.expected, n)
        self.assertEqual(str(cm.exception),
                         '18 bytes read on a total of 36 expected bytes')
        self.assertEqual(b'', stream._buffer)

    def test_readexactly_exception(self):
        stream = self._make_one()
        stream.feed_data(b'line\n')

        data = self.loop.run_until_complete(stream.readexactly(2))
        self.assertEqual(b'li', data)

        stream.set_exception(ValueError())
        self.assertRaises(
            ValueError, self.loop.run_until_complete, stream.readexactly(2))

    def test_exception(self):
        stream = self._make_one()
        self.assertIsNone(stream.exception())

        exc = ValueError()
        stream.set_exception(exc)
        self.assertIs(stream.exception(), exc)

    def test_exception_waiter(self):
        stream = self._make_one()

        @asyncio.coroutine
        def set_err():
            stream.set_exception(ValueError())

        t1 = asyncio.Task(stream.readline(), loop=self.loop)
        t2 = asyncio.Task(set_err(), loop=self.loop)

        self.loop.run_until_complete(asyncio.wait([t1, t2], loop=self.loop))
        self.assertRaises(ValueError, t1.result)

    def test_exception_cancel(self):
        stream = self._make_one()

        @asyncio.coroutine
        def read_a_line():
            yield from stream.readline()

        t = asyncio.Task(read_a_line(), loop=self.loop)
        test_utils.run_briefly(self.loop)
        t.cancel()
        test_utils.run_briefly(self.loop)
        # The following line fails if set_exception() isn't careful.
        stream.set_exception(RuntimeError('message'))
        test_utils.run_briefly(self.loop)
        self.assertIs(stream._waiter, None)

    def test_readany_eof(self):
        stream = self._make_one()
        read_task = asyncio.Task(stream.readany(), loop=self.loop)
        self.loop.call_soon(stream.feed_data, b'chunk1\n')

        data = self.loop.run_until_complete(read_task)

        self.assertEqual(b'chunk1\n', data)
        self.assertEqual(b'', stream._buffer)

    def test_readany_empty_eof(self):
        stream = self._make_one()
        stream.feed_eof()
        read_task = asyncio.Task(stream.readany(), loop=self.loop)

        data = self.loop.run_until_complete(read_task)

        self.assertEqual(b'', data)
        self.assertIs(data, streams.EOF_MARKER)

    def test_readany_exception(self):
        stream = self._make_one()
        stream.feed_data(b'line\n')

        data = self.loop.run_until_complete(stream.readany())
        self.assertEqual(b'line\n', data)

        stream.set_exception(ValueError())
        self.assertRaises(
            ValueError, self.loop.run_until_complete, stream.readany())

    def test_read_nowait(self):
        stream = self._make_one()
        stream.feed_data(b'line1\n')
        stream.feed_data(b'line2\n')

        self.assertEqual(
            stream.read_nowait(), b'line1\nline2\n')
        self.assertIs(
            stream.read_nowait(), streams.EOF_MARKER)
        self.assertEqual(
            bytes(stream._buffer), b'')

    def test_read_nowait_exception(self):
        stream = self._make_one()
        stream.feed_data(b'line\n')
        stream.set_exception(ValueError())

        self.assertRaises(ValueError, stream.read_nowait)

    def test_read_nowait_waiter(self):
        stream = self._make_one()
        stream.feed_data(b'line\n')
        stream._waiter = stream._create_waiter('readany')

        self.assertRaises(RuntimeError, stream.read_nowait)


class TestEmptyStreamReader(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def test_empty_stream_reader(self):
        s = streams.EmptyStreamReader()
        self.assertIsNone(s.set_exception(ValueError()))
        self.assertIsNone(s.exception())
        self.assertIsNone(s.feed_eof())
        self.assertIsNone(s.feed_data(b'data'))
        self.assertTrue(s.at_eof())
        self.assertIsNone(
            self.loop.run_until_complete(s.wait_eof()))
        self.assertIs(
            self.loop.run_until_complete(s.read()), streams.EOF_MARKER)
        self.assertIs(
            self.loop.run_until_complete(s.readline()), streams.EOF_MARKER)
        self.assertIs(
            self.loop.run_until_complete(s.readany()), streams.EOF_MARKER)
        self.assertRaises(
            asyncio.IncompleteReadError,
            self.loop.run_until_complete, s.readexactly(10))
        self.assertIs(s.read_nowait(), streams.EOF_MARKER)


class DataQueueMixin:

    def test_is_eof(self):
        self.assertFalse(self.buffer.is_eof())
        self.buffer.feed_eof()
        self.assertTrue(self.buffer.is_eof())

    def test_at_eof(self):
        self.assertFalse(self.buffer.at_eof())
        self.buffer.feed_eof()
        self.assertTrue(self.buffer.at_eof())
        self.buffer._buffer.append(object())
        self.assertFalse(self.buffer.at_eof())

    def test_feed_data(self):
        item = object()
        self.buffer.feed_data(item, 1)
        self.assertEqual([(item, 1)], list(self.buffer._buffer))

    def test_feed_eof(self):
        self.buffer.feed_eof()
        self.assertTrue(self.buffer._eof)

    def test_read(self):
        item = object()
        read_task = asyncio.Task(self.buffer.read(), loop=self.loop)

        def cb():
            self.buffer.feed_data(item, 1)
        self.loop.call_soon(cb)

        data = self.loop.run_until_complete(read_task)
        self.assertIs(item, data)

    def test_read_eof(self):
        read_task = asyncio.Task(self.buffer.read(), loop=self.loop)

        def cb():
            self.buffer.feed_eof()
        self.loop.call_soon(cb)

        self.assertRaises(
            streams.EofStream, self.loop.run_until_complete, read_task)

    def test_read_cancelled(self):
        read_task = asyncio.Task(self.buffer.read(), loop=self.loop)
        test_utils.run_briefly(self.loop)
        waiter = self.buffer._waiter
        self.assertIsInstance(waiter, asyncio.Future)

        read_task.cancel()
        self.assertRaises(
            asyncio.CancelledError,
            self.loop.run_until_complete, read_task)
        self.assertTrue(waiter.cancelled())
        self.assertIsNone(self.buffer._waiter)

        self.buffer.feed_data(b'test', 4)
        self.assertIsNone(self.buffer._waiter)

    def test_read_until_eof(self):
        item = object()
        self.buffer.feed_data(item, 1)
        self.buffer.feed_eof()

        data = self.loop.run_until_complete(self.buffer.read())
        self.assertIs(data, item)

        self.assertRaises(
            streams.EofStream,
            self.loop.run_until_complete, self.buffer.read())

    def test_read_exception(self):
        self.buffer.set_exception(ValueError())

        self.assertRaises(
            ValueError, self.loop.run_until_complete, self.buffer.read())

    def test_read_exception_with_data(self):
        val = object()
        self.buffer.feed_data(val, 1)
        self.buffer.set_exception(ValueError())

        self.assertIs(val, self.loop.run_until_complete(self.buffer.read()))
        self.assertRaises(
            ValueError, self.loop.run_until_complete, self.buffer.read())

    def test_read_exception_on_wait(self):
        read_task = asyncio.Task(self.buffer.read(), loop=self.loop)
        test_utils.run_briefly(self.loop)
        self.assertIsInstance(self.buffer._waiter, asyncio.Future)

        self.buffer.feed_eof()
        self.buffer.set_exception(ValueError())

        self.assertRaises(
            ValueError, self.loop.run_until_complete, read_task)

    def test_exception(self):
        self.assertIsNone(self.buffer.exception())

        exc = ValueError()
        self.buffer.set_exception(exc)
        self.assertIs(self.buffer.exception(), exc)

    def test_exception_waiter(self):
        @asyncio.coroutine
        def set_err():
            self.buffer.set_exception(ValueError())

        t1 = asyncio.Task(self.buffer.read(), loop=self.loop)
        t2 = asyncio.Task(set_err(), loop=self.loop)

        self.loop.run_until_complete(asyncio.wait([t1, t2], loop=self.loop))

        self.assertRaises(ValueError, t1.result)


class TestDataQueue(unittest.TestCase, DataQueueMixin):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        self.buffer = streams.DataQueue(loop=self.loop)

    def tearDown(self):
        self.loop.close()


class TestChunksQueue(unittest.TestCase, DataQueueMixin):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        self.buffer = streams.ChunksQueue(loop=self.loop)

    def tearDown(self):
        self.loop.close()

    def test_read_eof(self):
        read_task = asyncio.Task(self.buffer.read(), loop=self.loop)

        def cb():
            self.buffer.feed_eof()
        self.loop.call_soon(cb)

        self.loop.run_until_complete(read_task)
        self.assertTrue(self.buffer.at_eof())

    def test_read_until_eof(self):
        item = object()
        self.buffer.feed_data(item, 1)
        self.buffer.feed_eof()

        data = self.loop.run_until_complete(self.buffer.read())
        self.assertIs(data, item)

        thing = self.loop.run_until_complete(self.buffer.read())
        self.assertEqual(thing, b'')
        self.assertTrue(self.buffer.at_eof())

    def test_readany(self):
        self.assertIs(self.buffer.read.__func__, self.buffer.readany.__func__)
