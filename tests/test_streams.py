"""Tests for streams.py"""

import asyncio
import unittest
from unittest import mock

import pytest

from aiohttp import streams


DATA = b'line1\nline2\nline3\n'


def run_briefly(loop):
    async def once():
        pass
    t = loop.create_task(once())
    loop.run_until_complete(t)


def chunkify(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i+n]


def create_stream(loop):
    protocol = mock.Mock(_reading_paused=False)
    stream = streams.StreamReader(protocol, loop=loop)
    stream.feed_data(DATA)
    stream.feed_eof()
    return stream


@pytest.fixture
def protocol():
    return mock.Mock(_reading_paused=False)


class TestStreamReader(unittest.TestCase):

    DATA = b'line1\nline2\nline3\n'

    def setUp(self):
        self.protocol = mock.Mock(_reading_paused=False)
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def _make_one(self, *args, **kwargs):
        return streams.StreamReader(self.protocol,
                                    loop=self.loop, *args, **kwargs)

    def test_create_waiter(self):
        stream = self._make_one()
        stream._waiter = self.loop.create_future
        with self.assertRaises(RuntimeError):
            self.loop.run_until_complete(stream._wait('test'))

    @mock.patch('aiohttp.streams.asyncio')
    def test_ctor_global_loop(self, m_asyncio):
        stream = streams.StreamReader(self.protocol)
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

        async def cb():
            await asyncio.sleep(0.1, loop=self.loop)
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
        stream.feed_eof()

        data = self.loop.run_until_complete(stream.read())
        self.assertEqual(b'', data)

    def test_feed_nonempty_data(self):
        stream = self._make_one()
        stream.feed_data(self.DATA)
        stream.feed_eof()

        data = self.loop.run_until_complete(stream.read())
        self.assertEqual(self.DATA, data)

    def test_read_zero(self):
        # Read zero bytes.
        stream = self._make_one()
        stream.feed_data(self.DATA)

        data = self.loop.run_until_complete(stream.read(0))
        self.assertEqual(b'', data)

        stream.feed_eof()
        data = self.loop.run_until_complete(stream.read())
        self.assertEqual(self.DATA, data)

    def test_read(self):
        # Read bytes.
        stream = self._make_one()
        read_task = asyncio.Task(stream.read(30), loop=self.loop)

        def cb():
            stream.feed_data(self.DATA)
        self.loop.call_soon(cb)

        data = self.loop.run_until_complete(read_task)
        self.assertEqual(self.DATA, data)

        stream.feed_eof()
        data = self.loop.run_until_complete(stream.read())
        self.assertEqual(b'', data)

    def test_read_line_breaks(self):
        # Read bytes without line breaks.
        stream = self._make_one()
        stream.feed_data(b'line1')
        stream.feed_data(b'line2')

        data = self.loop.run_until_complete(stream.read(5))
        self.assertEqual(b'line1', data)

        data = self.loop.run_until_complete(stream.read(5))
        self.assertEqual(b'line2', data)

    def test_read_all(self):
        # Read all avaliable buffered bytes
        stream = self._make_one()
        stream.feed_data(b'line1')
        stream.feed_data(b'line2')
        stream.feed_eof()

        data = self.loop.run_until_complete(stream.read())
        self.assertEqual(b'line1line2', data)

    def test_read_up_to(self):
        # Read available buffered bytes up to requested amount
        stream = self._make_one()
        stream.feed_data(b'line1')
        stream.feed_data(b'line2')

        data = self.loop.run_until_complete(stream.read(8))
        self.assertEqual(b'line1lin', data)

        data = self.loop.run_until_complete(stream.read(8))
        self.assertEqual(b'e2', data)

    def test_read_eof(self):
        # Read bytes, stop at eof.
        stream = self._make_one()
        read_task = asyncio.Task(stream.read(1024), loop=self.loop)

        def cb():
            stream.feed_eof()
        self.loop.call_soon(cb)

        data = self.loop.run_until_complete(read_task)
        self.assertEqual(b'', data)

        data = self.loop.run_until_complete(stream.read())
        self.assertEqual(data, b'')

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

    @mock.patch('aiohttp.streams.internal_logger')
    def test_read_eof_unread_data_no_warning(self, internal_logger):
        # Read bytes.
        stream = self._make_one()
        stream.feed_eof()

        self.loop.run_until_complete(stream.read())
        self.loop.run_until_complete(stream.read())
        self.loop.run_until_complete(stream.read())
        self.loop.run_until_complete(stream.read())
        self.loop.run_until_complete(stream.read())
        stream.unread_data(b'data')
        self.loop.run_until_complete(stream.read())
        self.loop.run_until_complete(stream.read())
        self.assertFalse(internal_logger.warning.called)

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

        data = self.loop.run_until_complete(stream.read())
        self.assertEqual(b'', data)

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

        stream.feed_eof()
        data = self.loop.run_until_complete(stream.read())
        self.assertEqual(b' chunk4', data)

    def test_readline_limit_with_existing_data(self):
        # Read one line. The data is in StreamReader's buffer
        # before the event loop is run.

        stream = self._make_one(limit=2)
        stream.feed_data(b'li')
        stream.feed_data(b'ne1\nline2\n')

        self.assertRaises(
            ValueError, self.loop.run_until_complete, stream.readline())
        # The buffer should contain the remaining data after exception
        stream.feed_eof()
        data = self.loop.run_until_complete(stream.read())
        self.assertEqual(b'line2\n', data)

    def test_readline_limit(self):
        # Read one line. StreamReaders are fed with data after
        # their 'readline' methods are called.
        stream = self._make_one(limit=4)

        def cb():
            stream.feed_data(b'chunk1')
            stream.feed_data(b'chunk2\n')
            stream.feed_data(b'chunk3\n')
            stream.feed_eof()
        self.loop.call_soon(cb)

        self.assertRaises(
            ValueError, self.loop.run_until_complete, stream.readline())
        data = self.loop.run_until_complete(stream.read())
        self.assertEqual(b'chunk3\n', data)

    def test_readline_nolimit_nowait(self):
        # All needed data for the first 'readline' call will be
        # in the buffer.
        stream = self._make_one()
        stream.feed_data(self.DATA[:6])
        stream.feed_data(self.DATA[6:])

        line = self.loop.run_until_complete(stream.readline())
        self.assertEqual(b'line1\n', line)

        stream.feed_eof()
        data = self.loop.run_until_complete(stream.read())
        self.assertEqual(b'line2\nline3\n', data)

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

    def test_readline_read_byte_count(self):
        stream = self._make_one()
        stream.feed_data(self.DATA)

        self.loop.run_until_complete(stream.readline())

        data = self.loop.run_until_complete(stream.read(7))
        self.assertEqual(b'line2\nl', data)

        stream.feed_eof()
        data = self.loop.run_until_complete(stream.read())
        self.assertEqual(b'ine3\n', data)

    def test_readline_exception(self):
        stream = self._make_one()
        stream.feed_data(b'line\n')

        data = self.loop.run_until_complete(stream.readline())
        self.assertEqual(b'line\n', data)

        stream.set_exception(ValueError())
        self.assertRaises(
            ValueError, self.loop.run_until_complete, stream.readline())

    def test_readexactly_zero_or_less(self):
        # Read exact number of bytes (zero or less).
        stream = self._make_one()
        stream.feed_data(self.DATA)

        data = self.loop.run_until_complete(stream.readexactly(0))
        self.assertEqual(b'', data)
        stream.feed_eof()
        data = self.loop.run_until_complete(stream.read())
        self.assertEqual(self.DATA, data)

        stream = self._make_one()
        stream.feed_data(self.DATA)

        data = self.loop.run_until_complete(stream.readexactly(-1))
        self.assertEqual(b'', data)
        stream.feed_eof()
        data = self.loop.run_until_complete(stream.read())
        self.assertEqual(self.DATA, data)

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

        stream.feed_eof()
        data = self.loop.run_until_complete(stream.read())
        self.assertEqual(self.DATA, data)

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
        data = self.loop.run_until_complete(stream.read())
        self.assertEqual(b'', data)

    def test_readexactly_exception(self):
        stream = self._make_one()
        stream.feed_data(b'line\n')

        data = self.loop.run_until_complete(stream.readexactly(2))
        self.assertEqual(b'li', data)

        stream.set_exception(ValueError())
        self.assertRaises(
            ValueError, self.loop.run_until_complete, stream.readexactly(2))

    def test_unread_data(self):
        stream = self._make_one()
        stream.feed_data(b'line1')
        stream.feed_data(b'line2')
        stream.feed_data(b'onemoreline')

        data = self.loop.run_until_complete(stream.read(5))
        self.assertEqual(b'line1', data)

        stream.unread_data(data)

        data = self.loop.run_until_complete(stream.read(5))
        self.assertEqual(b'line1', data)

        data = self.loop.run_until_complete(stream.read(4))
        self.assertEqual(b'line', data)

        stream.unread_data(b'line1line')

        data = b''
        while len(data) < 10:
            data += self.loop.run_until_complete(stream.read(10))
        self.assertEqual(b'line1line2', data)

        data = self.loop.run_until_complete(stream.read(7))
        self.assertEqual(b'onemore', data)

        stream.unread_data(data)

        data = b''
        while len(data) < 11:
            data += self.loop.run_until_complete(stream.read(11))
        self.assertEqual(b'onemoreline', data)

        stream.unread_data(b'line')
        data = self.loop.run_until_complete(stream.read(4))
        self.assertEqual(b'line', data)

        stream.feed_eof()
        stream.unread_data(b'at_eof')
        data = self.loop.run_until_complete(stream.read(6))
        self.assertEqual(b'at_eof', data)

    def test_exception(self):
        stream = self._make_one()
        self.assertIsNone(stream.exception())

        exc = ValueError()
        stream.set_exception(exc)
        self.assertIs(stream.exception(), exc)

    def test_exception_waiter(self):
        stream = self._make_one()

        async def set_err():
            stream.set_exception(ValueError())

        t1 = asyncio.Task(stream.readline(), loop=self.loop)
        t2 = asyncio.Task(set_err(), loop=self.loop)

        self.loop.run_until_complete(asyncio.wait([t1, t2], loop=self.loop))
        self.assertRaises(ValueError, t1.result)

    def test_exception_cancel(self):
        stream = self._make_one()

        async def read_a_line():
            await stream.readline()

        t = asyncio.Task(read_a_line(), loop=self.loop)
        run_briefly(self.loop)
        t.cancel()
        run_briefly(self.loop)
        # The following line fails if set_exception() isn't careful.
        stream.set_exception(RuntimeError('message'))
        run_briefly(self.loop)
        self.assertIs(stream._waiter, None)

    def test_readany_eof(self):
        stream = self._make_one()
        read_task = asyncio.Task(stream.readany(), loop=self.loop)
        self.loop.call_soon(stream.feed_data, b'chunk1\n')

        data = self.loop.run_until_complete(read_task)
        self.assertEqual(b'chunk1\n', data)
        stream.feed_eof()
        data = self.loop.run_until_complete(stream.read())
        self.assertEqual(b'', data)

    def test_readany_empty_eof(self):
        stream = self._make_one()
        stream.feed_eof()
        read_task = asyncio.Task(stream.readany(), loop=self.loop)

        data = self.loop.run_until_complete(read_task)

        self.assertEqual(b'', data)

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
        stream.feed_data(b'line1\nline2\n')

        self.assertEqual(stream.read_nowait(), b'line1\nline2\n')
        self.assertEqual(stream.read_nowait(), b'')
        stream.feed_eof()
        data = self.loop.run_until_complete(stream.read())
        self.assertEqual(b'', data)

    def test_read_nowait_n(self):
        stream = self._make_one()
        stream.feed_data(b'line1\nline2\n')

        self.assertEqual(
            stream.read_nowait(4), b'line')
        self.assertEqual(
            stream.read_nowait(), b'1\nline2\n')
        self.assertEqual(stream.read_nowait(), b'')
        stream.feed_eof()
        data = self.loop.run_until_complete(stream.read())
        self.assertEqual(b'', data)

    def test_read_nowait_exception(self):
        stream = self._make_one()
        stream.feed_data(b'line\n')
        stream.set_exception(ValueError())

        self.assertRaises(ValueError, stream.read_nowait)

    def test_read_nowait_waiter(self):
        stream = self._make_one()
        stream.feed_data(b'line\n')
        stream._waiter = self.loop.create_future()

        self.assertRaises(RuntimeError, stream.read_nowait)

    def test_readchunk(self):
        stream = self._make_one()

        def cb():
            stream.feed_data(b'chunk1')
            stream.feed_data(b'chunk2')
            stream.feed_eof()
        self.loop.call_soon(cb)

        data, end_of_chunk = self.loop.run_until_complete(stream.readchunk())
        self.assertEqual(b'chunk1', data)
        self.assertFalse(end_of_chunk)

        data, end_of_chunk = self.loop.run_until_complete(stream.readchunk())
        self.assertEqual(b'chunk2', data)
        self.assertFalse(end_of_chunk)

        data, end_of_chunk = self.loop.run_until_complete(stream.readchunk())
        self.assertEqual(b'', data)
        self.assertFalse(end_of_chunk)

    def test_readchunk_wait_eof(self):
        stream = self._make_one()

        async def cb():
            await asyncio.sleep(0.1, loop=self.loop)
            stream.feed_eof()

        asyncio.Task(cb(), loop=self.loop)
        data, end_of_chunk = self.loop.run_until_complete(stream.readchunk())
        self.assertEqual(b"", data)
        self.assertFalse(end_of_chunk)
        self.assertTrue(stream.is_eof())

    def test_begin_and_end_chunk_receiving(self):
        stream = self._make_one()

        stream.begin_http_chunk_receiving()
        stream.feed_data(b'part1')
        stream.feed_data(b'part2')
        stream.end_http_chunk_receiving()

        data, end_of_chunk = self.loop.run_until_complete(stream.readchunk())
        self.assertEqual(b'part1part2', data)
        self.assertTrue(end_of_chunk)

        stream.begin_http_chunk_receiving()
        stream.feed_data(b'part3')

        data, end_of_chunk = self.loop.run_until_complete(stream.readchunk())
        self.assertEqual(b'part3', data)
        self.assertFalse(end_of_chunk)

        stream.end_http_chunk_receiving()

        data, end_of_chunk = self.loop.run_until_complete(stream.readchunk())
        self.assertEqual(b'', data)
        self.assertTrue(end_of_chunk)

        stream.feed_eof()

        data, end_of_chunk = self.loop.run_until_complete(stream.readchunk())
        self.assertEqual(b'', data)
        self.assertFalse(end_of_chunk)

    def test_end_chunk_receiving_without_begin(self):
        stream = self._make_one()
        self.assertRaises(RuntimeError, stream.end_http_chunk_receiving)

    def test_readchunk_with_unread(self):
        """Test that stream.unread does not break controlled chunk receiving.
        """
        stream = self._make_one()

        # Send 2 chunks
        stream.begin_http_chunk_receiving()
        stream.feed_data(b'part1')
        stream.end_http_chunk_receiving()
        stream.begin_http_chunk_receiving()
        stream.feed_data(b'part2')
        stream.end_http_chunk_receiving()

        # Read only one chunk
        data, end_of_chunk = self.loop.run_until_complete(stream.readchunk())

        # Try to unread a part of the first chunk
        stream.unread_data(b'rt1')

        # The end_of_chunk signal was already received for the first chunk,
        # so we receive up to the second one
        data, end_of_chunk = self.loop.run_until_complete(stream.readchunk())
        self.assertEqual(b'rt1part2', data)
        self.assertTrue(end_of_chunk)

        # Unread a part of the second chunk
        stream.unread_data(b'rt2')

        data, end_of_chunk = self.loop.run_until_complete(stream.readchunk())
        self.assertEqual(b'rt2', data)
        # end_of_chunk was already received for this chunk
        self.assertFalse(end_of_chunk)

        stream.feed_eof()
        data, end_of_chunk = self.loop.run_until_complete(stream.readchunk())
        self.assertEqual(b'', data)
        self.assertFalse(end_of_chunk)

    def test_readchunk_with_other_read_calls(self):
        """Test that stream.readchunk works when other read calls are made on
        the stream.
        """
        stream = self._make_one()

        stream.begin_http_chunk_receiving()
        stream.feed_data(b'part1')
        stream.end_http_chunk_receiving()
        stream.begin_http_chunk_receiving()
        stream.feed_data(b'part2')
        stream.end_http_chunk_receiving()

        data = self.loop.run_until_complete(stream.read(7))
        self.assertEqual(b'part1pa', data)

        data, end_of_chunk = self.loop.run_until_complete(stream.readchunk())
        self.assertEqual(b'rt2', data)
        self.assertTrue(end_of_chunk)

        stream.feed_eof()
        data, end_of_chunk = self.loop.run_until_complete(stream.readchunk())
        self.assertEqual(b'', data)
        self.assertFalse(end_of_chunk)

    def test___repr__(self):
        stream = self._make_one()
        self.assertEqual("<StreamReader>", repr(stream))

    def test___repr__nondefault_limit(self):
        stream = self._make_one(limit=123)
        self.assertEqual("<StreamReader low=123 high=246>", repr(stream))

    def test___repr__eof(self):
        stream = self._make_one()
        stream.feed_eof()
        self.assertEqual("<StreamReader eof>", repr(stream))

    def test___repr__data(self):
        stream = self._make_one()
        stream.feed_data(b'data')
        self.assertEqual("<StreamReader 4 bytes>", repr(stream))

    def test___repr__exception(self):
        stream = self._make_one()
        exc = RuntimeError()
        stream.set_exception(exc)
        self.assertEqual("<StreamReader e=RuntimeError()>", repr(stream))

    def test___repr__waiter(self):
        stream = self._make_one()
        stream._waiter = self.loop.create_future()
        self.assertRegex(
            repr(stream),
            "<StreamReader w=<Future pending[\S ]*>>")
        stream._waiter.set_result(None)
        self.loop.run_until_complete(stream._waiter)
        stream._waiter = None
        self.assertEqual("<StreamReader>", repr(stream))

    def test_unread_empty(self):
        stream = self._make_one()
        stream.feed_data(b'line1')
        stream.feed_eof()
        stream.unread_data(b'')

        data = self.loop.run_until_complete(stream.read(5))
        self.assertEqual(b'line1', data)
        self.assertTrue(stream.at_eof())


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
        self.assertEqual(
            self.loop.run_until_complete(s.read()), b'')
        self.assertEqual(
            self.loop.run_until_complete(s.readline()), b'')
        self.assertEqual(
            self.loop.run_until_complete(s.readany()), b'')
        self.assertEqual(
            self.loop.run_until_complete(s.readchunk()), (b'', False))
        self.assertRaises(
            asyncio.IncompleteReadError,
            self.loop.run_until_complete, s.readexactly(10))
        self.assertEqual(s.read_nowait(), b'')


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
        run_briefly(self.loop)
        waiter = self.buffer._waiter
        self.assertTrue(asyncio.isfuture(waiter))

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

    def test_read_exc(self):
        item = object()
        self.buffer.feed_data(item)
        self.buffer.set_exception(ValueError)
        read_task = asyncio.Task(self.buffer.read(), loop=self.loop)

        data = self.loop.run_until_complete(read_task)
        self.assertIs(item, data)

        self.assertRaises(
            ValueError, self.loop.run_until_complete, self.buffer.read())

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
        run_briefly(self.loop)
        self.assertTrue(asyncio.isfuture(self.buffer._waiter))

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

        async def set_err():
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


def test_feed_data_waiters(loop, protocol):
    reader = streams.StreamReader(protocol, loop=loop)
    waiter = reader._waiter = loop.create_future()
    eof_waiter = reader._eof_waiter = loop.create_future()

    reader.feed_data(b'1')
    assert list(reader._buffer) == [b'1']
    assert reader._size == 1
    assert reader.total_bytes == 1

    assert waiter.done()
    assert not eof_waiter.done()
    assert reader._waiter is None
    assert reader._eof_waiter is eof_waiter


def test_feed_data_completed_waiters(loop, protocol):
    reader = streams.StreamReader(protocol, loop=loop)
    waiter = reader._waiter = loop.create_future()

    waiter.set_result(1)
    reader.feed_data(b'1')

    assert reader._waiter is None


def test_feed_eof_waiters(loop, protocol):
    reader = streams.StreamReader(protocol, loop=loop)
    waiter = reader._waiter = loop.create_future()
    eof_waiter = reader._eof_waiter = loop.create_future()

    reader.feed_eof()
    assert reader._eof

    assert waiter.done()
    assert eof_waiter.done()
    assert reader._waiter is None
    assert reader._eof_waiter is None


def test_feed_eof_cancelled(loop, protocol):
    reader = streams.StreamReader(protocol, loop=loop)
    waiter = reader._waiter = loop.create_future()
    eof_waiter = reader._eof_waiter = loop.create_future()

    waiter.set_result(1)
    eof_waiter.set_result(1)

    reader.feed_eof()

    assert waiter.done()
    assert eof_waiter.done()
    assert reader._waiter is None
    assert reader._eof_waiter is None


def test_on_eof(loop, protocol):
    reader = streams.StreamReader(protocol, loop=loop)

    on_eof = mock.Mock()
    reader.on_eof(on_eof)

    assert not on_eof.called
    reader.feed_eof()
    assert on_eof.called


def test_on_eof_empty_reader(loop):
    reader = streams.EmptyStreamReader()

    on_eof = mock.Mock()
    reader.on_eof(on_eof)

    assert on_eof.called


def test_on_eof_exc_in_callback(loop, protocol):
    reader = streams.StreamReader(protocol, loop=loop)

    on_eof = mock.Mock()
    on_eof.side_effect = ValueError

    reader.on_eof(on_eof)
    assert not on_eof.called
    reader.feed_eof()
    assert on_eof.called
    assert not reader._eof_callbacks


def test_on_eof_exc_in_callback_empty_stream_reader(loop):
    reader = streams.EmptyStreamReader()

    on_eof = mock.Mock()
    on_eof.side_effect = ValueError

    reader.on_eof(on_eof)
    assert on_eof.called


def test_on_eof_eof_is_set(loop, protocol):
    reader = streams.StreamReader(protocol, loop=loop)
    reader.feed_eof()

    on_eof = mock.Mock()
    reader.on_eof(on_eof)
    assert on_eof.called
    assert not reader._eof_callbacks


def test_on_eof_eof_is_set_exception(loop, protocol):
    reader = streams.StreamReader(protocol, loop=loop)
    reader.feed_eof()

    on_eof = mock.Mock()
    on_eof.side_effect = ValueError

    reader.on_eof(on_eof)
    assert on_eof.called
    assert not reader._eof_callbacks


def test_set_exception(loop, protocol):
    reader = streams.StreamReader(protocol, loop=loop)
    waiter = reader._waiter = loop.create_future()
    eof_waiter = reader._eof_waiter = loop.create_future()

    exc = ValueError()
    reader.set_exception(exc)

    assert waiter.exception() is exc
    assert eof_waiter.exception() is exc
    assert reader._waiter is None
    assert reader._eof_waiter is None


def test_set_exception_cancelled(loop, protocol):
    reader = streams.StreamReader(protocol, loop=loop)
    waiter = reader._waiter = loop.create_future()
    eof_waiter = reader._eof_waiter = loop.create_future()

    waiter.set_result(1)
    eof_waiter.set_result(1)

    exc = ValueError()
    reader.set_exception(exc)

    assert waiter.exception() is None
    assert eof_waiter.exception() is None
    assert reader._waiter is None
    assert reader._eof_waiter is None


def test_set_exception_eof_callbacks(loop, protocol):
    reader = streams.StreamReader(protocol, loop=loop)

    on_eof = mock.Mock()
    reader.on_eof(on_eof)

    reader.set_exception(ValueError())
    assert not on_eof.called
    assert not reader._eof_callbacks


async def test_stream_reader_lines(loop):
    line_iter = iter(DATA.splitlines(keepends=True))
    async for line in create_stream(loop):
        assert line == next(line_iter, None)
    pytest.raises(StopIteration, next, line_iter)


async def test_stream_reader_chunks_complete(loop):
    """Tests if chunked iteration works if the chunking works out
    (i.e. the data is divisible by the chunk size)
    """
    chunk_iter = chunkify(DATA, 9)
    async for data in create_stream(loop).iter_chunked(9):
        assert data == next(chunk_iter, None)
    pytest.raises(StopIteration, next, chunk_iter)


async def test_stream_reader_chunks_incomplete(loop):
    """Tests if chunked iteration works if the last chunk is incomplete"""
    chunk_iter = chunkify(DATA, 8)
    async for data in create_stream(loop).iter_chunked(8):
        assert data == next(chunk_iter, None)
    pytest.raises(StopIteration, next, chunk_iter)


async def test_data_queue_empty(loop):
    """Tests that async looping yields nothing if nothing is there"""
    buffer = streams.DataQueue(loop=loop)
    buffer.feed_eof()

    async for _ in buffer:  # NOQA
        assert False


async def test_data_queue_items(loop):
    """Tests that async looping yields objects identically"""
    buffer = streams.DataQueue(loop=loop)

    items = [object(), object()]
    buffer.feed_data(items[0], 1)
    buffer.feed_data(items[1], 1)
    buffer.feed_eof()

    item_iter = iter(items)
    async for item in buffer:
        assert item is next(item_iter, None)
    pytest.raises(StopIteration, next, item_iter)


async def test_stream_reader_iter_any(loop):
    it = iter([b'line1\nline2\nline3\n'])
    async for raw in create_stream(loop).iter_any():
        assert raw == next(it)
    pytest.raises(StopIteration, next, it)


async def test_stream_reader_iter(loop):
    it = iter([b'line1\n',
               b'line2\n',
               b'line3\n'])
    async for raw in create_stream(loop):
        assert raw == next(it)
    pytest.raises(StopIteration, next, it)


async def test_stream_reader_iter_chunks_no_chunked_encoding(loop):
    it = iter([b'line1\nline2\nline3\n'])
    async for data, end_of_chunk in create_stream(loop).iter_chunks():
        assert (data, end_of_chunk) == (next(it), False)
    pytest.raises(StopIteration, next, it)


async def test_stream_reader_iter_chunks_chunked_encoding(loop, protocol):
    stream = streams.StreamReader(protocol, loop=loop)
    for line in DATA.splitlines(keepends=True):
        stream.begin_http_chunk_receiving()
        stream.feed_data(line)
        stream.end_http_chunk_receiving()
    stream.feed_eof()

    it = iter([b'line1\n', b'line2\n', b'line3\n'])
    async for data, end_of_chunk in stream.iter_chunks():
        assert (data, end_of_chunk) == (next(it), True)
    pytest.raises(StopIteration, next, it)
