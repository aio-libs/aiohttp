"""Tests for parser.py"""

import asyncio
import unittest
import unittest.mock

from aiohttp import parsers
from aiohttp import test_utils


class StreamParserTests(unittest.TestCase):

    DATA = b'line1\nline2\nline3\n'

    def setUp(self):
        self.lines_parser = parsers.LinesParser()
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def test_exception(self):
        stream = parsers.StreamParser()
        self.assertIsNone(stream.exception())

        exc = ValueError()
        stream.set_exception(exc)
        self.assertIs(stream.exception(), exc)

    def test_exception_waiter(self):
        stream = parsers.StreamParser()

        stream._parser = self.lines_parser
        buf = stream._output = parsers.DataQueue(loop=self.loop)

        exc = ValueError()
        stream.set_exception(exc)
        self.assertIs(buf.exception(), exc)

    def test_feed_data(self):
        stream = parsers.StreamParser()

        stream.feed_data(self.DATA)
        self.assertEqual(self.DATA, bytes(stream._input))

    def test_feed_empty_data(self):
        stream = parsers.StreamParser()

        stream.feed_data(b'')
        self.assertEqual(b'', bytes(stream._input))

    def test_set_parser_unset_prev(self):
        stream = parsers.StreamParser()
        stream.set_parser(self.lines_parser)

        unset = stream.unset_parser = unittest.mock.Mock()
        stream.set_parser(self.lines_parser)

        self.assertTrue(unset.called)

    def test_set_parser_exception(self):
        stream = parsers.StreamParser()

        exc = ValueError()
        stream.set_exception(exc)
        s = stream.set_parser(self.lines_parser)
        self.assertIs(s.exception(), exc)

    def test_set_parser_feed_existing(self):
        stream = parsers.StreamParser()
        stream.feed_data(b'line1')
        stream.feed_data(b'\r\nline2\r\ndata')
        s = stream.set_parser(self.lines_parser)

        self.assertEqual([bytearray(b'line1\r\n'), bytearray(b'line2\r\n')],
                         list(s._buffer))
        self.assertEqual(b'data', bytes(stream._input))
        self.assertIsNotNone(stream._parser)

        stream.unset_parser()
        self.assertIsNone(stream._parser)
        self.assertEqual(b'data', bytes(stream._input))
        self.assertTrue(s._eof)

    def test_set_parser_feed_existing_exc(self):
        def p(out, buf):
            yield from buf.read(1)
            raise ValueError()

        stream = parsers.StreamParser()
        stream.feed_data(b'line1')
        s = stream.set_parser(p)
        self.assertIsInstance(s.exception(), ValueError)

    def test_set_parser_feed_existing_eof(self):
        stream = parsers.StreamParser()
        stream.feed_data(b'line1')
        stream.feed_data(b'\r\nline2\r\ndata')
        stream.feed_eof()
        s = stream.set_parser(self.lines_parser)

        self.assertEqual([bytearray(b'line1\r\n'), bytearray(b'line2\r\n')],
                         list(s._buffer))
        self.assertEqual(b'data', bytes(stream._input))
        self.assertIsNone(stream._parser)

    def test_set_parser_feed_existing_eof_exc(self):
        def p(out, buf):
            try:
                while True:
                    yield  # read chunk
            except parsers.EofStream:
                raise ValueError()

        stream = parsers.StreamParser()
        stream.feed_data(b'line1')
        stream.feed_eof()
        s = stream.set_parser(p)
        self.assertIsInstance(s.exception(), ValueError)

    def test_set_parser_feed_existing_eof_unhandled_eof(self):
        def p(out, buf):
            while True:
                yield  # read chunk

        stream = parsers.StreamParser()
        stream.feed_data(b'line1')
        stream.feed_eof()
        s = stream.set_parser(p)
        self.assertIsNone(s.exception())
        self.assertTrue(s._eof)

    def test_set_parser_unset(self):
        stream = parsers.StreamParser()
        s = stream.set_parser(self.lines_parser)

        stream.feed_data(b'line1\r\nline2\r\n')
        self.assertEqual(
            [bytearray(b'line1\r\n'), bytearray(b'line2\r\n')],
            list(s._buffer))
        self.assertEqual(b'', bytes(stream._input))
        stream.unset_parser()
        self.assertTrue(s._eof)
        self.assertEqual(b'', bytes(stream._input))

    def test_set_parser_feed_existing_stop(self):
        def LinesParser(out, buf):
            try:
                out.feed_data((yield from buf.readuntil(b'\n')))
                out.feed_data((yield from buf.readuntil(b'\n')))
            finally:
                out.feed_eof()

        stream = parsers.StreamParser()
        stream.feed_data(b'line1')
        stream.feed_data(b'\r\nline2\r\ndata')
        s = stream.set_parser(LinesParser)

        self.assertEqual(b'line1\r\nline2\r\n', b''.join(s._buffer))
        self.assertEqual(b'data', bytes(stream._input))
        self.assertIsNone(stream._parser)
        self.assertTrue(s._eof)

    def test_feed_parser(self):
        stream = parsers.StreamParser()
        s = stream.set_parser(self.lines_parser)

        stream.feed_data(b'line1')
        stream.feed_data(b'\r\nline2\r\ndata')
        self.assertEqual(b'data', bytes(stream._input))

        stream.feed_eof()
        self.assertEqual([bytearray(b'line1\r\n'), bytearray(b'line2\r\n')],
                         list(s._buffer))
        self.assertEqual(b'data', bytes(stream._input))
        self.assertTrue(s._eof)

    def test_feed_parser_exc(self):
        def p(out, buf):
            yield  # read chunk
            raise ValueError()

        stream = parsers.StreamParser()
        s = stream.set_parser(p)

        stream.feed_data(b'line1')
        self.assertIsInstance(s.exception(), ValueError)
        self.assertEqual(b'', bytes(stream._input))

    def test_feed_parser_stop(self):
        def p(out, buf):
            yield  # chunk

        stream = parsers.StreamParser()
        stream.set_parser(p)

        stream.feed_data(b'line1')
        self.assertIsNone(stream._parser)
        self.assertEqual(b'', bytes(stream._input))

    def test_feed_eof_exc(self):
        def p(out, buf):
            try:
                while True:
                    yield  # read chunk
            except parsers.EofStream:
                raise ValueError()

        stream = parsers.StreamParser()
        s = stream.set_parser(p)

        stream.feed_data(b'line1')
        self.assertIsNone(s.exception())

        stream.feed_eof()
        self.assertIsInstance(s.exception(), ValueError)

    def test_feed_eof_stop(self):
        def p(out, buf):
            try:
                while True:
                    yield  # read chunk
            except parsers.EofStream:
                out.feed_eof()

        stream = parsers.StreamParser()
        s = stream.set_parser(p)

        stream.feed_data(b'line1')
        stream.feed_eof()
        self.assertTrue(s._eof)

    def test_feed_eof_unhandled_eof(self):
        def p(out, buf):
            while True:
                yield  # read chunk

        stream = parsers.StreamParser()
        s = stream.set_parser(p)

        stream.feed_data(b'line1')
        stream.feed_eof()
        self.assertIsNone(s.exception())
        self.assertTrue(s._eof)

    def test_feed_parser2(self):
        stream = parsers.StreamParser()
        s = stream.set_parser(self.lines_parser)

        stream.feed_data(b'line1\r\nline2\r\n')
        stream.feed_eof()
        self.assertEqual(
            [bytearray(b'line1\r\n'), bytearray(b'line2\r\n')],
            list(s._buffer))
        self.assertEqual(b'', bytes(stream._input))
        self.assertTrue(s._eof)

    def test_unset_parser_eof_exc(self):
        def p(out, buf):
            try:
                while True:
                    yield  # read chunk
            except parsers.EofStream:
                raise ValueError()

        stream = parsers.StreamParser()
        s = stream.set_parser(p)

        stream.feed_data(b'line1')
        stream.unset_parser()
        self.assertIsInstance(s.exception(), ValueError)
        self.assertIsNone(stream._parser)

    def test_unset_parser_eof_unhandled_eof(self):
        def p(out, buf):
            while True:
                yield  # read chunk

        stream = parsers.StreamParser()
        s = stream.set_parser(p)

        stream.feed_data(b'line1')
        stream.unset_parser()
        self.assertIsNone(s.exception(), ValueError)
        self.assertTrue(s._eof)

    def test_unset_parser_stop(self):
        def p(out, buf):
            try:
                while True:
                    yield  # read chunk
            except parsers.EofStream:
                out.feed_eof()

        stream = parsers.StreamParser()
        s = stream.set_parser(p)

        stream.feed_data(b'line1')
        stream.unset_parser()
        self.assertTrue(s._eof)


class DataQueueTests(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def test_feed_data(self):
        buffer = parsers.DataQueue(loop=self.loop)

        item = object()
        buffer.feed_data(item)
        self.assertEqual([item], list(buffer._buffer))

    def test_feed_eof(self):
        buffer = parsers.DataQueue(loop=self.loop)
        buffer.feed_eof()
        self.assertTrue(buffer._eof)

    def test_read(self):
        item = object()
        buffer = parsers.DataQueue(loop=self.loop)
        read_task = asyncio.Task(buffer.read(), loop=self.loop)

        def cb():
            buffer.feed_data(item)
        self.loop.call_soon(cb)

        data = self.loop.run_until_complete(read_task)
        self.assertIs(item, data)

    def test_read_eof(self):
        buffer = parsers.DataQueue(loop=self.loop)
        read_task = asyncio.Task(buffer.read(), loop=self.loop)

        def cb():
            buffer.feed_eof()
        self.loop.call_soon(cb)

        self.assertRaises(
            parsers.EofStream, self.loop.run_until_complete, read_task)

    def test_read_cancelled(self):
        buffer = parsers.DataQueue(loop=self.loop)
        read_task = asyncio.Task(buffer.read(), loop=self.loop)
        test_utils.run_briefly(self.loop)
        self.assertIsInstance(buffer._waiter, asyncio.Future)

        read_task.cancel()
        self.assertRaises(
            asyncio.CancelledError,
            self.loop.run_until_complete, read_task)
        self.assertTrue(buffer._waiter.cancelled())

        buffer.feed_data(b'test')
        self.assertIsNone(buffer._waiter)

    def test_read_until_eof(self):
        item = object()
        buffer = parsers.DataQueue(loop=self.loop)
        buffer.feed_data(item)
        buffer.feed_eof()

        data = self.loop.run_until_complete(buffer.read())
        self.assertIs(data, item)

        self.assertRaises(
            parsers.EofStream, self.loop.run_until_complete, buffer.read())

    def test_read_exception(self):
        buffer = parsers.DataQueue(loop=self.loop)
        buffer.feed_data(object())
        buffer.set_exception(ValueError())

        self.assertRaises(
            ValueError, self.loop.run_until_complete, buffer.read())

    def test_exception(self):
        buffer = parsers.DataQueue(loop=self.loop)
        self.assertIsNone(buffer.exception())

        exc = ValueError()
        buffer.set_exception(exc)
        self.assertIs(buffer.exception(), exc)

    def test_exception_waiter(self):
        buffer = parsers.DataQueue(loop=self.loop)

        @asyncio.coroutine
        def set_err():
            buffer.set_exception(ValueError())

        t1 = asyncio.Task(buffer.read(), loop=self.loop)
        t2 = asyncio.Task(set_err(), loop=self.loop)

        self.loop.run_until_complete(asyncio.wait([t1, t2], loop=self.loop))

        self.assertRaises(ValueError, t1.result)


class StreamProtocolTests(unittest.TestCase):

    def test_connection_made(self):
        tr = unittest.mock.Mock()

        proto = parsers.StreamProtocol()
        self.assertIsNone(proto.transport)

        proto.connection_made(tr)
        self.assertIs(proto.transport, tr)

    def test_connection_lost(self):
        proto = parsers.StreamProtocol()
        proto.connection_made(unittest.mock.Mock())
        proto.connection_lost(None)
        self.assertIsNone(proto.transport)
        self.assertTrue(proto._eof)

    def test_connection_lost_exc(self):
        proto = parsers.StreamProtocol()
        proto.connection_made(unittest.mock.Mock())

        exc = ValueError()
        proto.connection_lost(exc)
        self.assertIs(proto.exception(), exc)


class ParserBufferTests(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def _make_one(self):
        return parsers.ParserBuffer()

    def test_shrink(self):
        buf = parsers.ParserBuffer()
        buf.feed_data(b'data')

        buf._shrink()
        self.assertEqual(bytes(buf), b'data')

        buf.offset = 2
        buf._shrink()
        self.assertEqual(bytes(buf), b'ta')
        self.assertEqual(2, len(buf))
        self.assertEqual(2, buf.size)
        self.assertEqual(0, buf.offset)

    def test_feed_data(self):
        buf = self._make_one()
        buf.feed_data(b'')
        self.assertEqual(len(buf), 0)

        buf.feed_data(b'data')
        self.assertEqual(len(buf), 4)
        self.assertEqual(bytes(buf), b'data')

    def test_read(self):
        buf = self._make_one()
        p = buf.read(3)
        next(p)
        p.send(b'1')
        try:
            p.send(b'234')
        except StopIteration as exc:
            res = exc.value

        self.assertEqual(res, b'123')
        self.assertEqual(b'4', bytes(buf))

    def test_readsome(self):
        buf = self._make_one()
        p = buf.readsome(3)
        next(p)
        try:
            p.send(b'1')
        except StopIteration as exc:
            res = exc.value
        self.assertEqual(res, b'1')

        p = buf.readsome(2)
        next(p)
        try:
            p.send(b'234')
        except StopIteration as exc:
            res = exc.value
        self.assertEqual(res, b'23')
        self.assertEqual(b'4', bytes(buf))

    def test_skip(self):
        buf = self._make_one()
        p = buf.skip(3)
        next(p)
        p.send(b'1')
        try:
            p.send(b'234')
        except StopIteration as exc:
            res = exc.value

        self.assertIsNone(res)
        self.assertEqual(b'4', bytes(buf))

    def test_readuntil_limit(self):
        buf = self._make_one()
        p = buf.readuntil(b'\n', 4)
        next(p)
        p.send(b'1')
        p.send(b'234')
        self.assertRaises(ValueError, p.send, b'5')

        buf = parsers.ParserBuffer()
        p = buf.readuntil(b'\n', 4)
        next(p)
        self.assertRaises(ValueError, p.send, b'12345\n6')

        buf = parsers.ParserBuffer()
        p = buf.readuntil(b'\n', 4)
        next(p)
        self.assertRaises(ValueError, p.send, b'12345\n6')

        class CustomExc(Exception):
            pass

        buf = parsers.ParserBuffer()
        p = buf.readuntil(b'\n', 4, CustomExc)
        next(p)
        self.assertRaises(CustomExc, p.send, b'12345\n6')

    def test_readuntil(self):
        buf = self._make_one()
        p = buf.readuntil(b'\n', 4)
        next(p)
        p.send(b'123')
        try:
            p.send(b'\n456')
        except StopIteration as exc:
            res = exc.value

        self.assertEqual(res, b'123\n')
        self.assertEqual(b'456', bytes(buf))

    def test_skipuntil(self):
        buf = self._make_one()
        p = buf.skipuntil(b'\n')
        next(p)
        p.send(b'123')
        try:
            p.send(b'\n456\n')
        except StopIteration:
            pass
        self.assertEqual(b'456\n', bytes(buf))

        p = buf.skipuntil(b'\n')
        try:
            next(p)
        except StopIteration:
            pass
        self.assertEqual(b'', bytes(buf))

    def test_lines_parser(self):
        out = parsers.DataQueue(loop=self.loop)
        buf = self._make_one()

        p = parsers.LinesParser()(out, buf)
        next(p)
        for d in (b'line1', b'\r\n', b'lin', b'e2\r', b'\ndata'):
            p.send(d)

        self.assertEqual(
            [bytearray(b'line1\r\n'), bytearray(b'line2\r\n')],
            list(out._buffer))
        try:
            p.throw(parsers.EofStream())
        except parsers.EofStream:
            pass

        self.assertEqual(bytes(buf), b'data')

    def test_chunks_parser(self):
        out = parsers.DataQueue(loop=self.loop)
        buf = self._make_one()

        p = parsers.ChunksParser(5)(out, buf)
        next(p)
        for d in (b'line1', b'lin', b'e2d', b'ata'):
            p.send(d)

        self.assertEqual(
            [bytearray(b'line1'), bytearray(b'line2')], list(out._buffer))
        try:
            p.throw(parsers.EofStream())
        except parsers.EofStream:
            pass

        self.assertEqual(bytes(buf), b'data')
