"""Tests for parsers.py"""

import asyncio
import unittest
import unittest.mock

from aiohttp import errors
from aiohttp import parsers


class TestStreamParser(unittest.TestCase):

    DATA = b'line1\nline2\nline3\n'

    def setUp(self):
        self.lines_parser = parsers.LinesParser()
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def test_at_eof(self):
        proto = parsers.StreamParser(loop=self.loop)
        self.assertFalse(proto.at_eof())

        proto.feed_eof()
        self.assertTrue(proto.at_eof())

    def test_exception(self):
        stream = parsers.StreamParser(loop=self.loop)
        self.assertIsNone(stream.exception())

        exc = ValueError()
        stream.set_exception(exc)
        self.assertIs(stream.exception(), exc)

    def test_exception_connection_error(self):
        stream = parsers.StreamParser(loop=self.loop)
        self.assertIsNone(stream.exception())

        exc = ConnectionError()
        stream.set_exception(exc)
        self.assertIsNot(stream.exception(), exc)
        self.assertIsInstance(stream.exception(), RuntimeError)
        self.assertIs(stream.exception().__cause__, exc)
        self.assertIs(stream.exception().__context__, exc)

    def test_exception_waiter(self):
        stream = parsers.StreamParser(loop=self.loop)

        stream._parser = self.lines_parser
        buf = stream._output = parsers.FlowControlDataQueue(
            stream, loop=self.loop)

        exc = ValueError()
        stream.set_exception(exc)
        self.assertIs(buf.exception(), exc)

    def test_feed_data(self):
        stream = parsers.StreamParser(loop=self.loop)

        stream.feed_data(self.DATA)
        self.assertEqual(self.DATA, bytes(stream._buffer))

    def test_feed_none_data(self):
        stream = parsers.StreamParser(loop=self.loop)

        stream.feed_data(None)
        self.assertEqual(b'', bytes(stream._buffer))

    def test_set_parser_unset_prev(self):
        stream = parsers.StreamParser(loop=self.loop)
        stream.set_parser(self.lines_parser)

        unset = stream.unset_parser = unittest.mock.Mock()
        stream.set_parser(self.lines_parser)

        self.assertTrue(unset.called)

    def test_set_parser_exception(self):
        stream = parsers.StreamParser(loop=self.loop)

        exc = ValueError()
        stream.set_exception(exc)
        s = stream.set_parser(self.lines_parser)
        self.assertIs(s.exception(), exc)

    def test_set_parser_feed_existing(self):
        stream = parsers.StreamParser(loop=self.loop)
        stream.feed_data(b'line1')
        stream.feed_data(b'\r\nline2\r\ndata')
        s = stream.set_parser(self.lines_parser)

        self.assertEqual(
            [(bytearray(b'line1\r\n'), 7), (bytearray(b'line2\r\n'), 7)],
            list(s._buffer))
        self.assertEqual(b'data', bytes(stream._buffer))
        self.assertIsNotNone(stream._parser)

        stream.unset_parser()
        self.assertIsNone(stream._parser)
        self.assertEqual(b'data', bytes(stream._buffer))
        self.assertTrue(s._eof)

    def test_set_parser_feed_existing_exc(self):
        def p(out, buf):
            yield from buf.read(1)
            raise ValueError()

        stream = parsers.StreamParser(loop=self.loop)
        stream.feed_data(b'line1')
        s = stream.set_parser(p)
        self.assertIsInstance(s.exception(), ValueError)

    def test_set_parser_feed_existing_eof(self):
        stream = parsers.StreamParser(loop=self.loop)
        stream.feed_data(b'line1')
        stream.feed_data(b'\r\nline2\r\ndata')
        stream.feed_eof()
        s = stream.set_parser(self.lines_parser)

        self.assertEqual(
            [(bytearray(b'line1\r\n'), 7), (bytearray(b'line2\r\n'), 7)],
            list(s._buffer))
        self.assertEqual(b'data', bytes(stream._buffer))
        self.assertIsNone(stream._parser)

    def test_set_parser_feed_existing_eof_exc(self):
        def p(out, buf):
            try:
                while True:
                    yield  # read chunk
            except parsers.EofStream:
                raise ValueError()

        stream = parsers.StreamParser(loop=self.loop)
        stream.feed_data(b'line1')
        stream.feed_eof()
        s = stream.set_parser(p)
        self.assertIsInstance(s.exception(), ValueError)

    def test_set_parser_feed_existing_eof_unhandled_eof(self):
        def p(out, buf):
            while True:
                yield  # read chunk

        stream = parsers.StreamParser(loop=self.loop)
        stream.feed_data(b'line1')
        stream.feed_eof()
        s = stream.set_parser(p)
        self.assertFalse(s.is_eof())
        self.assertIsInstance(s.exception(), RuntimeError)

    def test_set_parser_unset(self):
        stream = parsers.StreamParser(loop=self.loop)
        s = stream.set_parser(self.lines_parser)

        stream.feed_data(b'line1\r\nline2\r\n')
        self.assertEqual(
            [(bytearray(b'line1\r\n'), 7), (bytearray(b'line2\r\n'), 7)],
            list(s._buffer))
        self.assertEqual(b'', bytes(stream._buffer))
        stream.unset_parser()
        self.assertTrue(s._eof)
        self.assertEqual(b'', bytes(stream._buffer))

    def test_set_parser_feed_existing_stop(self):
        def LinesParser(out, buf):
            try:
                chunk = yield from buf.readuntil(b'\n')
                out.feed_data(chunk, len(chunk))

                chunk = yield from buf.readuntil(b'\n')
                out.feed_data(chunk, len(chunk))
            finally:
                out.feed_eof()

        stream = parsers.StreamParser(loop=self.loop)
        stream.feed_data(b'line1')
        stream.feed_data(b'\r\nline2\r\ndata')
        s = stream.set_parser(LinesParser)

        self.assertEqual(
            b'line1\r\nline2\r\n', b''.join(d for d, _ in s._buffer))
        self.assertEqual(b'data', bytes(stream._buffer))
        self.assertIsNone(stream._parser)
        self.assertTrue(s._eof)

    def test_feed_parser(self):
        stream = parsers.StreamParser(loop=self.loop)
        s = stream.set_parser(self.lines_parser)

        stream.feed_data(b'line1')
        stream.feed_data(b'\r\nline2\r\ndata')
        self.assertEqual(b'data', bytes(stream._buffer))

        stream.feed_eof()
        self.assertEqual(
            [(bytearray(b'line1\r\n'), 7), (bytearray(b'line2\r\n'), 7)],
            list(s._buffer))
        self.assertEqual(b'data', bytes(stream._buffer))
        self.assertTrue(s.is_eof())

    def test_feed_parser_exc(self):
        def p(out, buf):
            yield  # read chunk
            raise ValueError()

        stream = parsers.StreamParser(loop=self.loop)
        s = stream.set_parser(p)

        stream.feed_data(b'line1')
        self.assertIsInstance(s.exception(), ValueError)
        self.assertEqual(b'', bytes(stream._buffer))

    def test_feed_parser_stop(self):
        def p(out, buf):
            yield  # chunk

        stream = parsers.StreamParser(loop=self.loop)
        stream.set_parser(p)

        stream.feed_data(b'line1')
        self.assertIsNone(stream._parser)
        self.assertEqual(b'', bytes(stream._buffer))

    def test_feed_eof_exc(self):
        def p(out, buf):
            try:
                while True:
                    yield  # read chunk
            except parsers.EofStream:
                raise ValueError()

        stream = parsers.StreamParser(loop=self.loop)
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

        stream = parsers.StreamParser(loop=self.loop)
        s = stream.set_parser(p)

        stream.feed_data(b'line1')
        stream.feed_eof()
        self.assertTrue(s._eof)

    def test_feed_eof_unhandled_eof(self):
        def p(out, buf):
            while True:
                yield  # read chunk

        stream = parsers.StreamParser(loop=self.loop)
        s = stream.set_parser(p)

        stream.feed_data(b'line1')
        stream.feed_eof()
        self.assertFalse(s.is_eof())
        self.assertIsInstance(s.exception(), RuntimeError)

    def test_feed_parser2(self):
        stream = parsers.StreamParser(loop=self.loop)
        s = stream.set_parser(self.lines_parser)

        stream.feed_data(b'line1\r\nline2\r\n')
        stream.feed_eof()
        self.assertEqual(
            [(bytearray(b'line1\r\n'), 7), (bytearray(b'line2\r\n'), 7)],
            list(s._buffer))
        self.assertEqual(b'', bytes(stream._buffer))
        self.assertTrue(s._eof)

    def test_unset_parser_eof_exc(self):
        def p(out, buf):
            try:
                while True:
                    yield  # read chunk
            except parsers.EofStream:
                raise ValueError()

        stream = parsers.StreamParser(loop=self.loop)
        s = stream.set_parser(p)

        stream.feed_data(b'line1')
        stream.unset_parser()
        self.assertIsInstance(s.exception(), ValueError)
        self.assertIsNone(stream._parser)

    def test_unset_parser_eof_unhandled_eof(self):
        def p(out, buf):
            while True:
                yield  # read chunk

        stream = parsers.StreamParser(loop=self.loop)
        s = stream.set_parser(p)

        stream.feed_data(b'line1')
        stream.unset_parser()
        self.assertIsInstance(s.exception(), RuntimeError)
        self.assertFalse(s.is_eof())

    def test_unset_parser_stop(self):
        def p(out, buf):
            try:
                while True:
                    yield  # read chunk
            except parsers.EofStream:
                out.feed_eof()

        stream = parsers.StreamParser(loop=self.loop)
        s = stream.set_parser(p)

        stream.feed_data(b'line1')
        stream.unset_parser()
        self.assertTrue(s._eof)

    def test_eof_exc(self):
        def p(out, buf):
            while True:
                yield  # read chunk

        class CustomEofErr(Exception):
            pass

        stream = parsers.StreamParser(
            eof_exc_class=CustomEofErr, loop=self.loop)
        s = stream.set_parser(p)

        stream.feed_eof()
        self.assertIsInstance(s.exception(), CustomEofErr)


class TestStreamProtocol(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def test_connection_made(self):
        tr = unittest.mock.Mock()

        proto = parsers.StreamProtocol(loop=self.loop)
        self.assertIsNone(proto.transport)

        proto.connection_made(tr)
        self.assertIs(proto.transport, tr)

    def test_connection_lost(self):
        proto = parsers.StreamProtocol(loop=self.loop)
        proto.connection_made(unittest.mock.Mock())
        proto.connection_lost(None)
        self.assertIsNone(proto.transport)
        self.assertIsNone(proto.writer)
        self.assertTrue(proto.reader._eof)

    def test_connection_lost_exc(self):
        proto = parsers.StreamProtocol(loop=self.loop)
        proto.connection_made(unittest.mock.Mock())

        exc = ValueError()
        proto.connection_lost(exc)
        self.assertIs(proto.reader.exception(), exc)

    def test_data_received(self):
        proto = parsers.StreamProtocol(loop=self.loop)
        proto.connection_made(unittest.mock.Mock())
        proto.reader = unittest.mock.Mock()

        proto.data_received(b'data')
        proto.reader.feed_data.assert_called_with(b'data')


class TestParserBuffer(unittest.TestCase):

    def setUp(self):
        self.stream = unittest.mock.Mock()
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def _make_one(self):
        return parsers.ParserBuffer()

    def test_feed_data(self):
        buf = self._make_one()
        buf.feed_data(b'')
        self.assertEqual(len(buf), 0)

        buf.feed_data(b'data')
        self.assertEqual(len(buf), 4)
        self.assertEqual(bytes(buf), b'data')

    def test_read_exc(self):
        buf = self._make_one()
        exc = ValueError()
        buf.set_exception(exc)
        self.assertIs(buf.exception(), exc)
        p = buf.read(3)
        next(p)
        self.assertRaises(ValueError, p.send, b'1')

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

    def test_wait(self):
        buf = self._make_one()
        p = buf.wait(3)
        next(p)
        p.send(b'1')
        try:
            p.send(b'234')
        except StopIteration as exc:
            res = exc.value

        self.assertEqual(res, b'123')
        self.assertEqual(b'1234', bytes(buf))

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
        self.assertRaises(errors.LineLimitExceededParserError, p.send, b'5')

        buf = parsers.ParserBuffer()
        p = buf.readuntil(b'\n', 4)
        next(p)
        self.assertRaises(
            errors.LineLimitExceededParserError, p.send, b'12345\n6')

        buf = parsers.ParserBuffer()
        p = buf.readuntil(b'\n', 4)
        next(p)
        self.assertRaises(
            errors.LineLimitExceededParserError, p.send, b'12345\n6')

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

    def test_waituntil_limit(self):
        buf = self._make_one()
        p = buf.waituntil(b'\n', 4)
        next(p)
        p.send(b'1')
        p.send(b'234')
        self.assertRaises(errors.LineLimitExceededParserError, p.send, b'5')

        buf = parsers.ParserBuffer()
        p = buf.waituntil(b'\n', 4)
        next(p)
        self.assertRaises(
            errors.LineLimitExceededParserError, p.send, b'12345\n6')

        buf = parsers.ParserBuffer()
        p = buf.waituntil(b'\n', 4)
        next(p)
        self.assertRaises(
            errors.LineLimitExceededParserError, p.send, b'12345\n6')

    def test_waituntil(self):
        buf = self._make_one()
        p = buf.waituntil(b'\n', 4)
        next(p)
        p.send(b'123')
        try:
            p.send(b'\n456')
        except StopIteration as exc:
            res = exc.value

        self.assertEqual(res, b'123\n')
        self.assertEqual(b'123\n456', bytes(buf))

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
        out = parsers.FlowControlDataQueue(self.stream, loop=self.loop)
        buf = self._make_one()

        p = parsers.LinesParser()(out, buf)
        next(p)
        for d in (b'line1', b'\r\n', b'lin', b'e2\r', b'\ndata'):
            p.send(d)

        self.assertEqual(
            [(bytearray(b'line1\r\n'), 7), (bytearray(b'line2\r\n'), 7)],
            list(out._buffer))
        try:
            p.throw(parsers.EofStream())
        except StopIteration:
            pass

        self.assertEqual(bytes(buf), b'data')

    def test_chunks_parser(self):
        out = parsers.FlowControlDataQueue(self.stream, loop=self.loop)
        buf = self._make_one()

        p = parsers.ChunksParser(5)(out, buf)
        next(p)
        for d in (b'line1', b'lin', b'e2d', b'ata'):
            p.send(d)

        self.assertEqual(
            [(bytearray(b'line1'), 5), (bytearray(b'line2'), 5)],
            list(out._buffer))
        try:
            p.throw(parsers.EofStream())
        except StopIteration:
            pass

        self.assertEqual(bytes(buf), b'data')
