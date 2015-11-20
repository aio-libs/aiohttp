"""Tests for parsers.py"""

import asyncio
import unittest
import unittest.mock

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
