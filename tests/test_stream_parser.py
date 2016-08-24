"""Tests for parsers.py"""

from unittest import mock

import pytest

from aiohttp import parsers

DATA = b'line1\nline2\nline3\n'


class LinesParser:
    """Lines parser.
    Lines parser splits a bytes stream into a chunks of data, each chunk ends
    with \\n symbol."""

    def __init__(self):
        pass

    def __call__(self, out, buf):
        try:
            while True:
                chunk = yield from buf.readuntil(b'\n', 0xffff)
                out.feed_data(chunk, len(chunk))
        except parsers.EofStream:
            pass


@pytest.fixture
def lines_parser():
    return LinesParser()


def test_at_eof(loop):
    proto = parsers.StreamParser(loop=loop)
    assert not proto.at_eof()

    proto.feed_eof()
    assert proto.at_eof()


def test_exception(loop):
    stream = parsers.StreamParser(loop=loop)
    assert stream.exception() is None

    exc = ValueError()
    stream.set_exception(exc)
    assert stream.exception() is exc


def test_exception_connection_error(loop):
    stream = parsers.StreamParser(loop=loop)
    assert stream.exception() is None

    exc = ConnectionError()
    stream.set_exception(exc)
    assert stream.exception() is not exc
    assert isinstance(stream.exception(), RuntimeError)
    assert stream.exception().__cause__ is exc
    assert stream.exception().__context__ is exc


def test_exception_waiter(loop, lines_parser):

    stream = parsers.StreamParser(loop=loop)

    stream._parser = lines_parser
    buf = stream._output = parsers.FlowControlDataQueue(
        stream, loop=loop)

    exc = ValueError()
    stream.set_exception(exc)
    assert buf.exception() is exc


def test_feed_data(loop):
    stream = parsers.StreamParser(loop=loop)

    stream.feed_data(DATA)
    assert DATA == bytes(stream._buffer)


def test_feed_none_data(loop):
    stream = parsers.StreamParser(loop=loop)

    stream.feed_data(None)
    assert b'' == bytes(stream._buffer)


def test_set_parser_unset_prev(loop, lines_parser):
    stream = parsers.StreamParser(loop=loop)
    stream.set_parser(lines_parser)

    unset = stream.unset_parser = mock.Mock()
    stream.set_parser(lines_parser)

    assert unset.called


def test_set_parser_exception(loop, lines_parser):
    stream = parsers.StreamParser(loop=loop)

    exc = ValueError()
    stream.set_exception(exc)
    s = stream.set_parser(lines_parser)
    assert s.exception() is exc


def test_set_parser_feed_existing(loop, lines_parser):
    stream = parsers.StreamParser(loop=loop)
    stream.feed_data(b'line1')
    stream.feed_data(b'\r\nline2\r\ndata')
    s = stream.set_parser(lines_parser)

    assert ([(bytearray(b'line1\r\n'), 7), (bytearray(b'line2\r\n'), 7)] ==
            list(s._buffer))
    assert b'data' == bytes(stream._buffer)
    assert stream._parser is not None

    stream.unset_parser()
    assert stream._parser is None
    assert b'data' == bytes(stream._buffer)
    assert s._eof


def test_set_parser_feed_existing_exc(loop):
    def p(out, buf):
        yield from buf.read(1)
        raise ValueError()

    stream = parsers.StreamParser(loop=loop)
    stream.feed_data(b'line1')
    s = stream.set_parser(p)
    assert isinstance(s.exception(), ValueError)


def test_set_parser_feed_existing_eof(loop, lines_parser):
    stream = parsers.StreamParser(loop=loop)
    stream.feed_data(b'line1')
    stream.feed_data(b'\r\nline2\r\ndata')
    stream.feed_eof()
    s = stream.set_parser(lines_parser)

    assert ([(bytearray(b'line1\r\n'), 7), (bytearray(b'line2\r\n'), 7)] ==
            list(s._buffer))
    assert b'data' == bytes(stream._buffer)
    assert stream._parser is None


def test_set_parser_feed_existing_eof_exc(loop):
    def p(out, buf):
        try:
            while True:
                yield  # read chunk
        except parsers.EofStream:
            raise ValueError()

    stream = parsers.StreamParser(loop=loop)
    stream.feed_data(b'line1')
    stream.feed_eof()
    s = stream.set_parser(p)
    assert isinstance(s.exception(), ValueError)


def test_set_parser_feed_existing_eof_unhandled_eof(loop):
    def p(out, buf):
        while True:
            yield  # read chunk

    stream = parsers.StreamParser(loop=loop)
    stream.feed_data(b'line1')
    stream.feed_eof()
    s = stream.set_parser(p)
    assert not s.is_eof()
    assert isinstance(s.exception(), RuntimeError)


def test_set_parser_unset(loop, lines_parser):
    stream = parsers.StreamParser(loop=loop)
    s = stream.set_parser(lines_parser)

    stream.feed_data(b'line1\r\nline2\r\n')
    assert ([(bytearray(b'line1\r\n'), 7), (bytearray(b'line2\r\n'), 7)] ==
            list(s._buffer))
    assert b'' == bytes(stream._buffer)
    stream.unset_parser()
    assert s._eof
    assert b'' == bytes(stream._buffer)


def test_set_parser_feed_existing_stop(loop):
    def LinesParser(out, buf):
        try:
            chunk = yield from buf.readuntil(b'\n')
            out.feed_data(chunk, len(chunk))

            chunk = yield from buf.readuntil(b'\n')
            out.feed_data(chunk, len(chunk))
        finally:
            out.feed_eof()

    stream = parsers.StreamParser(loop=loop)
    stream.feed_data(b'line1')
    stream.feed_data(b'\r\nline2\r\ndata')
    s = stream.set_parser(LinesParser)

    assert b'line1\r\nline2\r\n' == b''.join(d for d, _ in s._buffer)
    assert b'data' == bytes(stream._buffer)
    assert stream._parser is None
    assert s._eof


def test_feed_parser(loop, lines_parser):
    stream = parsers.StreamParser(loop=loop)
    s = stream.set_parser(lines_parser)

    stream.feed_data(b'line1')
    stream.feed_data(b'\r\nline2\r\ndata')
    assert b'data' == bytes(stream._buffer)

    stream.feed_eof()
    assert ([(bytearray(b'line1\r\n'), 7), (bytearray(b'line2\r\n'), 7)] ==
            list(s._buffer))
    assert b'data' == bytes(stream._buffer)
    assert s.is_eof()


def test_feed_parser_exc(loop):
    def p(out, buf):
        yield  # read chunk
        raise ValueError()

    stream = parsers.StreamParser(loop=loop)
    s = stream.set_parser(p)

    stream.feed_data(b'line1')
    assert isinstance(s.exception(), ValueError)
    assert b'' == bytes(stream._buffer)


def test_feed_parser_stop(loop):
    def p(out, buf):
        yield  # chunk

    stream = parsers.StreamParser(loop=loop)
    stream.set_parser(p)

    stream.feed_data(b'line1')
    assert stream._parser is None
    assert b'' == bytes(stream._buffer)


def test_feed_eof_exc(loop):
    def p(out, buf):
        try:
            while True:
                yield  # read chunk
        except parsers.EofStream:
            raise ValueError()

    stream = parsers.StreamParser(loop=loop)
    s = stream.set_parser(p)

    stream.feed_data(b'line1')
    assert s.exception() is None

    stream.feed_eof()
    assert isinstance(s.exception(), ValueError)


def test_feed_eof_stop(loop):
    def p(out, buf):
        try:
            while True:
                yield  # read chunk
        except parsers.EofStream:
            out.feed_eof()

    stream = parsers.StreamParser(loop=loop)
    s = stream.set_parser(p)

    stream.feed_data(b'line1')
    stream.feed_eof()
    assert s._eof


def test_feed_eof_unhandled_eof(loop):
    def p(out, buf):
        while True:
            yield  # read chunk

    stream = parsers.StreamParser(loop=loop)
    s = stream.set_parser(p)

    stream.feed_data(b'line1')
    stream.feed_eof()
    assert not s.is_eof()
    assert isinstance(s.exception(), RuntimeError)


def test_feed_parser2(loop, lines_parser):
    stream = parsers.StreamParser(loop=loop)
    s = stream.set_parser(lines_parser)

    stream.feed_data(b'line1\r\nline2\r\n')
    stream.feed_eof()
    assert ([(bytearray(b'line1\r\n'), 7), (bytearray(b'line2\r\n'), 7)] ==
            list(s._buffer))
    assert b'' == bytes(stream._buffer)
    assert s._eof


def test_unset_parser_eof_exc(loop):
    def p(out, buf):
        try:
            while True:
                yield  # read chunk
        except parsers.EofStream:
            raise ValueError()

    stream = parsers.StreamParser(loop=loop)
    s = stream.set_parser(p)

    stream.feed_data(b'line1')
    stream.unset_parser()
    assert isinstance(s.exception(), ValueError)
    assert stream._parser is None


def test_unset_parser_eof_unhandled_eof(loop):
    def p(out, buf):
        while True:
            yield  # read chunk

    stream = parsers.StreamParser(loop=loop)
    s = stream.set_parser(p)

    stream.feed_data(b'line1')
    stream.unset_parser()
    assert isinstance(s.exception(), RuntimeError)
    assert not s.is_eof()


def test_unset_parser_stop(loop):
    def p(out, buf):
        try:
            while True:
                yield  # read chunk
        except parsers.EofStream:
            out.feed_eof()

    stream = parsers.StreamParser(loop=loop)
    s = stream.set_parser(p)

    stream.feed_data(b'line1')
    stream.unset_parser()
    assert s._eof


def test_eof_exc(loop):
    def p(out, buf):
        while True:
            yield  # read chunk

    class CustomEofErr(Exception):
        pass

    stream = parsers.StreamParser(eof_exc_class=CustomEofErr, loop=loop)
    s = stream.set_parser(p)

    stream.feed_eof()
    assert isinstance(s.exception(), CustomEofErr)
