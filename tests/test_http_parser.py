"""Tests for aiohttp/protocol.py"""

import asyncio
import unittest
import zlib
from unittest import mock

import pytest
from yarl import URL

import aiohttp
from aiohttp import CIMultiDict, errors
from aiohttp.protocol import (DeflateBuffer, HttpParser, HttpPayloadParser,
                              HttpRequestParser, HttpResponseParser)


REQUEST_PARSERS = [HttpRequestParser]

try:
    from aiohttp import _parser
    REQUEST_PARSERS.append(_parser.HttpRequestParser)
except ImportError:  # pragma: no cover
    pass


@pytest.fixture
def loop():
    return mock.Mock()


@pytest.fixture
def protocol():
    return mock.Mock()


@pytest.fixture(params=REQUEST_PARSERS)
def parser(loop, protocol, request):
    """Parser implementations"""
    return request.param(protocol, loop, 8190, 32768, 8190)


def test_parse_headers(parser):
    text = b'''GET /test HTTP/1.1\r
test: line\r
 continue\r
test2: data\r
\r
'''
    messages, upgrade, tail = parser.feed_data(text)

    assert len(messages) == 1
    msg = messages[0][0]

    assert list(msg.headers.items()) == [('Test', 'line continue'),
                                         ('Test2', 'data')]
    assert msg.raw_headers == ((b'test', b'line continue'),
                               (b'test2', b'data'))
    assert not msg.should_close
    assert msg.compression is None
    assert not msg.upgrade


class TestParseHeaders(unittest.TestCase):

    def setUp(self):
        asyncio.set_event_loop(None)

        self.parser = HttpParser(8190, 32768, 8190)

    def test_parse_headers_multi(self):
        hdrs = (b'',
                b'Set-Cookie: c1=cookie1',
                b'Set-Cookie: c2=cookie2', '')

        headers, raw_headers, close, \
            compression, _, _ = self.parser.parse_headers(hdrs)

        self.assertEqual(list(headers.items()),
                         [('Set-Cookie', 'c1=cookie1'),
                          ('Set-Cookie', 'c2=cookie2')])
        self.assertEqual(raw_headers,
                         ((b'Set-Cookie', b'c1=cookie1'),
                          (b'Set-Cookie', b'c2=cookie2')))
        self.assertIsNone(close)
        self.assertIsNone(compression)

    def test_conn_close(self):
        headers, raw_headers, close, \
            compression, _, _ = self.parser.parse_headers(
                [b'', b'connection: close', b''])
        self.assertTrue(close)

    def test_conn_keep_alive(self):
        headers, raw_headers, close, \
            compression, _, _ = self.parser.parse_headers(
                [b'', b'connection: keep-alive', b''])
        self.assertFalse(close)

    def test_conn_other(self):
        headers, raw_headers, close, \
            compression, _, _ = self.parser.parse_headers(
                [b'', b'connection: test', b'', b''])
        self.assertIsNone(close)

    def test_conn_chunked(self):
        headers, raw_headers, close, \
            compression, _, chunked = self.parser.parse_headers(
                [b'', b'transfer-encoding: chunked', b'', b''])
        self.assertTrue(chunked)

    def test_conn_upgrade(self):
        headers, raw_headers, close, \
            compression, upgrade, _ = self.parser.parse_headers(
                [b'', b'connection: upgrade', b'', b''])
        self.assertTrue(upgrade)

    def test_compression_gzip(self):
        headers, raw_headers, close, \
            compression, upgrade, _ = self.parser.parse_headers(
                [b'', b'content-encoding: gzip', b'', b''])
        self.assertEqual('gzip', compression)

    def test_compression_deflate(self):
        headers, raw_headers, close, \
            compression, upgrade, _ = self.parser.parse_headers(
                [b'', b'content-encoding: deflate', b'', b''])
        self.assertEqual('deflate', compression)

    def test_compression_unknown(self):
        headers, raw_headers, close, \
            compression, _, _ = self.parser.parse_headers(
                [b'', b'content-encoding: compress', b'', b''])
        self.assertIsNone(compression)

    def test_max_field_size(self):
        with self.assertRaises(errors.LineTooLong) as cm:
            parser = HttpParser(None, None, 8190, 32768, 5)
            parser.parse_headers(
                [b'', b'test: line data data\r\n', b'data\r\n', b'\r\n'])
        self.assertIn("request header field test", str(cm.exception))

    def test_max_continuation_headers_size(self):
        with self.assertRaises(errors.LineTooLong) as cm:
            parser = HttpParser(None, None, 8190, 32768, 5)
            parser.parse_headers([b'', b'test: line\r\n',
                                  b' test\r\n', b'\r\n'])
        self.assertIn("request header field test", str(cm.exception))

    def test_max_header_size(self):
        with self.assertRaises(errors.LineTooLong) as cm:
            parser = HttpParser(None, None, 5, 5, 5)
            parser.parse_headers(
                [b'', b'test: line data data\r\n', b'data\r\n', b'\r\n'])
        self.assertIn("request header", str(cm.exception))

    def test_invalid_header(self):
        with self.assertRaisesRegex(
                errors.InvalidHeader,
                "(400, message='Invalid HTTP Header: test line)"):
            self.parser.parse_headers([b'', b'test line\r\n', b'\r\n'])

    def test_invalid_name(self):
        with self.assertRaisesRegex(
                errors.InvalidHeader,
                "(400, message='Invalid HTTP Header: test..)"):
            self.parser.parse_headers([b'', b'test[]: line\r\n', b'\r\n'])


class TestDeflateBuffer(unittest.TestCase):

    def setUp(self):
        self.stream = mock.Mock()
        asyncio.set_event_loop(None)

    def test_feed_data(self):
        buf = aiohttp.FlowControlDataQueue(self.stream)
        dbuf = DeflateBuffer(buf, 'deflate')

        dbuf.zlib = mock.Mock()
        dbuf.zlib.decompress.return_value = b'line'

        dbuf.feed_data(b'data', 4)
        self.assertEqual([b'line'], list(d for d, _ in buf._buffer))

    def test_feed_data_err(self):
        buf = aiohttp.FlowControlDataQueue(self.stream)
        dbuf = DeflateBuffer(buf, 'deflate')

        exc = ValueError()
        dbuf.zlib = mock.Mock()
        dbuf.zlib.decompress.side_effect = exc

        self.assertRaises(
            errors.ContentEncodingError, dbuf.feed_data, b'data', 4)

    def test_feed_eof(self):
        buf = aiohttp.FlowControlDataQueue(self.stream)
        dbuf = DeflateBuffer(buf, 'deflate')

        dbuf.zlib = mock.Mock()
        dbuf.zlib.flush.return_value = b'line'

        dbuf.feed_eof()
        self.assertEqual([b'line'], list(d for d, _ in buf._buffer))
        self.assertTrue(buf._eof)

    def test_feed_eof_err(self):
        buf = aiohttp.FlowControlDataQueue(self.stream)
        dbuf = DeflateBuffer(buf, 'deflate')

        dbuf.zlib = mock.Mock()
        dbuf.zlib.flush.return_value = b'line'
        dbuf.zlib.eof = False

        self.assertRaises(errors.ContentEncodingError, dbuf.feed_eof)

    def test_empty_body(self):
        buf = aiohttp.FlowControlDataQueue(self.stream)
        dbuf = DeflateBuffer(buf, 'deflate')
        dbuf.feed_eof()

        self.assertTrue(buf.at_eof())


class TestParsePayload(unittest.TestCase):

    def setUp(self):
        self.stream = mock.Mock()
        asyncio.set_event_loop(None)

    def test_parse_eof_payload(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        p = HttpPayloadParser(out, readall=True)
        p.feed_data(b'data')
        p.feed_eof()

        self.assertTrue(out.is_eof())
        self.assertEqual([(bytearray(b'data'), 4)], list(out._buffer))

    def test_parse_length_payload(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        p = HttpPayloadParser(out, length=4)
        p.feed_data(b'da')
        p.feed_data(b't')
        eof, tail = p.feed_data(b'aline')

        self.assertEqual(3, len(out._buffer))
        self.assertEqual(b'data', b''.join(d for d, _ in out._buffer))
        self.assertEqual(b'line', tail)

    def test_parse_length_payload_eof(self):
        out = aiohttp.FlowControlDataQueue(self.stream)

        p = HttpPayloadParser(out, length=4)
        p.feed_data(b'da')
        p.feed_eof()

    def test_parse_chunked_payload(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        p = HttpPayloadParser(out, chunked=True)
        eof, tail = p.feed_data(b'4\r\ndata\r\n4\r\nline\r\n0\r\ntest\r\n')
        self.assertEqual(b'dataline', b''.join(d for d, _ in out._buffer))
        self.assertEqual(b'', tail)
        self.assertTrue(eof)
        self.assertTrue(out.is_eof())

    def test_parse_chunked_payload_chunks(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        p = HttpPayloadParser(out, chunked=True)
        p.feed_data(b'4\r\ndata\r')
        p.feed_data(b'\n4')
        p.feed_data(b'\r')
        p.feed_data(b'\n')
        p.feed_data(b'line\r\n0\r\n')
        eof, tail = p.feed_data(b'test\r\n')
        self.assertEqual(b'dataline', b''.join(d for d, _ in out._buffer))
        self.assertTrue(eof)

    def test_parse_chunked_payload_chunk_extension(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        p = HttpPayloadParser(out, chunked=True)
        eof, tail = p.feed_data(
            b'4;test\r\ndata\r\n4\r\nline\r\n0\r\ntest\r\n')
        self.assertEqual(b'dataline', b''.join(d for d, _ in out._buffer))
        self.assertTrue(eof)

    def test_parse_chunked_payload_size_error(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        p = HttpPayloadParser(out, chunked=True)
        self.assertRaises(
            errors.TransferEncodingError, p.feed_data, b'blah\r\n')
        self.assertIsInstance(out.exception(), errors.TransferEncodingError)

    def test_http_payload_parser_length(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        p = HttpPayloadParser(out, length=2)
        eof, tail = p.feed_data(b'1245')
        self.assertTrue(eof)

        self.assertEqual(b'12', b''.join(d for d, _ in out._buffer))
        self.assertEqual(b'45', tail)

    _comp = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    _COMPRESSED = b''.join([_comp.compress(b'data'), _comp.flush()])

    def test_http_payload_parser_deflate(self):
        length = len(self._COMPRESSED)
        out = aiohttp.FlowControlDataQueue(self.stream)
        p = HttpPayloadParser(
            out, length=length, compression='deflate')
        p.feed_data(self._COMPRESSED)
        self.assertEqual(b'data', b''.join(d for d, _ in out._buffer))
        self.assertTrue(out.is_eof())

    def test_http_payload_parser_chunked(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        parser = HttpPayloadParser(out, chunked=True)
        assert not parser.done

        parser.feed_data(b'4;test\r\ndata\r\n4\r\nline\r\n0\r\ntest\r\n')
        self.assertEqual(b'dataline', b''.join(d for d, _ in out._buffer))
        self.assertTrue(out.is_eof())

    def test_http_payload_parser_eof(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        p = HttpPayloadParser(out, readall=True)
        assert not p.done

        p.feed_data(b'data')
        p.feed_data(b'line')
        p.feed_eof()
        self.assertEqual(b'dataline', b''.join(d for d, _ in out._buffer))
        self.assertTrue(out.is_eof())

    def test_http_payload_parser_length_zero(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        p = HttpPayloadParser(out, length=0)
        self.assertTrue(p.done)
        self.assertTrue(out.is_eof())


class TestParseRequest(unittest.TestCase):

    def setUp(self):
        self.stream = mock.Mock()
        asyncio.set_event_loop(None)

    def _test_http_request_parser_max_headers(self):
        p = HttpRequestParser(8190, 20, 8190)

        self.assertRaises(
            errors.LineTooLong,
            p.parse_message,
            b'get /path HTTP/1.1\r\ntest: line\r\ntest2: data\r\n\r\n'
            .split(b'\r\n'))

    def test_http_request_parser(self):
        p = HttpRequestParser()
        result = p.parse_message(b'get /path HTTP/1.1\r\n\r\n'.split(b'\r\n'))
        self.assertEqual(
            ('GET', '/path', (1, 1), CIMultiDict(), (),
             False, None, False, False, URL('/path')), result)

    def test_http_request_parser_utf8(self):
        p = HttpRequestParser()
        msg = 'get /path HTTP/1.1\r\nx-test:тест\r\n\r\n'.encode('utf-8')
        result = p.parse_message(msg.split(b'\r\n'))
        self.assertEqual(
            ('GET', '/path', (1, 1),
             CIMultiDict([('X-TEST', 'тест')]),
             ((b'x-test', 'тест'.encode('utf-8')),),
             False, None, False, False, URL('/path')),
            result)

    def test_http_request_parser_non_utf8(self):
        p = HttpRequestParser()
        msg = 'get /path HTTP/1.1\r\nx-test:тест\r\n\r\n'.encode('cp1251')
        result = p.parse_message(msg.split(b'\r\n'))
        self.assertEqual(
            ('GET', '/path', (1, 1),
             CIMultiDict([('X-TEST', 'тест'.encode('cp1251').decode(
                 'utf-8', 'surrogateescape'))]),
             ((b'x-test', 'тест'.encode('cp1251')),),
             False, None, False, False, URL('/path')),
            result)

    def test_http_request_parser_eof(self):
        # HttpRequestParser does fail on EofStream()
        p = HttpRequestParser()
        p.parse_message(b'get /path HTTP/1.1\r\n'.split(b'\r\n'))

    def test_http_request_parser_two_slashes(self):
        p = HttpRequestParser()
        result = p.parse_message(
            b'get //path HTTP/1.1\r\n\r\n'.split(b'\r\n'))
        self.assertEqual(
            ('GET', '//path', (1, 1), CIMultiDict(), (),
             False, None, False, False, URL('//path')),
            result)

    def test_http_request_parser_bad_status_line(self):
        p = HttpRequestParser()
        self.assertRaises(
            errors.BadStatusLine, p.parse_message, b'\r\n\r\n'.split(b'\r\n'))

    def test_http_request_parser_bad_method(self):
        p = HttpRequestParser()
        self.assertRaises(
            errors.BadStatusLine, p.parse_message,
            b'!12%()+=~$ /get HTTP/1.1\r\n\r\n'.split(b'\r\n'))

    def test_http_request_parser_bad_version(self):
        p = HttpRequestParser()
        self.assertRaises(
            errors.BadStatusLine,
            p.parse_message, b'GET //get HT/11\r\n\r\n'.split(b'\r\n'))


class TestParseResponse(unittest.TestCase):

    def setUp(self):
        self.stream = mock.Mock()
        asyncio.set_event_loop(None)

    def test_http_response_parser_utf8(self):
        p = HttpResponseParser()
        msg = 'HTTP/1.1 200 Ok\r\nx-test:тест\r\n\r\n'.encode('utf-8')
        result = p.parse_message(msg.split(b'\r\n'))
        self.assertEqual(result.version, (1, 1))
        self.assertEqual(result.code, 200)
        self.assertEqual(result.reason, 'Ok')
        self.assertEqual(result.headers, CIMultiDict([('X-TEST', 'тест')]))

    def test_http_response_parser_bad_status_line(self):
        p = HttpResponseParser()
        self.assertRaises(
            errors.BadStatusLine, p.parse_message, b'\r\n\r\n'.split(b'\r\n'))

    def _test_http_response_parser_bad_status_line_too_long(self):
        p = HttpResponseParser(
            max_headers=2, max_line_size=2)
        self.assertRaises(
            errors.LineTooLong,
            p.parse_message, b'HTTP/1.1 200 Ok\r\n\r\n'.split(b'\r\n'))

    def test_http_response_parser_bad_version(self):
        p = HttpResponseParser()
        with self.assertRaises(errors.BadStatusLine) as cm:
            p.parse_message(b'HT/11 200 Ok\r\n\r\n'.split(b'\r\n'))
        self.assertEqual('HT/11 200 Ok', cm.exception.args[0])

    def test_http_response_parser_no_reason(self):
        p = HttpResponseParser()
        result = p.parse_message(b'HTTP/1.1 200\r\n\r\n'.split(b'\r\n'))
        self.assertEqual(result.version, (1, 1))
        self.assertEqual(result.code, 200)
        self.assertEqual(result.reason, '')

    def test_http_response_parser_bad(self):
        p = HttpResponseParser()
        with self.assertRaises(errors.BadStatusLine) as cm:
            p.parse_message(b'HTT/1\r\n\r\n'.split(b'\r\n'))
        self.assertIn('HTT/1', str(cm.exception))

    def test_http_response_parser_code_under_100(self):
        p = HttpResponseParser()
        with self.assertRaises(errors.BadStatusLine) as cm:
            p.parse_message(b'HTTP/1.1 99 test\r\n\r\n'.split(b'\r\n'))
        self.assertIn('HTTP/1.1 99 test', str(cm.exception))

    def test_http_response_parser_code_above_999(self):
        p = HttpResponseParser()
        with self.assertRaises(errors.BadStatusLine) as cm:
            p.parse_message(b'HTTP/1.1 9999 test\r\n\r\n'.split(b'\r\n'))
        self.assertIn('HTTP/1.1 9999 test', str(cm.exception))

    def test_http_response_parser_code_not_int(self):
        p = HttpResponseParser()
        with self.assertRaises(errors.BadStatusLine) as cm:
            p.parse_message(b'HTTP/1.1 ttt test\r\n\r\n'.split(b'\r\n'))
        self.assertIn('HTTP/1.1 ttt test', str(cm.exception))
