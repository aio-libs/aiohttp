"""Tests for aiohttp/protocol.py"""

import asyncio
import zlib
import unittest
import unittest.mock

import aiohttp
from aiohttp import errors
from aiohttp import protocol
from aiohttp import CIMultiDict


class ParseHeadersTests(unittest.TestCase):

    def setUp(self):
        asyncio.set_event_loop(None)

        self.parser = protocol.HttpParser(8190, 32768, 8190)

    def test_parse_headers(self):
        hdrs = ('', 'test: line', ' continue',
                'test2: data', '', '')

        headers, close, compression = self.parser.parse_headers(hdrs)

        self.assertEqual(list(headers.items()),
                         [('TEST', 'line\r\n continue'), ('TEST2', 'data')])
        self.assertIsNone(close)
        self.assertIsNone(compression)

    def test_parse_headers_multi(self):
        hdrs = ('',
                'Set-Cookie: c1=cookie1',
                'Set-Cookie: c2=cookie2', '')

        headers, close, compression = self.parser.parse_headers(hdrs)

        self.assertEqual(list(headers.items()),
                         [('SET-COOKIE', 'c1=cookie1'),
                          ('SET-COOKIE', 'c2=cookie2')])
        self.assertIsNone(close)
        self.assertIsNone(compression)

    def test_conn_close(self):
        headers, close, compression = self.parser.parse_headers(
            ['', 'connection: close', ''])
        self.assertTrue(close)

    def test_conn_keep_alive(self):
        headers, close, compression = self.parser.parse_headers(
            ['', 'connection: keep-alive', ''])
        self.assertFalse(close)

    def test_conn_other(self):
        headers, close, compression = self.parser.parse_headers(
            ['', 'connection: test', '', ''])
        self.assertIsNone(close)

    def test_compression_gzip(self):
        headers, close, compression = self.parser.parse_headers(
            ['', 'content-encoding: gzip', '', ''])
        self.assertEqual('gzip', compression)

    def test_compression_deflate(self):
        headers, close, compression = self.parser.parse_headers(
            ['', 'content-encoding: deflate', '', ''])
        self.assertEqual('deflate', compression)

    def test_compression_unknown(self):
        headers, close, compression = self.parser.parse_headers(
            ['', 'content-encoding: compress', '', ''])
        self.assertIsNone(compression)

    def test_max_field_size(self):
        with self.assertRaises(errors.LineTooLong) as cm:
            parser = protocol.HttpParser(8190, 32768, 5)
            parser.parse_headers(
                ['', 'test: line data data\r\n', 'data\r\n', '\r\n'])
        self.assertIn("limit request headers fields size", str(cm.exception))

    def test_max_continuation_headers_size(self):
        with self.assertRaises(errors.LineTooLong) as cm:
            parser = protocol.HttpParser(8190, 32768, 5)
            parser.parse_headers(['', 'test: line\r\n', ' test\r\n', '\r\n'])
        self.assertIn("limit request headers fields size", str(cm.exception))

    def test_invalid_header(self):
        with self.assertRaisesRegex(
                errors.InvalidHeader,
                "(400, message='Invalid HTTP Header: test line)"):
            self.parser.parse_headers(['', 'test line\r\n', '\r\n'])

    def test_invalid_name(self):
        with self.assertRaisesRegex(
                errors.InvalidHeader,
                "(400, message='Invalid HTTP Header: TEST..)"):
            self.parser.parse_headers(['', 'test[]: line\r\n', '\r\n'])


class DeflateBufferTests(unittest.TestCase):

    def setUp(self):
        self.stream = unittest.mock.Mock()
        asyncio.set_event_loop(None)

    def test_feed_data(self):
        buf = aiohttp.FlowControlDataQueue(self.stream)
        dbuf = protocol.DeflateBuffer(buf, 'deflate')

        dbuf.zlib = unittest.mock.Mock()
        dbuf.zlib.decompress.return_value = b'line'

        dbuf.feed_data(b'data')
        self.assertEqual([b'line'], list(buf._buffer))

    def test_feed_data_err(self):
        buf = aiohttp.FlowControlDataQueue(self.stream)
        dbuf = protocol.DeflateBuffer(buf, 'deflate')

        exc = ValueError()
        dbuf.zlib = unittest.mock.Mock()
        dbuf.zlib.decompress.side_effect = exc

        self.assertRaises(errors.ContentEncodingError, dbuf.feed_data, b'data')

    def test_feed_eof(self):
        buf = aiohttp.FlowControlDataQueue(self.stream)
        dbuf = protocol.DeflateBuffer(buf, 'deflate')

        dbuf.zlib = unittest.mock.Mock()
        dbuf.zlib.flush.return_value = b'line'

        dbuf.feed_eof()
        self.assertEqual([b'line'], list(buf._buffer))
        self.assertTrue(buf._eof)

    def test_feed_eof_err(self):
        buf = aiohttp.FlowControlDataQueue(self.stream)
        dbuf = protocol.DeflateBuffer(buf, 'deflate')

        dbuf.zlib = unittest.mock.Mock()
        dbuf.zlib.flush.return_value = b'line'
        dbuf.zlib.eof = False

        self.assertRaises(errors.ContentEncodingError, dbuf.feed_eof)


class ParsePayloadTests(unittest.TestCase):

    def setUp(self):
        self.stream = unittest.mock.Mock()
        asyncio.set_event_loop(None)

    def test_parse_eof_payload(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpPayloadParser(None).parse_eof_payload(out, buf)
        next(p)
        p.send(b'data')
        try:
            p.throw(aiohttp.EofStream())
        except StopIteration:
            pass

        self.assertEqual([b'data'], list(out._buffer))

    def test_parse_length_payload(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpPayloadParser(None).parse_length_payload(out, buf, 4)
        next(p)
        p.send(b'da')
        p.send(b't')
        try:
            p.send(b'aline')
        except StopIteration:
            pass

        self.assertEqual(3, len(out._buffer))
        self.assertEqual(b'data', b''.join(out._buffer))
        self.assertEqual(b'line', bytes(buf))

    def test_parse_length_payload_eof(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpPayloadParser(None).parse_length_payload(out, buf, 4)
        next(p)
        p.send(b'da')
        self.assertRaises(aiohttp.EofStream, p.throw, aiohttp.EofStream)

    def test_parse_chunked_payload(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpPayloadParser(None).parse_chunked_payload(out, buf)
        next(p)
        try:
            p.send(b'4\r\ndata\r\n4\r\nline\r\n0\r\ntest\r\n')
        except StopIteration:
            pass
        self.assertEqual(b'dataline', b''.join(out._buffer))
        self.assertEqual(b'', bytes(buf))

    def test_parse_chunked_payload_chunks(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpPayloadParser(None).parse_chunked_payload(out, buf)
        next(p)
        p.send(b'4\r\ndata\r')
        p.send(b'\n4')
        p.send(b'\r')
        p.send(b'\n')
        p.send(b'line\r\n0\r\n')
        self.assertRaises(StopIteration, p.send, b'test\r\n')
        self.assertEqual(b'dataline', b''.join(out._buffer))

    def test_parse_chunked_payload_incomplete(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpPayloadParser(None).parse_chunked_payload(out, buf)
        next(p)
        p.send(b'4\r\ndata\r\n')
        self.assertRaises(aiohttp.EofStream, p.throw, aiohttp.EofStream)

    def test_parse_chunked_payload_extension(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpPayloadParser(None).parse_chunked_payload(out, buf)
        next(p)
        try:
            p.send(b'4;test\r\ndata\r\n4\r\nline\r\n0\r\ntest\r\n')
        except StopIteration:
            pass
        self.assertEqual(b'dataline', b''.join(out._buffer))

    def test_parse_chunked_payload_size_error(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpPayloadParser(None).parse_chunked_payload(out, buf)
        next(p)
        self.assertRaises(errors.TransferEncodingError, p.send, b'blah\r\n')

    def test_http_payload_parser_length_broken(self):
        msg = protocol.RawRequestMessage(
            'GET', '/', (1, 1),
            CIMultiDict([('CONTENT-LENGTH', 'qwe')]),
            None, None)
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpPayloadParser(msg)(out, buf)
        self.assertRaises(errors.InvalidHeader, next, p)

    def test_http_payload_parser_length_wrong(self):
        msg = protocol.RawRequestMessage(
            'GET', '/', (1, 1),
            CIMultiDict([('CONTENT-LENGTH', '-1')]), None, None)
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpPayloadParser(msg)(out, buf)
        self.assertRaises(errors.InvalidHeader, next, p)

    def test_http_payload_parser_length(self):
        msg = protocol.RawRequestMessage(
            'GET', '/', (1, 1),
            CIMultiDict([('CONTENT-LENGTH', '2')]), None, None)
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpPayloadParser(msg)(out, buf)
        next(p)
        try:
            p.send(b'1245')
        except StopIteration:
            pass

        self.assertEqual(b'12', b''.join(out._buffer))
        self.assertEqual(b'45', bytes(buf))

    def test_http_payload_parser_no_length(self):
        msg = protocol.RawRequestMessage(
            'GET', '/', (1, 1), CIMultiDict(), None, None)
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpPayloadParser(msg, readall=False)(out, buf)
        self.assertRaises(StopIteration, next, p)
        self.assertEqual(b'', b''.join(out._buffer))
        self.assertTrue(out._eof)

    _comp = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    _COMPRESSED = b''.join([_comp.compress(b'data'), _comp.flush()])

    def test_http_payload_parser_deflate(self):
        msg = protocol.RawRequestMessage(
            'GET', '/', (1, 1),
            CIMultiDict([('CONTENT-LENGTH', len(self._COMPRESSED))]),
            None, 'deflate')

        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpPayloadParser(msg)(out, buf)
        next(p)
        self.assertRaises(StopIteration, p.send, self._COMPRESSED)
        self.assertEqual(b'data', b''.join(out._buffer))

    def test_http_payload_parser_deflate_disabled(self):
        msg = protocol.RawRequestMessage(
            'GET', '/', (1, 1),
            CIMultiDict([('CONTENT-LENGTH', len(self._COMPRESSED))]),
            None, 'deflate')

        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpPayloadParser(msg, compression=False)(out, buf)
        next(p)
        self.assertRaises(StopIteration, p.send, self._COMPRESSED)
        self.assertEqual(self._COMPRESSED, b''.join(out._buffer))

    def test_http_payload_parser_websocket(self):
        msg = protocol.RawRequestMessage(
            'GET', '/', (1, 1),
            CIMultiDict([('SEC-WEBSOCKET-KEY1', '13')]), None, None)
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpPayloadParser(msg)(out, buf)
        next(p)
        self.assertRaises(StopIteration, p.send, b'1234567890')
        self.assertEqual(b'12345678', b''.join(out._buffer))

    def test_http_payload_parser_chunked(self):
        msg = protocol.RawRequestMessage(
            'GET', '/', (1, 1),
            CIMultiDict([('TRANSFER-ENCODING', 'chunked')]),
            None, None)
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpPayloadParser(msg)(out, buf)
        next(p)
        self.assertRaises(StopIteration, p.send,
                          b'4;test\r\ndata\r\n4\r\nline\r\n0\r\ntest\r\n')
        self.assertEqual(b'dataline', b''.join(out._buffer))

    def test_http_payload_parser_eof(self):
        msg = protocol.RawRequestMessage(
            'GET', '/', (1, 1), CIMultiDict(), None, None)
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpPayloadParser(msg, readall=True)(out, buf)
        next(p)
        p.send(b'data')
        p.send(b'line')
        self.assertRaises(StopIteration, p.throw, aiohttp.EofStream())
        self.assertEqual(b'dataline', b''.join(out._buffer))

    def test_http_payload_parser_length_zero(self):
        msg = protocol.RawRequestMessage(
            'GET', '/', (1, 1),
            CIMultiDict([('CONTENT-LENGTH', '0')]), None, None)
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpPayloadParser(msg)(out, buf)
        self.assertRaises(StopIteration, next, p)
        self.assertEqual(b'', b''.join(out._buffer))


class ParseRequestTests(unittest.TestCase):

    def setUp(self):
        self.stream = unittest.mock.Mock()
        asyncio.set_event_loop(None)

    def test_http_request_parser_max_headers(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpRequestParser(8190, 20, 8190)(out, buf)
        next(p)

        self.assertRaises(
            errors.LineTooLong,
            p.send,
            b'get /path HTTP/1.1\r\ntest: line\r\ntest2: data\r\n\r\n')

    def test_http_request_parser(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpRequestParser()(out, buf)
        next(p)
        try:
            p.send(b'get /path HTTP/1.1\r\n\r\n')
        except StopIteration:
            pass
        result = out._buffer[0]
        self.assertEqual(
            ('GET', '/path', (1, 1), CIMultiDict(), False, None),
            result)

    def test_http_request_parser_utf8(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpRequestParser()(out, buf)
        next(p)
        msg = 'get /path HTTP/1.1\r\nx-test:тест\r\n\r\n'.encode('utf-8')
        try:
            p.send(msg)
        except StopIteration:
            pass
        result = out._buffer[0]
        self.assertEqual(
            ('GET', '/path', (1, 1),
             CIMultiDict([('X-TEST', 'тест')]), False, None),
            result)

    def test_http_request_parser_eof(self):
        # HttpRequestParser does fail on EofStream()
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpRequestParser()(out, buf)
        next(p)
        p.send(b'get /path HTTP/1.1\r\n')
        try:
            p.throw(aiohttp.EofStream())
        except aiohttp.EofStream:
            pass
        self.assertFalse(out._buffer)

    def test_http_request_parser_two_slashes(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpRequestParser()(out, buf)
        next(p)
        try:
            p.send(b'get //path HTTP/1.1\r\n\r\n')
        except StopIteration:
            pass
        self.assertEqual(
            ('GET', '//path', (1, 1), CIMultiDict(), False, None),
            out._buffer[0])

    def test_http_request_parser_bad_status_line(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpRequestParser()(out, buf)
        next(p)
        self.assertRaises(
            errors.BadStatusLine, p.send, b'\r\n\r\n')

    def test_http_request_parser_bad_method(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpRequestParser()(out, buf)
        next(p)
        self.assertRaises(
            errors.BadStatusLine,
            p.send, b'!12%()+=~$ /get HTTP/1.1\r\n\r\n')

    def test_http_request_parser_bad_version(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpRequestParser()(out, buf)
        next(p)
        self.assertRaises(
            errors.BadStatusLine,
            p.send, b'GET //get HT/11\r\n\r\n')


class ParseResponseTests(unittest.TestCase):

    def setUp(self):
        self.stream = unittest.mock.Mock()
        asyncio.set_event_loop(None)

    def test_http_response_parser_utf8(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpResponseParser()(out, buf)
        next(p)
        msg = 'HTTP/1.1 200 Ok\r\nx-test:тест\r\n\r\n'.encode('utf-8')
        try:
            p.send(msg)
        except StopIteration:
            pass
        v, s, r, h = out._buffer[0][:4]
        self.assertEqual(v, (1, 1))
        self.assertEqual(s, 200)
        self.assertEqual(r, 'Ok')
        self.assertEqual(h, CIMultiDict([('X-TEST', 'тест')]))

    def test_http_response_parser_bad_status_line(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpResponseParser()(out, buf)
        next(p)
        self.assertRaises(errors.BadStatusLine, p.send, b'\r\n\r\n')

    def test_http_response_parser_bad_status_line_too_long(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpResponseParser(
            max_headers=2, max_line_size=2)(out, buf)
        next(p)
        self.assertRaises(
            errors.LineTooLong, p.send, b'HTTP/1.1 200 Ok\r\n\r\n')

    def test_http_response_parser_bad_status_line_eof(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpResponseParser()(out, buf)
        next(p)
        self.assertRaises(aiohttp.EofStream, p.throw, aiohttp.EofStream())

    def test_http_response_parser_bad_version(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpResponseParser()(out, buf)
        next(p)
        with self.assertRaises(errors.BadStatusLine) as cm:
            p.send(b'HT/11 200 Ok\r\n\r\n')
        self.assertEqual('HT/11 200 Ok', cm.exception.args[0])

    def test_http_response_parser_no_reason(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpResponseParser()(out, buf)
        next(p)
        try:
            p.send(b'HTTP/1.1 200\r\n\r\n')
        except StopIteration:
            pass
        v, s, r = out._buffer[0][:3]
        self.assertEqual(v, (1, 1))
        self.assertEqual(s, 200)
        self.assertEqual(r, '')

    def test_http_response_parser_bad(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpResponseParser()(out, buf)
        next(p)
        with self.assertRaises(errors.BadStatusLine) as cm:
            p.send(b'HTT/1\r\n\r\n')
        self.assertIn('HTT/1', str(cm.exception))

    def test_http_response_parser_code_under_100(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpResponseParser()(out, buf)
        next(p)
        with self.assertRaises(errors.BadStatusLine) as cm:
            p.send(b'HTTP/1.1 99 test\r\n\r\n')
        self.assertIn('HTTP/1.1 99 test', str(cm.exception))

    def test_http_response_parser_code_above_999(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpResponseParser()(out, buf)
        next(p)
        with self.assertRaises(errors.BadStatusLine) as cm:
            p.send(b'HTTP/1.1 9999 test\r\n\r\n')
        self.assertIn('HTTP/1.1 9999 test', str(cm.exception))

    def test_http_response_parser_code_not_int(self):
        out = aiohttp.FlowControlDataQueue(self.stream)
        buf = aiohttp.ParserBuffer()
        p = protocol.HttpResponseParser()(out, buf)
        next(p)
        with self.assertRaises(errors.BadStatusLine) as cm:
            p.send(b'HTTP/1.1 ttt test\r\n\r\n')
        self.assertIn('HTTP/1.1 ttt test', str(cm.exception))
