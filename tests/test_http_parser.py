"""Tests for aiohttp/protocol.py"""

import asyncio
import unittest
import zlib
from unittest import mock

import pytest
from yarl import URL

import aiohttp
from aiohttp import CIMultiDict, errors, streams
from aiohttp.protocol import (DeflateBuffer, HttpPayloadParser,
                              HttpRequestParser, HttpResponseParser)


REQUEST_PARSERS = [HttpRequestParser]
RESPONSE_PARSERS = [HttpResponseParser]

try:
    from aiohttp import _parser
    REQUEST_PARSERS.append(_parser.HttpRequestParser)
    RESPONSE_PARSERS.append(_parser.HttpResponseParser)
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


@pytest.fixture(params=RESPONSE_PARSERS)
def response(loop, protocol, request):
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


def test_headers_multi_feed(parser):
    text1 = b'GET /test HTTP/1.1\r\n'
    text2 = b'test: line\r'
    text3 = b'\n continue\r\n\r\n'

    messages, upgrade, tail = parser.feed_data(text1)
    assert len(messages) == 0

    messages, upgrade, tail = parser.feed_data(text2)
    assert len(messages) == 0

    messages, upgrade, tail = parser.feed_data(text3)
    assert len(messages) == 1

    msg = messages[0][0]
    assert list(msg.headers.items()) == [('Test', 'line continue')]
    assert msg.raw_headers == ((b'test', b'line continue'),)
    assert not msg.should_close
    assert msg.compression is None
    assert not msg.upgrade


def test_parse_headers_multi(parser):
    text = (b'GET /test HTTP/1.1\r\n'
            b'Set-Cookie: c1=cookie1\r\n'
            b'Set-Cookie: c2=cookie2\r\n\r\n')

    messages, upgrade, tail = parser.feed_data(text)
    assert len(messages) == 1
    msg = messages[0][0]

    assert list(msg.headers.items()) == [('Set-Cookie', 'c1=cookie1'),
                                         ('Set-Cookie', 'c2=cookie2')]
    assert msg.raw_headers == ((b'Set-Cookie', b'c1=cookie1'),
                               (b'Set-Cookie', b'c2=cookie2'))
    assert not msg.should_close
    assert msg.compression is None


def test_conn_default_1_0(parser):
    text = b'GET /test HTTP/1.0\r\n\r\n'
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert msg.should_close


def test_conn_default_1_1(parser):
    text = b'GET /test HTTP/1.1\r\n\r\n'
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert not msg.should_close


def test_conn_close(parser):
    text = (b'GET /test HTTP/1.1\r\n'
            b'connection: close\r\n\r\n')
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert msg.should_close


def test_conn_close_1_0(parser):
    text = (b'GET /test HTTP/1.0\r\n'
            b'connection: close\r\n\r\n')
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert msg.should_close


def test_conn_keep_alive_1_0(parser):
    text = (b'GET /test HTTP/1.0\r\n'
            b'connection: keep-alive\r\n\r\n')
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert not msg.should_close


def test_conn_keep_alive_1_1(parser):
    text = (b'GET /test HTTP/1.1\r\n'
            b'connection: keep-alive\r\n\r\n')
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert not msg.should_close


def test_conn_other_1_0(parser):
    text = (b'GET /test HTTP/1.0\r\n'
            b'connection: test\r\n\r\n')
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert msg.should_close


def test_conn_other_1_1(parser):
    text = (b'GET /test HTTP/1.1\r\n'
            b'connection: test\r\n\r\n')
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert not msg.should_close


def test_request_chunked(parser):
    text = (b'GET /test HTTP/1.1\r\n'
            b'transfer-encoding: chunked\r\n\r\n')
    messages, upgrade, tail = parser.feed_data(text)
    msg, payload = messages[0]
    assert msg.chunked
    assert not upgrade
    assert isinstance(payload, streams.FlowControlStreamReader)


def test_conn_upgrade(parser):
    text = (b'GET /test HTTP/1.1\r\n'
            b'connection: upgrade\r\n'
            b'upgrade: websocket\r\n\r\n')
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert not msg.should_close
    assert msg.upgrade
    assert upgrade


def test_compression_deflate(parser):
    text = (b'GET /test HTTP/1.1\r\n'
            b'content-encoding: deflate\r\n\r\n')
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert msg.compression == 'deflate'


def test_compression_gzip(parser):
    text = (b'GET /test HTTP/1.1\r\n'
            b'content-encoding: gzip\r\n\r\n')
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert msg.compression == 'gzip'


def test_compression_unknown(parser):
    text = (b'GET /test HTTP/1.1\r\n'
            b'content-encoding: compress\r\n\r\n')
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert not msg.compression


def test_headers_connect(parser):
    text = (b'CONNECT www.google.com HTTP/1.1\r\n'
            b'content-length: 0\r\n\r\n')
    messages, upgrade, tail = parser.feed_data(text)
    msg, payload = messages[0]
    assert upgrade
    assert isinstance(payload, streams.FlowControlStreamReader)


def test_headers_old_websocket_key1(parser):
    text = (b'GET /test HTTP/1.1\r\n'
            b'SEC-WEBSOCKET-KEY1: line\r\n\r\n')

    with pytest.raises(errors.BadHttpMessage):
        parser.feed_data(text)


def test_headers_content_length_err_1(parser):
    text = (b'GET /test HTTP/1.1\r\n'
            b'content-length: line\r\n\r\n')

    with pytest.raises(errors.BadHttpMessage):
        parser.feed_data(text)


def test_headers_content_length_err_2(parser):
    text = (b'GET /test HTTP/1.1\r\n'
            b'content-length: -1\r\n\r\n')

    with pytest.raises(errors.BadHttpMessage):
        parser.feed_data(text)


def test_invalid_header(parser):
    text = (b'GET /test HTTP/1.1\r\n'
            b'test line\r\n\r\n')
    with pytest.raises(errors.BadHttpMessage):
        parser.feed_data(text)


def test_invalid_name(parser):
    text = (b'GET /test HTTP/1.1\r\n'
            b'test[]: line\r\n\r\n')

    with pytest.raises(errors.BadHttpMessage):
        parser.feed_data(text)


def test_max_header_field_size(parser):
    name = b'test' * 10 * 1024
    text = (b'GET /test HTTP/1.1\r\n' + name + b':data\r\n\r\n')

    with pytest.raises(errors.LineTooLong):
        parser.feed_data(text)


def test_max_header_value_size(parser):
    name = b'test' * 10 * 1024
    text = (b'GET /test HTTP/1.1\r\n'
            b'data:' + name + b'\r\n\r\n')

    with pytest.raises(errors.LineTooLong):
        parser.feed_data(text)


def test_max_header_value_size_continuation(parser):
    name = b'test' * 10 * 1024
    text = (b'GET /test HTTP/1.1\r\n'
            b'data: test\r\n ' + name + b'\r\n\r\n')

    with pytest.raises(errors.LineTooLong):
        parser.feed_data(text)


def test_http_request_parser(parser):
    text = b'GET /path HTTP/1.1\r\n\r\n'
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]

    assert msg == ('GET', '/path', (1, 1), CIMultiDict(), (),
                   False, None, False, False, URL('/path'))


def test_http_request_upgrade(parser):
    text = (b'GET /test HTTP/1.1\r\n'
            b'connection: upgrade\r\n'
            b'upgrade: websocket\r\n\r\n'
            b'some raw data')
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert not msg.should_close
    assert msg.upgrade
    assert upgrade
    assert tail == b'some raw data'


def test_http_request_parser_utf8(parser):
    text = 'GET /path HTTP/1.1\r\nx-test:тест\r\n\r\n'.encode('utf-8')
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]

    assert msg == ('GET', '/path', (1, 1),
                   CIMultiDict([('X-TEST', 'тест')]),
                   ((b'x-test', 'тест'.encode('utf-8')),),
                   False, None, False, False, URL('/path'))


def test_http_request_parser_non_utf8(parser):
    text = 'GET /path HTTP/1.1\r\nx-test:тест\r\n\r\n'.encode('cp1251')
    msg = parser.feed_data(text)[0][0][0]

    assert msg == ('GET', '/path', (1, 1),
                   CIMultiDict([('X-TEST', 'тест'.encode('cp1251').decode(
                       'utf-8', 'surrogateescape'))]),
                   ((b'x-test', 'тест'.encode('cp1251')),),
                   False, None, False, False, URL('/path'))


def test_http_request_parser_two_slashes(parser):
    text = b'GET //path HTTP/1.1\r\n\r\n'
    msg = parser.feed_data(text)[0][0][0]

    assert msg[:-1] == ('GET', '//path', (1, 1), CIMultiDict(), (),
                        False, None, False, False)


def test_http_request_parser_bad_method(parser):
    with pytest.raises(errors.BadStatusLine):
        parser.feed_data(b'!12%()+=~$ /get HTTP/1.1\r\n\r\n')


def test_http_request_parser_bad_version(parser):
    with pytest.raises(errors.BadHttpMessage):
        parser.feed_data(b'GET //get HT/11\r\n\r\n')


def test_http_request_max_status_line(parser):
    with pytest.raises(errors.LineTooLong):
        parser.feed_data(
            b'GET /path' + b'test' * 10 * 1024 + b' HTTP/1.1\r\n\r\n')


def test_http_response_parser_utf8(response):
    text = 'HTTP/1.1 200 Ok\r\nx-test:тест\r\n\r\n'.encode('utf-8')

    messages, upgraded, tail = response.feed_data(text)
    assert len(messages) == 1
    msg = messages[0][0]

    assert msg.version == (1, 1)
    assert msg.code == 200
    assert msg.reason == 'Ok'
    assert msg.headers == CIMultiDict([('X-TEST', 'тест')])
    assert msg.raw_headers == ((b'x-test', 'тест'.encode('utf-8')),)
    assert not upgraded
    assert not tail


def test_http_response_parser_bad_status_line_too_long(response):
    with pytest.raises(errors.LineTooLong):
        response.feed_data(
            b'HTTP/1.1 200 Ok' + b'test' * 10 * 1024 + b'\r\n\r\n')


def test_http_response_parser_bad_version(response):
    with pytest.raises(errors.BadHttpMessage):
        response.feed_data(b'HT/11 200 Ok\r\n\r\n')


def test_http_response_parser_no_reason(response):
    msg = response.feed_data(b'HTTP/1.1 200\r\n\r\n')[0][0][0]

    assert msg.version == (1, 1)
    assert msg.code == 200
    assert not msg.reason


def test_http_response_parser_bad(response):
    with pytest.raises(errors.BadHttpMessage):
        response.feed_data(b'HTT/1\r\n\r\n')


def test_http_response_parser_code_under_100(response):
    msg = response.feed_data(b'HTTP/1.1 99 test\r\n\r\n')[0][0][0]
    assert msg.code == 99


def test_http_response_parser_code_above_999(response):
    with pytest.raises(errors.BadHttpMessage):
        response.feed_data(b'HTTP/1.1 9999 test\r\n\r\n')


def test_http_response_parser_code_not_int(response):
    with pytest.raises(errors.BadHttpMessage):
        response.feed_data(b'HTTP/1.1 ttt test\r\n\r\n')


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
