# Tests for aiohttp/protocol.py

import asyncio
from typing import Any, List
from unittest import mock
from urllib.parse import quote

import pytest
from multidict import CIMultiDict
from yarl import URL

import aiohttp
from aiohttp import http_exceptions, streams
from aiohttp.http_parser import (
    NO_EXTENSIONS,
    DeflateBuffer,
    HttpPayloadParser,
    HttpRequestParserPy,
    HttpResponseParserPy,
)

try:
    import brotli
except ImportError:
    brotli = None


REQUEST_PARSERS = [HttpRequestParserPy]
RESPONSE_PARSERS = [HttpResponseParserPy]

try:
    from aiohttp.http_parser import HttpRequestParserC, HttpResponseParserC

    REQUEST_PARSERS.append(HttpRequestParserC)
    RESPONSE_PARSERS.append(HttpResponseParserC)
except ImportError:  # pragma: no cover
    pass


@pytest.fixture
def protocol():
    return mock.Mock()


def _gen_ids(parsers: List[Any]) -> List[str]:
    return [
        "py-parser" if parser.__module__ == "aiohttp.http_parser" else "c-parser"
        for parser in parsers
    ]


@pytest.fixture(params=REQUEST_PARSERS, ids=_gen_ids(REQUEST_PARSERS))
def parser(loop: Any, protocol: Any, request: Any):
    # Parser implementations
    return request.param(
        protocol,
        loop,
        2**16,
        max_line_size=8190,
        max_headers=32768,
        max_field_size=8190,
    )


@pytest.fixture(params=REQUEST_PARSERS, ids=_gen_ids(REQUEST_PARSERS))
def request_cls(request: Any):
    # Request Parser class
    return request.param


@pytest.fixture(params=RESPONSE_PARSERS, ids=_gen_ids(RESPONSE_PARSERS))
def response(loop: Any, protocol: Any, request: Any):
    # Parser implementations
    return request.param(
        protocol,
        loop,
        2**16,
        max_line_size=8190,
        max_headers=32768,
        max_field_size=8190,
    )


@pytest.fixture(params=RESPONSE_PARSERS, ids=_gen_ids(RESPONSE_PARSERS))
def response_cls(request: Any):
    # Parser implementations
    return request.param


@pytest.fixture
def stream():
    return mock.Mock()


@pytest.mark.skipif(NO_EXTENSIONS, reason="Extentions available but not imported")
def test_c_parser_loaded():
    assert "HttpRequestParserC" in dir(aiohttp.http_parser)
    assert "HttpResponseParserC" in dir(aiohttp.http_parser)
    assert "RawRequestMessageC" in dir(aiohttp.http_parser)
    assert "RawResponseMessageC" in dir(aiohttp.http_parser)


def test_parse_headers(parser: Any) -> None:
    text = b"""GET /test HTTP/1.1\r
test: line\r
 continue\r
test2: data\r
\r
"""
    messages, upgrade, tail = parser.feed_data(text)
    assert len(messages) == 1
    msg = messages[0][0]

    assert list(msg.headers.items()) == [("test", "line continue"), ("test2", "data")]
    assert msg.raw_headers == ((b"test", b"line continue"), (b"test2", b"data"))
    assert not msg.should_close
    assert msg.compression is None
    assert not msg.upgrade


def test_parse(parser) -> None:
    text = b"GET /test HTTP/1.1\r\n\r\n"
    messages, upgrade, tail = parser.feed_data(text)
    assert len(messages) == 1
    msg, _ = messages[0]
    assert msg.compression is None
    assert not msg.upgrade
    assert msg.method == "GET"
    assert msg.path == "/test"
    assert msg.version == (1, 1)


async def test_parse_body(parser) -> None:
    text = b"GET /test HTTP/1.1\r\nContent-Length: 4\r\n\r\nbody"
    messages, upgrade, tail = parser.feed_data(text)
    assert len(messages) == 1
    _, payload = messages[0]
    body = await payload.read(4)
    assert body == b"body"


async def test_parse_body_with_CRLF(parser) -> None:
    text = b"\r\nGET /test HTTP/1.1\r\nContent-Length: 4\r\n\r\nbody"
    messages, upgrade, tail = parser.feed_data(text)
    assert len(messages) == 1
    _, payload = messages[0]
    body = await payload.read(4)
    assert body == b"body"


def test_parse_delayed(parser) -> None:
    text = b"GET /test HTTP/1.1\r\n"
    messages, upgrade, tail = parser.feed_data(text)
    assert len(messages) == 0
    assert not upgrade

    messages, upgrade, tail = parser.feed_data(b"\r\n")
    assert len(messages) == 1
    msg = messages[0][0]
    assert msg.method == "GET"


def test_headers_multi_feed(parser) -> None:
    text1 = b"GET /test HTTP/1.1\r\n"
    text2 = b"test: line\r"
    text3 = b"\n continue\r\n\r\n"

    messages, upgrade, tail = parser.feed_data(text1)
    assert len(messages) == 0

    messages, upgrade, tail = parser.feed_data(text2)
    assert len(messages) == 0

    messages, upgrade, tail = parser.feed_data(text3)
    assert len(messages) == 1

    msg = messages[0][0]
    assert list(msg.headers.items()) == [("test", "line continue")]
    assert msg.raw_headers == ((b"test", b"line continue"),)
    assert not msg.should_close
    assert msg.compression is None
    assert not msg.upgrade


def test_headers_split_field(parser) -> None:
    text1 = b"GET /test HTTP/1.1\r\n"
    text2 = b"t"
    text3 = b"es"
    text4 = b"t: value\r\n\r\n"

    messages, upgrade, tail = parser.feed_data(text1)
    messages, upgrade, tail = parser.feed_data(text2)
    messages, upgrade, tail = parser.feed_data(text3)
    assert len(messages) == 0
    messages, upgrade, tail = parser.feed_data(text4)
    assert len(messages) == 1

    msg = messages[0][0]
    assert list(msg.headers.items()) == [("test", "value")]
    assert msg.raw_headers == ((b"test", b"value"),)
    assert not msg.should_close
    assert msg.compression is None
    assert not msg.upgrade


def test_parse_headers_multi(parser) -> None:
    text = (
        b"GET /test HTTP/1.1\r\n"
        b"Set-Cookie: c1=cookie1\r\n"
        b"Set-Cookie: c2=cookie2\r\n\r\n"
    )

    messages, upgrade, tail = parser.feed_data(text)
    assert len(messages) == 1
    msg = messages[0][0]

    assert list(msg.headers.items()) == [
        ("Set-Cookie", "c1=cookie1"),
        ("Set-Cookie", "c2=cookie2"),
    ]
    assert msg.raw_headers == (
        (b"Set-Cookie", b"c1=cookie1"),
        (b"Set-Cookie", b"c2=cookie2"),
    )
    assert not msg.should_close
    assert msg.compression is None


def test_conn_default_1_0(parser) -> None:
    text = b"GET /test HTTP/1.0\r\n\r\n"
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert msg.should_close


def test_conn_default_1_1(parser) -> None:
    text = b"GET /test HTTP/1.1\r\n\r\n"
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert not msg.should_close


def test_conn_close(parser) -> None:
    text = b"GET /test HTTP/1.1\r\n" b"connection: close\r\n\r\n"
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert msg.should_close


def test_conn_close_1_0(parser) -> None:
    text = b"GET /test HTTP/1.0\r\n" b"connection: close\r\n\r\n"
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert msg.should_close


def test_conn_keep_alive_1_0(parser) -> None:
    text = b"GET /test HTTP/1.0\r\n" b"connection: keep-alive\r\n\r\n"
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert not msg.should_close


def test_conn_keep_alive_1_1(parser) -> None:
    text = b"GET /test HTTP/1.1\r\n" b"connection: keep-alive\r\n\r\n"
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert not msg.should_close


def test_conn_other_1_0(parser) -> None:
    text = b"GET /test HTTP/1.0\r\n" b"connection: test\r\n\r\n"
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert msg.should_close


def test_conn_other_1_1(parser) -> None:
    text = b"GET /test HTTP/1.1\r\n" b"connection: test\r\n\r\n"
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert not msg.should_close


def test_request_chunked(parser) -> None:
    text = b"GET /test HTTP/1.1\r\n" b"transfer-encoding: chunked\r\n\r\n"
    messages, upgrade, tail = parser.feed_data(text)
    msg, payload = messages[0]
    assert msg.chunked
    assert not upgrade
    assert isinstance(payload, streams.StreamReader)


def test_request_te_chunked_with_content_length(parser: Any) -> None:
    text = (
        b"GET /test HTTP/1.1\r\n"
        b"content-length: 1234\r\n"
        b"transfer-encoding: chunked\r\n\r\n"
    )
    with pytest.raises(
        http_exceptions.BadHttpMessage,
        match="Content-Length can't be present with Transfer-Encoding",
    ):
        parser.feed_data(text)


def test_request_te_chunked123(parser: Any) -> None:
    text = b"GET /test HTTP/1.1\r\n" b"transfer-encoding: chunked123\r\n\r\n"
    with pytest.raises(
        http_exceptions.BadHttpMessage,
        match="Request has invalid `Transfer-Encoding`",
    ):
        parser.feed_data(text)


def test_conn_upgrade(parser: Any) -> None:
    text = (
        b"GET /test HTTP/1.1\r\n"
        b"connection: upgrade\r\n"
        b"upgrade: websocket\r\n\r\n"
    )
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert not msg.should_close
    assert msg.upgrade
    assert upgrade


def test_compression_empty(parser) -> None:
    text = b"GET /test HTTP/1.1\r\n" b"content-encoding: \r\n\r\n"
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert msg.compression is None


def test_compression_deflate(parser) -> None:
    text = b"GET /test HTTP/1.1\r\n" b"content-encoding: deflate\r\n\r\n"
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert msg.compression == "deflate"


def test_compression_gzip(parser) -> None:
    text = b"GET /test HTTP/1.1\r\n" b"content-encoding: gzip\r\n\r\n"
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert msg.compression == "gzip"


@pytest.mark.skipif(brotli is None, reason="brotli is not installed")
def test_compression_brotli(parser) -> None:
    text = b"GET /test HTTP/1.1\r\n" b"content-encoding: br\r\n\r\n"
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert msg.compression == "br"


def test_compression_unknown(parser) -> None:
    text = b"GET /test HTTP/1.1\r\n" b"content-encoding: compress\r\n\r\n"
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert msg.compression is None


def test_url_connect(parser: Any) -> None:
    text = b"CONNECT www.google.com HTTP/1.1\r\n" b"content-length: 0\r\n\r\n"
    messages, upgrade, tail = parser.feed_data(text)
    msg, payload = messages[0]
    assert upgrade
    assert msg.url == URL.build(authority="www.google.com")


def test_headers_connect(parser: Any) -> None:
    text = b"CONNECT www.google.com HTTP/1.1\r\n" b"content-length: 0\r\n\r\n"
    messages, upgrade, tail = parser.feed_data(text)
    msg, payload = messages[0]
    assert upgrade
    assert isinstance(payload, streams.StreamReader)


def test_url_absolute(parser: Any) -> None:
    text = (
        b"GET https://www.google.com/path/to.html HTTP/1.1\r\n"
        b"content-length: 0\r\n\r\n"
    )
    messages, upgrade, tail = parser.feed_data(text)
    msg, payload = messages[0]
    assert not upgrade
    assert msg.method == "GET"
    assert msg.url == URL("https://www.google.com/path/to.html")


def test_headers_old_websocket_key1(parser: Any) -> None:
    text = b"GET /test HTTP/1.1\r\n" b"SEC-WEBSOCKET-KEY1: line\r\n\r\n"

    with pytest.raises(http_exceptions.BadHttpMessage):
        parser.feed_data(text)


def test_headers_content_length_err_1(parser) -> None:
    text = b"GET /test HTTP/1.1\r\n" b"content-length: line\r\n\r\n"

    with pytest.raises(http_exceptions.BadHttpMessage):
        parser.feed_data(text)


def test_headers_content_length_err_2(parser) -> None:
    text = b"GET /test HTTP/1.1\r\n" b"content-length: -1\r\n\r\n"

    with pytest.raises(http_exceptions.BadHttpMessage):
        parser.feed_data(text)


def test_invalid_header(parser) -> None:
    text = b"GET /test HTTP/1.1\r\n" b"test line\r\n\r\n"
    with pytest.raises(http_exceptions.BadHttpMessage):
        parser.feed_data(text)


def test_invalid_name(parser) -> None:
    text = b"GET /test HTTP/1.1\r\n" b"test[]: line\r\n\r\n"

    with pytest.raises(http_exceptions.BadHttpMessage):
        parser.feed_data(text)


@pytest.mark.parametrize("size", [40960, 8191])
def test_max_header_field_size(parser, size) -> None:
    name = b"t" * size
    text = b"GET /test HTTP/1.1\r\n" + name + b":data\r\n\r\n"

    match = f"400, message='Got more than 8190 bytes \\({size}\\) when reading"
    with pytest.raises(http_exceptions.LineTooLong, match=match):
        parser.feed_data(text)


def test_max_header_field_size_under_limit(parser) -> None:
    name = b"t" * 8190
    text = b"GET /test HTTP/1.1\r\n" + name + b":data\r\n\r\n"

    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert msg.method == "GET"
    assert msg.path == "/test"
    assert msg.version == (1, 1)
    assert msg.headers == CIMultiDict({name.decode(): "data"})
    assert msg.raw_headers == ((name, b"data"),)
    assert not msg.should_close
    assert msg.compression is None
    assert not msg.upgrade
    assert not msg.chunked
    assert msg.url == URL("/test")


@pytest.mark.parametrize("size", [40960, 8191])
def test_max_header_value_size(parser, size) -> None:
    name = b"t" * size
    text = b"GET /test HTTP/1.1\r\n" b"data:" + name + b"\r\n\r\n"

    match = f"400, message='Got more than 8190 bytes \\({size}\\) when reading"
    with pytest.raises(http_exceptions.LineTooLong, match=match):
        parser.feed_data(text)


def test_max_header_value_size_under_limit(parser) -> None:
    value = b"A" * 8190
    text = b"GET /test HTTP/1.1\r\n" b"data:" + value + b"\r\n\r\n"

    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert msg.method == "GET"
    assert msg.path == "/test"
    assert msg.version == (1, 1)
    assert msg.headers == CIMultiDict({"data": value.decode()})
    assert msg.raw_headers == ((b"data", value),)
    assert not msg.should_close
    assert msg.compression is None
    assert not msg.upgrade
    assert not msg.chunked
    assert msg.url == URL("/test")


@pytest.mark.parametrize("size", [40965, 8191])
def test_max_header_value_size_continuation(parser, size) -> None:
    name = b"T" * (size - 5)
    text = b"GET /test HTTP/1.1\r\n" b"data: test\r\n " + name + b"\r\n\r\n"

    match = f"400, message='Got more than 8190 bytes \\({size}\\) when reading"
    with pytest.raises(http_exceptions.LineTooLong, match=match):
        parser.feed_data(text)


def test_max_header_value_size_continuation_under_limit(parser) -> None:
    value = b"A" * 8185
    text = b"GET /test HTTP/1.1\r\n" b"data: test\r\n " + value + b"\r\n\r\n"

    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert msg.method == "GET"
    assert msg.path == "/test"
    assert msg.version == (1, 1)
    assert msg.headers == CIMultiDict({"data": "test " + value.decode()})
    assert msg.raw_headers == ((b"data", b"test " + value),)
    assert not msg.should_close
    assert msg.compression is None
    assert not msg.upgrade
    assert not msg.chunked
    assert msg.url == URL("/test")


def test_http_request_parser(parser) -> None:
    text = b"GET /path HTTP/1.1\r\n\r\n"
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]

    assert msg.method == "GET"
    assert msg.path == "/path"
    assert msg.version == (1, 1)
    assert msg.headers == CIMultiDict()
    assert msg.raw_headers == ()
    assert not msg.should_close
    assert msg.compression is None
    assert not msg.upgrade
    assert not msg.chunked
    assert msg.url == URL("/path")


def test_http_request_bad_status_line(parser) -> None:
    text = b"getpath \r\n\r\n"
    with pytest.raises(http_exceptions.BadStatusLine):
        parser.feed_data(text)


def test_http_request_upgrade(parser) -> None:
    text = (
        b"GET /test HTTP/1.1\r\n"
        b"connection: upgrade\r\n"
        b"upgrade: websocket\r\n\r\n"
        b"some raw data"
    )
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]
    assert not msg.should_close
    assert msg.upgrade
    assert upgrade
    assert tail == b"some raw data"


def test_http_request_parser_utf8(parser) -> None:
    text = "GET /path HTTP/1.1\r\nx-test:тест\r\n\r\n".encode()
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]

    assert msg.method == "GET"
    assert msg.path == "/path"
    assert msg.version == (1, 1)
    assert msg.headers == CIMultiDict([("X-TEST", "тест")])
    assert msg.raw_headers == ((b"x-test", "тест".encode()),)
    assert not msg.should_close
    assert msg.compression is None
    assert not msg.upgrade
    assert not msg.chunked
    assert msg.url == URL("/path")


def test_http_request_parser_non_utf8(parser) -> None:
    text = "GET /path HTTP/1.1\r\nx-test:тест\r\n\r\n".encode("cp1251")
    msg = parser.feed_data(text)[0][0][0]

    assert msg.method == "GET"
    assert msg.path == "/path"
    assert msg.version == (1, 1)
    assert msg.headers == CIMultiDict(
        [("X-TEST", "тест".encode("cp1251").decode("utf8", "surrogateescape"))]
    )
    assert msg.raw_headers == ((b"x-test", "тест".encode("cp1251")),)
    assert not msg.should_close
    assert msg.compression is None
    assert not msg.upgrade
    assert not msg.chunked
    assert msg.url == URL("/path")


def test_http_request_parser_two_slashes(parser) -> None:
    text = b"GET //path HTTP/1.1\r\n\r\n"
    msg = parser.feed_data(text)[0][0][0]

    assert msg.method == "GET"
    assert msg.path == "//path"
    assert msg.url.path == "//path"
    assert msg.version == (1, 1)
    assert not msg.should_close
    assert msg.compression is None
    assert not msg.upgrade
    assert not msg.chunked


def test_http_request_parser_bad_method(parser) -> None:
    with pytest.raises(http_exceptions.BadStatusLine):
        parser.feed_data(b'=":<G>(e),[T];?" /get HTTP/1.1\r\n\r\n')


def test_http_request_parser_bad_version(parser) -> None:
    with pytest.raises(http_exceptions.BadHttpMessage):
        parser.feed_data(b"GET //get HT/11\r\n\r\n")


@pytest.mark.parametrize("size", [40965, 8191])
def test_http_request_max_status_line(parser, size) -> None:
    path = b"t" * (size - 5)
    match = f"400, message='Got more than 8190 bytes \\({size}\\) when reading"
    with pytest.raises(http_exceptions.LineTooLong, match=match):
        parser.feed_data(b"GET /path" + path + b" HTTP/1.1\r\n\r\n")


def test_http_request_max_status_line_under_limit(parser) -> None:
    path = b"t" * (8190 - 5)
    messages, upgraded, tail = parser.feed_data(
        b"GET /path" + path + b" HTTP/1.1\r\n\r\n"
    )
    msg = messages[0][0]

    assert msg.method == "GET"
    assert msg.path == "/path" + path.decode()
    assert msg.version == (1, 1)
    assert msg.headers == CIMultiDict()
    assert msg.raw_headers == ()
    assert not msg.should_close
    assert msg.compression is None
    assert not msg.upgrade
    assert not msg.chunked
    assert msg.url == URL("/path" + path.decode())


def test_http_response_parser_utf8(response) -> None:
    text = "HTTP/1.1 200 Ok\r\nx-test:тест\r\n\r\n".encode()

    messages, upgraded, tail = response.feed_data(text)
    assert len(messages) == 1
    msg = messages[0][0]

    assert msg.version == (1, 1)
    assert msg.code == 200
    assert msg.reason == "Ok"
    assert msg.headers == CIMultiDict([("X-TEST", "тест")])
    assert msg.raw_headers == ((b"x-test", "тест".encode()),)
    assert not upgraded
    assert not tail


@pytest.mark.parametrize("size", [40962, 8191])
def test_http_response_parser_bad_status_line_too_long(response, size) -> None:
    reason = b"t" * (size - 2)
    match = f"400, message='Got more than 8190 bytes \\({size}\\) when reading"
    with pytest.raises(http_exceptions.LineTooLong, match=match):
        response.feed_data(b"HTTP/1.1 200 Ok" + reason + b"\r\n\r\n")


def test_http_response_parser_status_line_under_limit(response) -> None:
    reason = b"O" * 8190
    messages, upgraded, tail = response.feed_data(
        b"HTTP/1.1 200 " + reason + b"\r\n\r\n"
    )
    msg = messages[0][0]
    assert msg.version == (1, 1)
    assert msg.code == 200
    assert msg.reason == reason.decode()


def test_http_response_parser_bad_version(response) -> None:
    with pytest.raises(http_exceptions.BadHttpMessage):
        response.feed_data(b"HT/11 200 Ok\r\n\r\n")


def test_http_response_parser_no_reason(response) -> None:
    msg = response.feed_data(b"HTTP/1.1 200\r\n\r\n")[0][0][0]

    assert msg.version == (1, 1)
    assert msg.code == 200
    assert msg.reason == ""


def test_http_response_parser_bad(response) -> None:
    with pytest.raises(http_exceptions.BadHttpMessage):
        response.feed_data(b"HTT/1\r\n\r\n")


def test_http_response_parser_code_under_100(response) -> None:
    msg = response.feed_data(b"HTTP/1.1 99 test\r\n\r\n")[0][0][0]
    assert msg.code == 99


def test_http_response_parser_code_above_999(response) -> None:
    with pytest.raises(http_exceptions.BadHttpMessage):
        response.feed_data(b"HTTP/1.1 9999 test\r\n\r\n")


def test_http_response_parser_code_not_int(response) -> None:
    with pytest.raises(http_exceptions.BadHttpMessage):
        response.feed_data(b"HTTP/1.1 ttt test\r\n\r\n")


def test_http_request_chunked_payload(parser) -> None:
    text = b"GET /test HTTP/1.1\r\n" b"transfer-encoding: chunked\r\n\r\n"
    msg, payload = parser.feed_data(text)[0][0]

    assert msg.chunked
    assert not payload.is_eof()
    assert isinstance(payload, streams.StreamReader)

    parser.feed_data(b"4\r\ndata\r\n4\r\nline\r\n0\r\n\r\n")

    assert b"dataline" == b"".join(d for d in payload._buffer)
    assert [4, 8] == payload._http_chunk_splits
    assert payload.is_eof()


def test_http_request_chunked_payload_and_next_message(parser) -> None:
    text = b"GET /test HTTP/1.1\r\n" b"transfer-encoding: chunked\r\n\r\n"
    msg, payload = parser.feed_data(text)[0][0]

    messages, upgraded, tail = parser.feed_data(
        b"4\r\ndata\r\n4\r\nline\r\n0\r\n\r\n"
        b"POST /test2 HTTP/1.1\r\n"
        b"transfer-encoding: chunked\r\n\r\n"
    )

    assert b"dataline" == b"".join(d for d in payload._buffer)
    assert [4, 8] == payload._http_chunk_splits
    assert payload.is_eof()

    assert len(messages) == 1
    msg2, payload2 = messages[0]

    assert msg2.method == "POST"
    assert msg2.chunked
    assert not payload2.is_eof()


def test_http_request_chunked_payload_chunks(parser) -> None:
    text = b"GET /test HTTP/1.1\r\n" b"transfer-encoding: chunked\r\n\r\n"
    msg, payload = parser.feed_data(text)[0][0]

    parser.feed_data(b"4\r\ndata\r")
    parser.feed_data(b"\n4")
    parser.feed_data(b"\r")
    parser.feed_data(b"\n")
    parser.feed_data(b"li")
    parser.feed_data(b"ne\r\n0\r\n")
    parser.feed_data(b"test: test\r\n")

    assert b"dataline" == b"".join(d for d in payload._buffer)
    assert [4, 8] == payload._http_chunk_splits
    assert not payload.is_eof()

    parser.feed_data(b"\r\n")
    assert b"dataline" == b"".join(d for d in payload._buffer)
    assert [4, 8] == payload._http_chunk_splits
    assert payload.is_eof()


def test_parse_chunked_payload_chunk_extension(parser) -> None:
    text = b"GET /test HTTP/1.1\r\n" b"transfer-encoding: chunked\r\n\r\n"
    msg, payload = parser.feed_data(text)[0][0]

    parser.feed_data(b"4;test\r\ndata\r\n4\r\nline\r\n0\r\ntest: test\r\n\r\n")

    assert b"dataline" == b"".join(d for d in payload._buffer)
    assert [4, 8] == payload._http_chunk_splits
    assert payload.is_eof()


def _test_parse_no_length_or_te_on_post(loop, protocol, request_cls):
    parser = request_cls(protocol, loop, readall=True)
    text = b"POST /test HTTP/1.1\r\n\r\n"
    msg, payload = parser.feed_data(text)[0][0]

    assert payload.is_eof()


def test_parse_payload_response_without_body(loop, protocol, response_cls) -> None:
    parser = response_cls(protocol, loop, 2**16, response_with_body=False)
    text = b"HTTP/1.1 200 Ok\r\n" b"content-length: 10\r\n\r\n"
    msg, payload = parser.feed_data(text)[0][0]

    assert payload.is_eof()


def test_parse_length_payload(response) -> None:
    text = b"HTTP/1.1 200 Ok\r\n" b"content-length: 4\r\n\r\n"
    msg, payload = response.feed_data(text)[0][0]
    assert not payload.is_eof()

    response.feed_data(b"da")
    response.feed_data(b"t")
    response.feed_data(b"aHT")

    assert payload.is_eof()
    assert b"data" == b"".join(d for d in payload._buffer)


def test_parse_no_length_payload(parser) -> None:
    text = b"PUT / HTTP/1.1\r\n\r\n"
    msg, payload = parser.feed_data(text)[0][0]
    assert payload.is_eof()


def test_partial_url(parser) -> None:
    messages, upgrade, tail = parser.feed_data(b"GET /te")
    assert len(messages) == 0
    messages, upgrade, tail = parser.feed_data(b"st HTTP/1.1\r\n\r\n")
    assert len(messages) == 1

    msg, payload = messages[0]

    assert msg.method == "GET"
    assert msg.path == "/test"
    assert msg.version == (1, 1)
    assert payload.is_eof()


def test_url_parse_non_strict_mode(parser) -> None:
    payload = "GET /test/тест HTTP/1.1\r\n\r\n".encode()
    messages, upgrade, tail = parser.feed_data(payload)
    assert len(messages) == 1

    msg, payload = messages[0]

    assert msg.method == "GET"
    assert msg.path == "/test/тест"
    assert msg.version == (1, 1)
    assert payload.is_eof()


@pytest.mark.parametrize(
    ("uri", "path", "query", "fragment"),
    [
        ("/path%23frag", "/path#frag", {}, ""),
        ("/path%2523frag", "/path%23frag", {}, ""),
        ("/path?key=value%23frag", "/path", {"key": "value#frag"}, ""),
        ("/path?key=value%2523frag", "/path", {"key": "value%23frag"}, ""),
        ("/path#frag%20", "/path", {}, "frag "),
        ("/path#frag%2520", "/path", {}, "frag%20"),
    ],
)
def test_parse_uri_percent_encoded(parser, uri, path, query, fragment) -> None:
    text = (f"GET {uri} HTTP/1.1\r\n\r\n").encode()
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]

    assert msg.path == uri
    assert msg.url == URL(uri)
    assert msg.url.path == path
    assert msg.url.query == query
    assert msg.url.fragment == fragment


def test_parse_uri_utf8(parser) -> None:
    text = ("GET /путь?ключ=знач#фраг HTTP/1.1\r\n\r\n").encode()
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]

    assert msg.path == "/путь?ключ=знач#фраг"
    assert msg.url.path == "/путь"
    assert msg.url.query == {"ключ": "знач"}
    assert msg.url.fragment == "фраг"


def test_parse_uri_utf8_percent_encoded(parser) -> None:
    text = (
        "GET %s HTTP/1.1\r\n\r\n" % quote("/путь?ключ=знач#фраг", safe="/?=#")
    ).encode()
    messages, upgrade, tail = parser.feed_data(text)
    msg = messages[0][0]

    assert msg.path == quote("/путь?ключ=знач#фраг", safe="/?=#")
    assert msg.url == URL("/путь?ключ=знач#фраг")
    assert msg.url.path == "/путь"
    assert msg.url.query == {"ключ": "знач"}
    assert msg.url.fragment == "фраг"


@pytest.mark.skipif(
    "HttpRequestParserC" not in dir(aiohttp.http_parser),
    reason="C based HTTP parser not available",
)
def test_parse_bad_method_for_c_parser_raises(loop, protocol):
    payload = b"GET1 /test HTTP/1.1\r\n\r\n"
    parser = HttpRequestParserC(
        protocol,
        loop,
        2**16,
        max_line_size=8190,
        max_headers=32768,
        max_field_size=8190,
    )

    with pytest.raises(aiohttp.http_exceptions.BadStatusLine):
        messages, upgrade, tail = parser.feed_data(payload)


class TestParsePayload:
    async def test_parse_eof_payload(self, stream) -> None:
        out = aiohttp.FlowControlDataQueue(
            stream, 2**16, loop=asyncio.get_event_loop()
        )
        p = HttpPayloadParser(out, readall=True)
        p.feed_data(b"data")
        p.feed_eof()

        assert out.is_eof()
        assert [(bytearray(b"data"), 4)] == list(out._buffer)

    async def test_parse_no_body(self, stream) -> None:
        out = aiohttp.FlowControlDataQueue(
            stream, 2**16, loop=asyncio.get_event_loop()
        )
        p = HttpPayloadParser(out, method="PUT")

        assert out.is_eof()
        assert p.done

    async def test_parse_length_payload_eof(self, stream) -> None:
        out = aiohttp.FlowControlDataQueue(
            stream, 2**16, loop=asyncio.get_event_loop()
        )

        p = HttpPayloadParser(out, length=4)
        p.feed_data(b"da")

        with pytest.raises(http_exceptions.ContentLengthError):
            p.feed_eof()

    async def test_parse_chunked_payload_size_error(self, stream) -> None:
        out = aiohttp.FlowControlDataQueue(
            stream, 2**16, loop=asyncio.get_event_loop()
        )
        p = HttpPayloadParser(out, chunked=True)
        with pytest.raises(http_exceptions.TransferEncodingError):
            p.feed_data(b"blah\r\n")
        assert isinstance(out.exception(), http_exceptions.TransferEncodingError)

    async def test_parse_chunked_payload_split_end(self, protocol) -> None:
        out = aiohttp.StreamReader(protocol, 2**16, loop=None)
        p = HttpPayloadParser(out, chunked=True)
        p.feed_data(b"4\r\nasdf\r\n0\r\n")
        p.feed_data(b"\r\n")

        assert out.is_eof()
        assert b"asdf" == b"".join(out._buffer)

    async def test_parse_chunked_payload_split_end2(self, protocol) -> None:
        out = aiohttp.StreamReader(protocol, 2**16, loop=None)
        p = HttpPayloadParser(out, chunked=True)
        p.feed_data(b"4\r\nasdf\r\n0\r\n\r")
        p.feed_data(b"\n")

        assert out.is_eof()
        assert b"asdf" == b"".join(out._buffer)

    async def test_parse_chunked_payload_split_end_trailers(self, protocol) -> None:
        out = aiohttp.StreamReader(protocol, 2**16, loop=None)
        p = HttpPayloadParser(out, chunked=True)
        p.feed_data(b"4\r\nasdf\r\n0\r\n")
        p.feed_data(b"Content-MD5: 912ec803b2ce49e4a541068d495ab570\r\n")
        p.feed_data(b"\r\n")

        assert out.is_eof()
        assert b"asdf" == b"".join(out._buffer)

    async def test_parse_chunked_payload_split_end_trailers2(self, protocol) -> None:
        out = aiohttp.StreamReader(protocol, 2**16, loop=None)
        p = HttpPayloadParser(out, chunked=True)
        p.feed_data(b"4\r\nasdf\r\n0\r\n")
        p.feed_data(b"Content-MD5: 912ec803b2ce49e4a541068d495ab570\r\n\r")
        p.feed_data(b"\n")

        assert out.is_eof()
        assert b"asdf" == b"".join(out._buffer)

    async def test_parse_chunked_payload_split_end_trailers3(self, protocol) -> None:
        out = aiohttp.StreamReader(protocol, 2**16, loop=None)
        p = HttpPayloadParser(out, chunked=True)
        p.feed_data(b"4\r\nasdf\r\n0\r\nContent-MD5: ")
        p.feed_data(b"912ec803b2ce49e4a541068d495ab570\r\n\r\n")

        assert out.is_eof()
        assert b"asdf" == b"".join(out._buffer)

    async def test_parse_chunked_payload_split_end_trailers4(self, protocol) -> None:
        out = aiohttp.StreamReader(protocol, 2**16, loop=None)
        p = HttpPayloadParser(out, chunked=True)
        p.feed_data(b"4\r\nasdf\r\n0\r\n" b"C")
        p.feed_data(b"ontent-MD5: 912ec803b2ce49e4a541068d495ab570\r\n\r\n")

        assert out.is_eof()
        assert b"asdf" == b"".join(out._buffer)

    async def test_http_payload_parser_length(self, stream) -> None:
        out = aiohttp.FlowControlDataQueue(
            stream, 2**16, loop=asyncio.get_event_loop()
        )
        p = HttpPayloadParser(out, length=2)
        eof, tail = p.feed_data(b"1245")
        assert eof

        assert b"12" == b"".join(d for d, _ in out._buffer)
        assert b"45" == tail

    async def test_http_payload_parser_deflate(self, stream) -> None:
        # c=compressobj(wbits=15); b''.join([c.compress(b'data'), c.flush()])
        COMPRESSED = b"x\x9cKI,I\x04\x00\x04\x00\x01\x9b"

        length = len(COMPRESSED)
        out = aiohttp.FlowControlDataQueue(
            stream, 2**16, loop=asyncio.get_event_loop()
        )
        p = HttpPayloadParser(out, length=length, compression="deflate")
        p.feed_data(COMPRESSED)
        assert b"data" == b"".join(d for d, _ in out._buffer)
        assert out.is_eof()

    async def test_http_payload_parser_deflate_no_hdrs(self, stream: Any) -> None:
        """Tests incorrectly formed data (no zlib headers)."""
        # c=compressobj(wbits=-15); b''.join([c.compress(b'data'), c.flush()])
        COMPRESSED = b"KI,I\x04\x00"

        length = len(COMPRESSED)
        out = aiohttp.FlowControlDataQueue(
            stream, 2**16, loop=asyncio.get_event_loop()
        )
        p = HttpPayloadParser(out, length=length, compression="deflate")
        p.feed_data(COMPRESSED)
        assert b"data" == b"".join(d for d, _ in out._buffer)
        assert out.is_eof()

    async def test_http_payload_parser_deflate_light(self, stream) -> None:
        # c=compressobj(wbits=9); b''.join([c.compress(b'data'), c.flush()])
        COMPRESSED = b"\x18\x95KI,I\x04\x00\x04\x00\x01\x9b"

        length = len(COMPRESSED)
        out = aiohttp.FlowControlDataQueue(
            stream, 2**16, loop=asyncio.get_event_loop()
        )
        p = HttpPayloadParser(out, length=length, compression="deflate")
        p.feed_data(COMPRESSED)
        assert b"data" == b"".join(d for d, _ in out._buffer)
        assert out.is_eof()

    async def test_http_payload_parser_deflate_split(self, stream) -> None:
        out = aiohttp.FlowControlDataQueue(
            stream, 2**16, loop=asyncio.get_event_loop()
        )
        p = HttpPayloadParser(out, compression="deflate", readall=True)
        # Feeding one correct byte should be enough to choose exact
        # deflate decompressor
        p.feed_data(b"x", 1)
        p.feed_data(b"\x9cKI,I\x04\x00\x04\x00\x01\x9b", 11)
        p.feed_eof()
        assert b"data" == b"".join(d for d, _ in out._buffer)

    async def test_http_payload_parser_deflate_split_err(self, stream) -> None:
        out = aiohttp.FlowControlDataQueue(
            stream, 2**16, loop=asyncio.get_event_loop()
        )
        p = HttpPayloadParser(out, compression="deflate", readall=True)
        # Feeding one wrong byte should be enough to choose exact
        # deflate decompressor
        p.feed_data(b"K", 1)
        p.feed_data(b"I,I\x04\x00", 5)
        p.feed_eof()
        assert b"data" == b"".join(d for d, _ in out._buffer)

    async def test_http_payload_parser_length_zero(self, stream) -> None:
        out = aiohttp.FlowControlDataQueue(
            stream, 2**16, loop=asyncio.get_event_loop()
        )
        p = HttpPayloadParser(out, length=0)
        assert p.done
        assert out.is_eof()

    @pytest.mark.skipif(brotli is None, reason="brotli is not installed")
    async def test_http_payload_brotli(self, stream) -> None:
        compressed = brotli.compress(b"brotli data")
        out = aiohttp.FlowControlDataQueue(
            stream, 2**16, loop=asyncio.get_event_loop()
        )
        p = HttpPayloadParser(out, length=len(compressed), compression="br")
        p.feed_data(compressed)
        assert b"brotli data" == b"".join(d for d, _ in out._buffer)
        assert out.is_eof()


class TestDeflateBuffer:
    async def test_feed_data(self, stream) -> None:
        buf = aiohttp.FlowControlDataQueue(
            stream, 2**16, loop=asyncio.get_event_loop()
        )
        dbuf = DeflateBuffer(buf, "deflate")

        dbuf.decompressor = mock.Mock()
        dbuf.decompressor.decompress.return_value = b"line"

        # First byte should be b'x' in order code not to change the decoder.
        dbuf.feed_data(b"xxxx", 4)
        assert [b"line"] == list(d for d, _ in buf._buffer)

    async def test_feed_data_err(self, stream) -> None:
        buf = aiohttp.FlowControlDataQueue(
            stream, 2**16, loop=asyncio.get_event_loop()
        )
        dbuf = DeflateBuffer(buf, "deflate")

        exc = ValueError()
        dbuf.decompressor = mock.Mock()
        dbuf.decompressor.decompress.side_effect = exc

        with pytest.raises(http_exceptions.ContentEncodingError):
            # Should be more than 4 bytes to trigger deflate FSM error.
            # Should start with b'x', otherwise code switch mocked decoder.
            dbuf.feed_data(b"xsomedata", 9)

    async def test_feed_eof(self, stream) -> None:
        buf = aiohttp.FlowControlDataQueue(
            stream, 2**16, loop=asyncio.get_event_loop()
        )
        dbuf = DeflateBuffer(buf, "deflate")

        dbuf.decompressor = mock.Mock()
        dbuf.decompressor.flush.return_value = b"line"

        dbuf.feed_eof()
        assert [b"line"] == list(d for d, _ in buf._buffer)
        assert buf._eof

    async def test_feed_eof_err_deflate(self, stream) -> None:
        buf = aiohttp.FlowControlDataQueue(
            stream, 2**16, loop=asyncio.get_event_loop()
        )
        dbuf = DeflateBuffer(buf, "deflate")

        dbuf.decompressor = mock.Mock()
        dbuf.decompressor.flush.return_value = b"line"
        dbuf.decompressor.eof = False

        with pytest.raises(http_exceptions.ContentEncodingError):
            dbuf.feed_eof()

    async def test_feed_eof_no_err_gzip(self, stream) -> None:
        buf = aiohttp.FlowControlDataQueue(
            stream, 2**16, loop=asyncio.get_event_loop()
        )
        dbuf = DeflateBuffer(buf, "gzip")

        dbuf.decompressor = mock.Mock()
        dbuf.decompressor.flush.return_value = b"line"
        dbuf.decompressor.eof = False

        dbuf.feed_eof()
        assert [b"line"] == list(d for d, _ in buf._buffer)

    async def test_feed_eof_no_err_brotli(self, stream) -> None:
        buf = aiohttp.FlowControlDataQueue(
            stream, 2**16, loop=asyncio.get_event_loop()
        )
        dbuf = DeflateBuffer(buf, "br")

        dbuf.decompressor = mock.Mock()
        dbuf.decompressor.flush.return_value = b"line"
        dbuf.decompressor.eof = False

        dbuf.feed_eof()
        assert [b"line"] == list(d for d, _ in buf._buffer)

    async def test_empty_body(self, stream) -> None:
        buf = aiohttp.FlowControlDataQueue(
            stream, 2**16, loop=asyncio.get_event_loop()
        )
        dbuf = DeflateBuffer(buf, "deflate")
        dbuf.feed_eof()

        assert buf.at_eof()
