# type: ignore
import asyncio
import datetime
import socket
import weakref
from collections.abc import MutableMapping
from typing import Any
from unittest import mock

import pytest
from multidict import CIMultiDict, CIMultiDictProxy, MultiDict
from yarl import URL

from aiohttp import HttpVersion, web
from aiohttp.http_parser import RawRequestMessage
from aiohttp.streams import StreamReader
from aiohttp.test_utils import make_mocked_request
from aiohttp.web import HTTPRequestEntityTooLarge, HTTPUnsupportedMediaType
from aiohttp.web_request import ETag


@pytest.fixture
def protocol():
    return mock.Mock(_reading_paused=False)


def test_base_ctor() -> None:
    message = RawRequestMessage(
        "GET",
        "/path/to?a=1&b=2",
        HttpVersion(1, 1),
        CIMultiDictProxy(CIMultiDict()),
        (),
        False,
        False,
        False,
        False,
        URL("/path/to?a=1&b=2"),
    )

    req = web.BaseRequest(
        message, mock.Mock(), mock.Mock(), mock.Mock(), mock.Mock(), mock.Mock()
    )

    assert "GET" == req.method
    assert HttpVersion(1, 1) == req.version
    # MacOS may return CamelCased host name, need .lower()
    # FQDN can be wider than host, e.g.
    # 'fv-az397-495' in 'fv-az397-495.internal.cloudapp.net'
    assert req.host.lower() in socket.getfqdn().lower()
    assert "/path/to?a=1&b=2" == req.path_qs
    assert "/path/to" == req.path
    assert "a=1&b=2" == req.query_string
    assert CIMultiDict() == req.headers
    assert () == req.raw_headers

    get = req.query
    assert MultiDict([("a", "1"), ("b", "2")]) == get
    # second call should return the same object
    assert get is req.query

    assert req.keep_alive

    assert "__dict__" not in dir(req)

    assert req


def test_ctor() -> None:
    req = make_mocked_request("GET", "/path/to?a=1&b=2")

    assert "GET" == req.method
    assert HttpVersion(1, 1) == req.version
    # MacOS may return CamelCased host name, need .lower()
    # FQDN can be wider than host, e.g.
    # 'fv-az397-495' in 'fv-az397-495.internal.cloudapp.net'
    assert req.host.lower() in socket.getfqdn().lower()
    assert "/path/to?a=1&b=2" == req.path_qs
    assert "/path/to" == req.path
    assert "a=1&b=2" == req.query_string
    assert CIMultiDict() == req.headers
    assert () == req.raw_headers

    get = req.query
    assert MultiDict([("a", "1"), ("b", "2")]) == get
    # second call should return the same object
    assert get is req.query

    assert req.keep_alive

    # just make sure that all lines of make_mocked_request covered
    headers = CIMultiDict(FOO="bar")
    payload = mock.Mock()
    protocol = mock.Mock()
    app = mock.Mock()
    req = make_mocked_request(
        "GET",
        "/path/to?a=1&b=2",
        headers=headers,
        protocol=protocol,
        payload=payload,
        app=app,
    )
    assert req.app is app
    assert req.content is payload
    assert req.protocol is protocol
    assert req.transport is protocol.transport
    assert req.headers == headers
    assert req.raw_headers == ((b"FOO", b"bar"),)
    assert req.task is req._task

    assert "__dict__" not in dir(req)


def test_doubleslashes() -> None:
    # NB: //foo/bar is an absolute URL with foo netloc and /bar path
    req = make_mocked_request("GET", "/bar//foo/")
    assert "/bar//foo/" == req.path


def test_content_type_not_specified() -> None:
    req = make_mocked_request("Get", "/")
    assert "application/octet-stream" == req.content_type


def test_content_type_from_spec() -> None:
    req = make_mocked_request(
        "Get", "/", CIMultiDict([("CONTENT-TYPE", "application/json")])
    )
    assert "application/json" == req.content_type


def test_content_type_from_spec_with_charset() -> None:
    req = make_mocked_request(
        "Get", "/", CIMultiDict([("CONTENT-TYPE", "text/html; charset=UTF-8")])
    )
    assert "text/html" == req.content_type
    assert "UTF-8" == req.charset


def test_calc_content_type_on_getting_charset() -> None:
    req = make_mocked_request(
        "Get", "/", CIMultiDict([("CONTENT-TYPE", "text/html; charset=UTF-8")])
    )
    assert "UTF-8" == req.charset
    assert "text/html" == req.content_type


def test_urlencoded_querystring() -> None:
    req = make_mocked_request("GET", "/yandsearch?text=%D1%82%D0%B5%D0%BA%D1%81%D1%82")
    assert {"text": "текст"} == req.query


def test_non_ascii_path() -> None:
    req = make_mocked_request("GET", "/путь")
    assert "/путь" == req.path


def test_non_ascii_raw_path() -> None:
    req = make_mocked_request("GET", "/путь")
    assert "/путь" == req.raw_path


def test_absolute_url() -> None:
    req = make_mocked_request("GET", "https://example.com/path/to?a=1")
    assert req.url == URL("https://example.com/path/to?a=1")
    assert req.scheme == "https"
    assert req.host == "example.com"
    assert req.rel_url == URL.build(path="/path/to", query={"a": "1"})


def test_clone_absolute_scheme() -> None:
    req = make_mocked_request("GET", "https://example.com/path/to?a=1")
    assert req.scheme == "https"
    req2 = req.clone(scheme="http")
    assert req2.scheme == "http"
    assert req2.url.scheme == "http"


def test_clone_absolute_host() -> None:
    req = make_mocked_request("GET", "https://example.com/path/to?a=1")
    assert req.host == "example.com"
    req2 = req.clone(host="foo.test")
    assert req2.host == "foo.test"
    assert req2.url.host == "foo.test"


def test_content_length() -> None:
    req = make_mocked_request("Get", "/", CIMultiDict([("CONTENT-LENGTH", "123")]))

    assert 123 == req.content_length


def test_range_to_slice_head() -> None:
    def bytes_gen(size):
        for i in range(size):
            yield i % 256

    payload = bytearray(bytes_gen(10000))
    req = make_mocked_request(
        "GET", "/", headers=CIMultiDict([("RANGE", "bytes=0-499")]), payload=payload
    )
    assert isinstance(req.http_range, slice)
    assert req.content[req.http_range] == payload[:500]


def test_range_to_slice_mid() -> None:
    def bytes_gen(size):
        for i in range(size):
            yield i % 256

    payload = bytearray(bytes_gen(10000))
    req = make_mocked_request(
        "GET", "/", headers=CIMultiDict([("RANGE", "bytes=500-999")]), payload=payload
    )
    assert isinstance(req.http_range, slice)
    assert req.content[req.http_range] == payload[500:1000]


def test_range_to_slice_tail_start() -> None:
    def bytes_gen(size):
        for i in range(size):
            yield i % 256

    payload = bytearray(bytes_gen(10000))
    req = make_mocked_request(
        "GET", "/", headers=CIMultiDict([("RANGE", "bytes=9500-")]), payload=payload
    )
    assert isinstance(req.http_range, slice)
    assert req.content[req.http_range] == payload[-500:]


def test_range_to_slice_tail_stop() -> None:
    def bytes_gen(size):
        for i in range(size):
            yield i % 256

    payload = bytearray(bytes_gen(10000))
    req = make_mocked_request(
        "GET", "/", headers=CIMultiDict([("RANGE", "bytes=-500")]), payload=payload
    )
    assert isinstance(req.http_range, slice)
    assert req.content[req.http_range] == payload[-500:]


def test_non_keepalive_on_http10() -> None:
    req = make_mocked_request("GET", "/", version=HttpVersion(1, 0))
    assert not req.keep_alive


def test_non_keepalive_on_closing() -> None:
    req = make_mocked_request("GET", "/", closing=True)
    assert not req.keep_alive


async def test_call_POST_on_GET_request() -> None:
    req = make_mocked_request("GET", "/")

    ret = await req.post()
    assert CIMultiDict() == ret


async def test_call_POST_on_weird_content_type() -> None:
    req = make_mocked_request(
        "POST", "/", headers=CIMultiDict({"CONTENT-TYPE": "something/weird"})
    )

    ret = await req.post()
    assert CIMultiDict() == ret


async def test_call_POST_twice() -> None:
    req = make_mocked_request("GET", "/")

    ret1 = await req.post()
    ret2 = await req.post()
    assert ret1 is ret2


def test_no_request_cookies() -> None:
    req = make_mocked_request("GET", "/")

    assert req.cookies == {}

    cookies = req.cookies
    assert cookies is req.cookies


def test_request_cookie() -> None:
    headers = CIMultiDict(COOKIE="cookie1=value1; cookie2=value2")
    req = make_mocked_request("GET", "/", headers=headers)

    assert req.cookies == {"cookie1": "value1", "cookie2": "value2"}


def test_request_cookie__set_item() -> None:
    headers = CIMultiDict(COOKIE="name=value")
    req = make_mocked_request("GET", "/", headers=headers)

    assert req.cookies == {"name": "value"}

    with pytest.raises(TypeError):
        req.cookies["my"] = "value"


def test_match_info() -> None:
    req = make_mocked_request("GET", "/")
    assert req._match_info is req.match_info


def test_request_is_mutable_mapping() -> None:
    req = make_mocked_request("GET", "/")
    assert isinstance(req, MutableMapping)
    req["key"] = "value"
    assert "value" == req["key"]


def test_request_delitem() -> None:
    req = make_mocked_request("GET", "/")
    req["key"] = "value"
    assert "value" == req["key"]
    del req["key"]
    assert "key" not in req


def test_request_len() -> None:
    req = make_mocked_request("GET", "/")
    assert len(req) == 0
    req["key"] = "value"
    assert len(req) == 1


def test_request_iter() -> None:
    req = make_mocked_request("GET", "/")
    req["key"] = "value"
    req["key2"] = "value2"
    assert set(req) == {"key", "key2"}


def test___repr__() -> None:
    req = make_mocked_request("GET", "/path/to")
    assert "<Request GET /path/to >" == repr(req)


def test___repr___non_ascii_path() -> None:
    req = make_mocked_request("GET", "/path/\U0001f415\U0001f308")
    assert "<Request GET /path/\\U0001f415\\U0001f308 >" == repr(req)


def test_http_scheme() -> None:
    req = make_mocked_request("GET", "/", headers={"Host": "example.com"})
    assert "http" == req.scheme
    assert req.secure is False


def test_https_scheme_by_ssl_transport() -> None:
    req = make_mocked_request(
        "GET", "/", headers={"Host": "example.com"}, sslcontext=True
    )
    assert "https" == req.scheme
    assert req.secure is True


def test_single_forwarded_header() -> None:
    header = "by=identifier;for=identifier;host=identifier;proto=identifier"
    req = make_mocked_request("GET", "/", headers=CIMultiDict({"Forwarded": header}))
    assert req.forwarded[0]["by"] == "identifier"
    assert req.forwarded[0]["for"] == "identifier"
    assert req.forwarded[0]["host"] == "identifier"
    assert req.forwarded[0]["proto"] == "identifier"


@pytest.mark.parametrize(
    "forward_for_in, forward_for_out",
    [
        ("1.2.3.4:1234", "1.2.3.4:1234"),
        ("1.2.3.4", "1.2.3.4"),
        ('"[2001:db8:cafe::17]:1234"', "[2001:db8:cafe::17]:1234"),
        ('"[2001:db8:cafe::17]"', "[2001:db8:cafe::17]"),
    ],
)
def test_forwarded_node_identifier(forward_for_in: Any, forward_for_out: Any) -> None:
    header = f"for={forward_for_in}"
    req = make_mocked_request("GET", "/", headers=CIMultiDict({"Forwarded": header}))
    assert req.forwarded == ({"for": forward_for_out},)


def test_single_forwarded_header_camelcase() -> None:
    header = "bY=identifier;fOr=identifier;HOst=identifier;pRoTO=identifier"
    req = make_mocked_request("GET", "/", headers=CIMultiDict({"Forwarded": header}))
    assert req.forwarded[0]["by"] == "identifier"
    assert req.forwarded[0]["for"] == "identifier"
    assert req.forwarded[0]["host"] == "identifier"
    assert req.forwarded[0]["proto"] == "identifier"


def test_single_forwarded_header_single_param() -> None:
    header = "BY=identifier"
    req = make_mocked_request("GET", "/", headers=CIMultiDict({"Forwarded": header}))
    assert req.forwarded[0]["by"] == "identifier"


def test_single_forwarded_header_multiple_param() -> None:
    header = "By=identifier1,BY=identifier2,  By=identifier3 ,  BY=identifier4"
    req = make_mocked_request("GET", "/", headers=CIMultiDict({"Forwarded": header}))
    assert len(req.forwarded) == 4
    assert req.forwarded[0]["by"] == "identifier1"
    assert req.forwarded[1]["by"] == "identifier2"
    assert req.forwarded[2]["by"] == "identifier3"
    assert req.forwarded[3]["by"] == "identifier4"


def test_single_forwarded_header_quoted_escaped() -> None:
    header = r'BY=identifier;pROTO="\lala lan\d\~ 123\!&"'
    req = make_mocked_request("GET", "/", headers=CIMultiDict({"Forwarded": header}))
    assert req.forwarded[0]["by"] == "identifier"
    assert req.forwarded[0]["proto"] == "lala land~ 123!&"


def test_single_forwarded_header_custom_param() -> None:
    header = r'BY=identifier;PROTO=https;SOME="other, \"value\""'
    req = make_mocked_request("GET", "/", headers=CIMultiDict({"Forwarded": header}))
    assert len(req.forwarded) == 1
    assert req.forwarded[0]["by"] == "identifier"
    assert req.forwarded[0]["proto"] == "https"
    assert req.forwarded[0]["some"] == 'other, "value"'


def test_single_forwarded_header_empty_params() -> None:
    # This is allowed by the grammar given in RFC 7239
    header = ";For=identifier;;PROTO=https;;;"
    req = make_mocked_request("GET", "/", headers=CIMultiDict({"Forwarded": header}))
    assert req.forwarded[0]["for"] == "identifier"
    assert req.forwarded[0]["proto"] == "https"


def test_single_forwarded_header_bad_separator() -> None:
    header = "BY=identifier PROTO=https"
    req = make_mocked_request("GET", "/", headers=CIMultiDict({"Forwarded": header}))
    assert "proto" not in req.forwarded[0]


def test_single_forwarded_header_injection1() -> None:
    # We might receive a header like this if we're sitting behind a reverse
    # proxy that blindly appends a forwarded-element without checking
    # the syntax of existing field-values. We should be able to recover
    # the appended element anyway.
    header = 'for=_injected;by=", for=_real'
    req = make_mocked_request("GET", "/", headers=CIMultiDict({"Forwarded": header}))
    assert len(req.forwarded) == 2
    assert "by" not in req.forwarded[0]
    assert req.forwarded[1]["for"] == "_real"


def test_single_forwarded_header_injection2() -> None:
    header = "very bad syntax, for=_real"
    req = make_mocked_request("GET", "/", headers=CIMultiDict({"Forwarded": header}))
    assert len(req.forwarded) == 2
    assert "for" not in req.forwarded[0]
    assert req.forwarded[1]["for"] == "_real"


def test_single_forwarded_header_long_quoted_string() -> None:
    header = 'for="' + "\\\\" * 5000 + '"'
    req = make_mocked_request("GET", "/", headers=CIMultiDict({"Forwarded": header}))
    assert req.forwarded[0]["for"] == "\\" * 5000


def test_multiple_forwarded_headers() -> None:
    headers = CIMultiDict()
    headers.add("Forwarded", "By=identifier1;for=identifier2, BY=identifier3")
    headers.add("Forwarded", "By=identifier4;fOr=identifier5")
    req = make_mocked_request("GET", "/", headers=headers)
    assert len(req.forwarded) == 3
    assert req.forwarded[0]["by"] == "identifier1"
    assert req.forwarded[0]["for"] == "identifier2"
    assert req.forwarded[1]["by"] == "identifier3"
    assert req.forwarded[2]["by"] == "identifier4"
    assert req.forwarded[2]["for"] == "identifier5"


def test_multiple_forwarded_headers_bad_syntax() -> None:
    headers = CIMultiDict()
    headers.add("Forwarded", "for=_1;by=_2")
    headers.add("Forwarded", "invalid value")
    headers.add("Forwarded", "")
    headers.add("Forwarded", "for=_3;by=_4")
    req = make_mocked_request("GET", "/", headers=headers)
    assert len(req.forwarded) == 4
    assert req.forwarded[0]["for"] == "_1"
    assert "for" not in req.forwarded[1]
    assert "for" not in req.forwarded[2]
    assert req.forwarded[3]["by"] == "_4"


def test_multiple_forwarded_headers_injection() -> None:
    headers = CIMultiDict()
    # This could be sent by an attacker, hoping to "shadow" the second header.
    headers.add("Forwarded", 'for=_injected;by="')
    # This is added by our trusted reverse proxy.
    headers.add("Forwarded", "for=_real;by=_actual_proxy")
    req = make_mocked_request("GET", "/", headers=headers)
    assert len(req.forwarded) == 2
    assert "by" not in req.forwarded[0]
    assert req.forwarded[1]["for"] == "_real"
    assert req.forwarded[1]["by"] == "_actual_proxy"


def test_host_by_host_header() -> None:
    req = make_mocked_request("GET", "/", headers=CIMultiDict({"Host": "example.com"}))
    assert req.host == "example.com"


def test_raw_headers() -> None:
    req = make_mocked_request("GET", "/", headers=CIMultiDict({"X-HEADER": "aaa"}))
    assert req.raw_headers == ((b"X-HEADER", b"aaa"),)


def test_rel_url() -> None:
    req = make_mocked_request("GET", "/path")
    assert URL("/path") == req.rel_url


def test_url_url() -> None:
    req = make_mocked_request("GET", "/path", headers={"HOST": "example.com"})
    assert URL("http://example.com/path") == req.url


def test_clone() -> None:
    req = make_mocked_request("GET", "/path")
    req2 = req.clone()
    assert req2.method == "GET"
    assert req2.rel_url == URL("/path")


def test_clone_client_max_size() -> None:
    req = make_mocked_request("GET", "/path", client_max_size=1024)
    req2 = req.clone()
    assert req._client_max_size == req2._client_max_size
    assert req2._client_max_size == 1024


def test_clone_override_client_max_size() -> None:
    req = make_mocked_request("GET", "/path", client_max_size=1024)
    req2 = req.clone(client_max_size=2048)
    assert req2.client_max_size == 2048


def test_clone_method() -> None:
    req = make_mocked_request("GET", "/path")
    req2 = req.clone(method="POST")
    assert req2.method == "POST"
    assert req2.rel_url == URL("/path")


def test_clone_rel_url() -> None:
    req = make_mocked_request("GET", "/path")
    req2 = req.clone(rel_url=URL("/path2"))
    assert req2.rel_url == URL("/path2")


def test_clone_rel_url_str() -> None:
    req = make_mocked_request("GET", "/path")
    req2 = req.clone(rel_url="/path2")
    assert req2.rel_url == URL("/path2")


def test_clone_headers() -> None:
    req = make_mocked_request("GET", "/path", headers={"A": "B"})
    req2 = req.clone(headers=CIMultiDict({"B": "C"}))
    assert req2.headers == CIMultiDict({"B": "C"})
    assert req2.raw_headers == ((b"B", b"C"),)


def test_clone_headers_dict() -> None:
    req = make_mocked_request("GET", "/path", headers={"A": "B"})
    req2 = req.clone(headers={"B": "C"})
    assert req2.headers == CIMultiDict({"B": "C"})
    assert req2.raw_headers == ((b"B", b"C"),)


async def test_cannot_clone_after_read(protocol: Any) -> None:
    payload = StreamReader(protocol, 2**16, loop=asyncio.get_event_loop())
    payload.feed_data(b"data")
    payload.feed_eof()
    req = make_mocked_request("GET", "/path", payload=payload)
    await req.read()
    with pytest.raises(RuntimeError):
        req.clone()


async def test_make_too_big_request(protocol: Any) -> None:
    payload = StreamReader(protocol, 2**16, loop=asyncio.get_event_loop())
    large_file = 1024**2 * b"x"
    too_large_file = large_file + b"x"
    payload.feed_data(too_large_file)
    payload.feed_eof()
    req = make_mocked_request("POST", "/", payload=payload)
    with pytest.raises(HTTPRequestEntityTooLarge) as err:
        await req.read()

    assert err.value.status_code == 413


async def test_request_with_wrong_content_type_encoding(protocol: Any) -> None:
    payload = StreamReader(protocol, 2**16, loop=asyncio.get_event_loop())
    payload.feed_data(b"{}")
    payload.feed_eof()
    headers = {"Content-Type": "text/html; charset=test"}
    req = make_mocked_request("POST", "/", payload=payload, headers=headers)

    with pytest.raises(HTTPUnsupportedMediaType) as err:
        await req.text()
    assert err.value.status_code == 415


async def test_make_too_big_request_same_size_to_max(protocol: Any) -> None:
    payload = StreamReader(protocol, 2**16, loop=asyncio.get_event_loop())
    large_file = 1024**2 * b"x"
    payload.feed_data(large_file)
    payload.feed_eof()
    req = make_mocked_request("POST", "/", payload=payload)
    resp_text = await req.read()

    assert resp_text == large_file


async def test_make_too_big_request_adjust_limit(protocol: Any) -> None:
    payload = StreamReader(protocol, 2**16, loop=asyncio.get_event_loop())
    large_file = 1024**2 * b"x"
    too_large_file = large_file + b"x"
    payload.feed_data(too_large_file)
    payload.feed_eof()
    max_size = 1024**2 + 2
    req = make_mocked_request("POST", "/", payload=payload, client_max_size=max_size)
    txt = await req.read()
    assert len(txt) == 1024**2 + 1


async def test_multipart_formdata(protocol: Any) -> None:
    payload = StreamReader(protocol, 2**16, loop=asyncio.get_event_loop())
    payload.feed_data(
        b"-----------------------------326931944431359\r\n"
        b'Content-Disposition: form-data; name="a"\r\n'
        b"\r\n"
        b"b\r\n"
        b"-----------------------------326931944431359\r\n"
        b'Content-Disposition: form-data; name="c"\r\n'
        b"\r\n"
        b"d\r\n"
        b"-----------------------------326931944431359--\r\n"
    )
    content_type = (
        "multipart/form-data; boundary=---------------------------326931944431359"
    )
    payload.feed_eof()
    req = make_mocked_request(
        "POST", "/", headers={"CONTENT-TYPE": content_type}, payload=payload
    )
    result = await req.post()
    assert dict(result) == {"a": "b", "c": "d"}


async def test_multipart_formdata_file(protocol: Any) -> None:
    # Make sure file uploads work, even without a content type
    payload = StreamReader(protocol, 2**16, loop=asyncio.get_event_loop())
    payload.feed_data(
        b"-----------------------------326931944431359\r\n"
        b'Content-Disposition: form-data; name="a_file"; filename="binary"\r\n'
        b"\r\n"
        b"\ff\r\n"
        b"-----------------------------326931944431359--\r\n"
    )
    content_type = (
        "multipart/form-data; boundary=---------------------------326931944431359"
    )
    payload.feed_eof()
    req = make_mocked_request(
        "POST", "/", headers={"CONTENT-TYPE": content_type}, payload=payload
    )
    result = await req.post()
    assert hasattr(result["a_file"], "file")
    content = result["a_file"].file.read()
    assert content == b"\ff"

    req._finish()


async def test_make_too_big_request_limit_None(protocol: Any) -> None:
    payload = StreamReader(protocol, 2**16, loop=asyncio.get_event_loop())
    large_file = 1024**2 * b"x"
    too_large_file = large_file + b"x"
    payload.feed_data(too_large_file)
    payload.feed_eof()
    max_size = None
    req = make_mocked_request("POST", "/", payload=payload, client_max_size=max_size)
    txt = await req.read()
    assert len(txt) == 1024**2 + 1


def test_remote_peername_tcp() -> None:
    transp = mock.Mock()
    transp.get_extra_info.return_value = ("10.10.10.10", 1234)
    req = make_mocked_request("GET", "/", transport=transp)
    assert req.remote == "10.10.10.10"


def test_remote_peername_unix() -> None:
    transp = mock.Mock()
    transp.get_extra_info.return_value = "/path/to/sock"
    req = make_mocked_request("GET", "/", transport=transp)
    assert req.remote == "/path/to/sock"


def test_save_state_on_clone() -> None:
    req = make_mocked_request("GET", "/")
    req["key"] = "val"
    req2 = req.clone()
    req2["key"] = "val2"
    assert req["key"] == "val"
    assert req2["key"] == "val2"


def test_clone_scheme() -> None:
    req = make_mocked_request("GET", "/")
    assert req.scheme == "http"
    req2 = req.clone(scheme="https")
    assert req2.scheme == "https"
    assert req2.url.scheme == "https"


def test_clone_host() -> None:
    req = make_mocked_request("GET", "/")
    assert req.host != "example.com"
    req2 = req.clone(host="example.com")
    assert req2.host == "example.com"
    assert req2.url.host == "example.com"


def test_clone_remote() -> None:
    req = make_mocked_request("GET", "/")
    assert req.remote != "11.11.11.11"
    req2 = req.clone(remote="11.11.11.11")
    assert req2.remote == "11.11.11.11"


def test_remote_with_closed_transport() -> None:
    transp = mock.Mock()
    transp.get_extra_info.return_value = ("10.10.10.10", 1234)
    req = make_mocked_request("GET", "/", transport=transp)
    req._protocol = None
    assert req.remote == "10.10.10.10"


def test_url_http_with_closed_transport() -> None:
    req = make_mocked_request("GET", "/")
    req._protocol = None
    assert str(req.url).startswith("http://")


def test_url_https_with_closed_transport() -> None:
    req = make_mocked_request("GET", "/", sslcontext=True)
    req._protocol = None
    assert str(req.url).startswith("https://")


async def test_get_extra_info() -> None:
    valid_key = "test"
    valid_value = "existent"
    default_value = "default"

    def get_extra_info(name: str, default: Any = None):
        return {valid_key: valid_value}.get(name, default)

    transp = mock.Mock()
    transp.get_extra_info.side_effect = get_extra_info
    req = make_mocked_request("GET", "/", transport=transp)

    req_extra_info = req.get_extra_info(valid_key, default_value)
    transp_extra_info = req._protocol.transport.get_extra_info(valid_key, default_value)
    assert req_extra_info == transp_extra_info

    req._protocol.transport = None
    extra_info = req.get_extra_info(valid_key, default_value)
    assert extra_info == default_value

    req._protocol = None
    extra_info = req.get_extra_info(valid_key, default_value)
    assert extra_info == default_value


def test_eq() -> None:
    req1 = make_mocked_request("GET", "/path/to?a=1&b=2")
    req2 = make_mocked_request("GET", "/path/to?a=1&b=2")
    assert req1 != req2
    assert req1 == req1


async def test_json(aiohttp_client: Any) -> None:
    async def handler(request):
        body_text = await request.text()
        assert body_text == '{"some": "data"}'
        assert request.headers["Content-Type"] == "application/json"
        body_json = await request.json()
        assert body_json == {"some": "data"}
        return web.Response()

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    json_data = {"some": "data"}
    async with client.post("/", json=json_data) as resp:
        assert 200 == resp.status


async def test_json_invalid_content_type(aiohttp_client: Any) -> None:
    async def handler(request):
        body_text = await request.text()
        assert body_text == '{"some": "data"}'
        assert request.headers["Content-Type"] == "text/plain"
        await request.json()  # raises HTTP 400

    app = web.Application()
    app.router.add_post("/", handler)
    client = await aiohttp_client(app)

    json_data = {"some": "data"}
    headers = {"Content-Type": "text/plain"}
    async with client.post("/", json=json_data, headers=headers) as resp:
        assert 400 == resp.status
        resp_text = await resp.text()
        assert resp_text == (
            "Attempt to decode JSON with unexpected mimetype: text/plain"
        )


def test_weakref_creation() -> None:
    req = make_mocked_request("GET", "/")
    weakref.ref(req)


@pytest.mark.parametrize(
    ["header", "header_attr"],
    [
        pytest.param("If-Match", "if_match"),
        pytest.param("If-None-Match", "if_none_match"),
    ],
)
@pytest.mark.parametrize(
    ["header_val", "expected"],
    [
        pytest.param(
            '"67ab43", W/"54ed21", "7892,dd"',
            (
                ETag(is_weak=False, value="67ab43"),
                ETag(is_weak=True, value="54ed21"),
                ETag(is_weak=False, value="7892,dd"),
            ),
        ),
        pytest.param(
            '"bfc1ef-5b2c2730249c88ca92d82d"',
            (ETag(is_weak=False, value="bfc1ef-5b2c2730249c88ca92d82d"),),
        ),
        pytest.param(
            '"valid-tag", "also-valid-tag",somegarbage"last-tag"',
            (
                ETag(is_weak=False, value="valid-tag"),
                ETag(is_weak=False, value="also-valid-tag"),
            ),
        ),
        pytest.param(
            '"ascii", "это точно не ascii", "ascii again"',
            (ETag(is_weak=False, value="ascii"),),
        ),
        pytest.param(
            "*",
            (ETag(is_weak=False, value="*"),),
        ),
    ],
)
def test_etag_headers(header, header_attr, header_val, expected) -> None:
    req = make_mocked_request("GET", "/", headers={header: header_val})
    assert getattr(req, header_attr) == expected


@pytest.mark.parametrize(
    ["header", "header_attr"],
    [
        pytest.param("If-Modified-Since", "if_modified_since"),
        pytest.param("If-Unmodified-Since", "if_unmodified_since"),
        pytest.param("If-Range", "if_range"),
    ],
)
@pytest.mark.parametrize(
    ["header_val", "expected"],
    [
        pytest.param("xxyyzz", None),
        pytest.param("Tue, 08 Oct 4446413 00:56:40 GMT", None),
        pytest.param("Tue, 08 Oct 2000 00:56:80 GMT", None),
        pytest.param(
            "Tue, 08 Oct 2000 00:56:40 GMT",
            datetime.datetime(2000, 10, 8, 0, 56, 40, tzinfo=datetime.timezone.utc),
        ),
    ],
)
def test_datetime_headers(header, header_attr, header_val, expected) -> None:
    req = make_mocked_request("GET", "/", headers={header: header_val})
    assert getattr(req, header_attr) == expected
